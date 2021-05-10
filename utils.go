// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"
	"sort"

	"github.com/canonical/go-tpm2/internal"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

// ComputeCpHash computes a command parameter digest from the specified command code and provided command parameters, using the
// digest algorithm specified by hashAlg. The params argument corresponds to the handle and parameters area of a command (in that
// order), separated by the Delimiter sentinel value. Handle arguments must be represented by either the Handle type or
// HandleContext type.
//
// The number of command handles and number / type of command parameters can be determined by looking in part 3 of the TPM 2.0
// Library Specification for the specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to a command and set of command
// parameters, such as TPMContext.PolicySigned, TPMContext.PolicySecret, TPMContext.PolicyTicket and TPMContext.PolicyCpHash.
func ComputeCpHash(hashAlg HashAlgorithmId, command CommandCode, params ...interface{}) (Digest, error) {
	if !hashAlg.Available() {
		return nil, fmt.Errorf("unsupported digest algorithm or algorithm not linked in to binary (%v)", hashAlg)
	}

	var handles []Name
	var i int

	for _, param := range params {
		if param == Delimiter {
			break
		}
		i++
		switch p := param.(type) {
		case Handle:
			handles = append(handles, makePartialHandleContext(p).Name())
		case HandleContext:
			handles = append(handles, p.Name())
		default:
			return nil, makeInvalidArgError("params", "parameter in handle area is not a Handle or HandleContext")
		}
	}

	var cpBytes []byte

	if i < len(params)-1 {
		var err error
		cpBytes, err = mu.MarshalToBytes(params[i+1:]...)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal command parameters: %v", err)
		}
	}

	return cryptComputeCpHash(hashAlg, command, handles, cpBytes), nil
}

// ComputePCRDigest computes a digest using the specified algorithm from the provided set of PCR values and the provided PCR
// selections. The digest is computed the same way as PCRComputeCurrentDigest as defined in the TPM reference implementation.
// It is most useful for computing an input to TPMContext.PolicyPCR, and validating quotes and creation data.
func ComputePCRDigest(alg HashAlgorithmId, pcrs PCRSelectionList, values PCRValues) (Digest, error) {
	if !alg.Available() {
		return nil, fmt.Errorf("unsupported digest algorithm or algorithm not linked in to binary (%v)", alg)
	}
	h := alg.NewHash()

	for _, s := range pcrs {
		if _, ok := values[s.Hash]; !ok {
			return nil, fmt.Errorf("the provided values don't contain digests for the selected PCR bank %v", s.Hash)
		}
		sel := make([]int, len(s.Select))
		copy(sel, s.Select)
		sort.Ints(sel)
		for _, i := range sel {
			d, ok := values[s.Hash][i]
			if !ok {
				return nil, fmt.Errorf("the provided values don't contain a digest for PCR%d in bank %v", i, s.Hash)
			}
			h.Write(d)
		}
	}

	return h.Sum(nil), nil
}

func ComputePCRDigestSimple(alg HashAlgorithmId, values PCRValues) (PCRSelectionList, Digest, error) {
	if !alg.Available() {
		return nil, nil, fmt.Errorf("unknown digest algorithm %v", alg)
	}

	pcrs := values.SelectionList()
	digest, err := ComputePCRDigest(alg, pcrs, values)
	if err != nil {
		panic(fmt.Sprintf("ComputePCRDigest failed: %v", err))
	}

	return pcrs, digest, nil
}

// TrialAuthPolicy provides a mechanism for computing authorization policy digests without having to execute a trial authorization
// policy session on the TPM. An advantage of this is that it is possible to compute digests for PolicySecret and PolicyNV assertions
// without knowledge of the authorization value of the authorizing entities used for those commands.
type TrialAuthPolicy struct {
	alg    HashAlgorithmId
	digest Digest
}

// ComputeAuthPolicy creates a new context for computing an authorization policy digest.
func ComputeAuthPolicy(alg HashAlgorithmId) (*TrialAuthPolicy, error) {
	if !alg.Available() {
		return nil, errors.New("unsupported digest algorithm or algorithm not linked in to binary")
	}
	return &TrialAuthPolicy{alg: alg, digest: make(Digest, alg.Size())}, nil
}

func (p *TrialAuthPolicy) beginUpdate() (hash.Hash, func()) {
	h := p.alg.NewHash()
	h.Write(p.digest)

	return h, func() {
		p.digest = h.Sum(nil)
	}
}

func (p *TrialAuthPolicy) beginUpdateForCommand(commandCode CommandCode) (hash.Hash, func()) {
	h, end := p.beginUpdate()
	binary.Write(h, binary.BigEndian, commandCode)
	return h, end
}

func (p *TrialAuthPolicy) update(commandCode CommandCode, name Name, ref Nonce) {
	h, end := p.beginUpdateForCommand(commandCode)
	h.Write(name)
	end()

	h, end = p.beginUpdate()
	h.Write(ref)
	end()
}

func (p *TrialAuthPolicy) reset() {
	p.digest = make(Digest, len(p.digest))
}

// GetDigest returns the current digest computed for the policy assertions executed so far.
func (p *TrialAuthPolicy) GetDigest() Digest {
	return p.digest
}

func (p *TrialAuthPolicy) SetDigest(d Digest) error {
	if len(d) != p.alg.Size() {
		return errors.New("Invalid digest length")
	}
	p.digest = d
	return nil
}

func (p *TrialAuthPolicy) Reset() {
	p.reset()
}

func (p *TrialAuthPolicy) PolicySigned(authName Name, policyRef Nonce) {
	p.update(CommandPolicySigned, authName, policyRef)
}

func (p *TrialAuthPolicy) PolicySecret(authName Name, policyRef Nonce) {
	p.update(CommandPolicySecret, authName, policyRef)
}

func (p *TrialAuthPolicy) PolicyOR(pHashList DigestList) error {
	if len(pHashList) < 2 || len(pHashList) > 8 {
		return errors.New("invalid number of digests")
	}

	p.reset()

	h, end := p.beginUpdateForCommand(CommandPolicyOR)
	for _, digest := range pHashList {
		h.Write(digest)
	}
	end()
	return nil
}

func (p *TrialAuthPolicy) PolicyPCR(pcrDigest Digest, pcrs PCRSelectionList) {
	h, end := p.beginUpdateForCommand(CommandPolicyPCR)
	if _, err := mu.MarshalToWriter(h, pcrs); err != nil {
		panic(fmt.Sprintf("cannot marshal PCR selection: %v", err))
	}
	h.Write(pcrDigest)
	end()
}

func (p *TrialAuthPolicy) PolicyNV(nvIndexName Name, operandB Operand, offset uint16, operation ArithmeticOp) {
	h := p.alg.NewHash()
	h.Write(operandB)
	binary.Write(h, binary.BigEndian, offset)
	binary.Write(h, binary.BigEndian, operation)

	args := h.Sum(nil)

	h, end := p.beginUpdateForCommand(CommandPolicyNV)
	h.Write(args)
	h.Write(nvIndexName)
	end()
}

func (p *TrialAuthPolicy) PolicyCounterTimer(operandB Operand, offset uint16, operation ArithmeticOp) {
	h := p.alg.NewHash()
	h.Write(operandB)
	binary.Write(h, binary.BigEndian, offset)
	binary.Write(h, binary.BigEndian, operation)

	args := h.Sum(nil)

	h, end := p.beginUpdateForCommand(CommandPolicyCounterTimer)
	h.Write(args)
	end()
}

func (p *TrialAuthPolicy) PolicyCommandCode(code CommandCode) {
	h, end := p.beginUpdateForCommand(CommandPolicyCommandCode)
	binary.Write(h, binary.BigEndian, code)
	end()
}

func (p *TrialAuthPolicy) PolicyCpHash(cpHashA Digest) {
	h, end := p.beginUpdateForCommand(CommandPolicyCpHash)
	h.Write(cpHashA)
	end()
}

func (p *TrialAuthPolicy) PolicyNameHash(nameHash Digest) {
	h, end := p.beginUpdateForCommand(CommandPolicyNameHash)
	h.Write(nameHash)
	end()
}

func (p *TrialAuthPolicy) PolicyDuplicationSelect(objectName, newParentName Name, includeObject bool) {
	h, end := p.beginUpdateForCommand(CommandPolicyDuplicationSelect)
	if includeObject {
		h.Write(objectName)
	}
	h.Write(newParentName)
	binary.Write(h, binary.BigEndian, includeObject)
	end()
}

func (p *TrialAuthPolicy) PolicyAuthorize(policyRef Nonce, keySign Name) {
	p.update(CommandPolicyAuthorize, keySign, policyRef)
}

func (p *TrialAuthPolicy) PolicyAuthValue() {
	_, end := p.beginUpdateForCommand(CommandPolicyAuthValue)
	end()
}

func (p *TrialAuthPolicy) PolicyPassword() {
	// This extends the same value as PolicyAuthValue - see section 23.18 of part 3 of the "TPM 2.0 Library
	// Specification"
	_, end := p.beginUpdateForCommand(CommandPolicyAuthValue)
	end()
}

func (p *TrialAuthPolicy) PolicyNvWritten(writtenSet bool) {
	h, end := p.beginUpdateForCommand(CommandPolicyNvWritten)
	binary.Write(h, binary.BigEndian, writtenSet)
	end()
}

// UnwrapDuplicationObjectToSensitive unwraps the supplied duplication object and returns the
// corresponding sensitive area. If inSymSeed is supplied, then it is assumed that the object
// has an outer wrapper. In this case, privKey, parentNameAlg and parentSymmetricAlg must be
// supplied - privKey is the key with which inSymSeed is protected, parentNameAlg is the name
// algorithm for the parent key (and must not be HashAlgorithmNull), and parentSymmetricAlg
// defines the symmetric algorithm for the parent key (and the Algorithm field must not be
// SymObjectAlgorithmNull).
//
// If symmetricAlg is supplied and the Algorithm field is not SymObjectAlgorithmNull, then it is
// assumed that the object has an inner wrapper. In this case, the symmetric key for the inner
// wrapper must be supplied using the encryptionKey argument.
func UnwrapDuplicationObjectToSensitive(duplicate Private, public *Public, privKey crypto.PrivateKey, parentNameAlg HashAlgorithmId, parentSymmetricAlg *SymDefObject, encryptionKey Data, inSymSeed EncryptedSecret, symmetricAlg *SymDefObject) (*Sensitive, error) {
	hasInnerWrapper := false
	if symmetricAlg != nil && symmetricAlg.Algorithm != SymObjectAlgorithmNull {
		hasInnerWrapper = true
		if !symmetricAlg.Algorithm.Available() {
			return nil, errors.New("symmetric algorithm for inner wrapper is not available")
		}
	}

	var seed []byte
	hasOuterWrapper := false
	if len(inSymSeed) > 0 {
		hasOuterWrapper = true
		if privKey == nil {
			return nil, errors.New("parent private key is required for outer wrapper")
		}
		if parentNameAlg == HashAlgorithmNull {
			return nil, errors.New("invalid parent name algorithm")
		}
		if parentSymmetricAlg == nil || parentSymmetricAlg.Algorithm == SymObjectAlgorithmNull {
			return nil, errors.New("invalid symmetric algorithm for outer wrapper")
		}
		if !parentSymmetricAlg.Algorithm.Available() {
			return nil, errors.New("symmetric algorithm for outer wrapper is not available")
		}

		var err error
		seed, err = cryptSecretDecrypt(privKey, parentNameAlg, []byte("DUPLICATE"), inSymSeed)
		if err != nil {
			return nil, xerrors.Errorf("cannot decrypt symmetric seed: %w", err)
		}
	}

	name, err := public.Name()
	if err != nil {
		return nil, xerrors.Errorf("cannot compute name: %w", err)
	}

	if hasOuterWrapper {
		// Remove outer wrapper
		r := bytes.NewReader(duplicate)

		var outerIntegrity []byte
		if _, err := mu.UnmarshalFromReader(r, &outerIntegrity); err != nil {
			return nil, xerrors.Errorf("cannot unpack outer integrity digest: %w", err)
		}

		duplicate, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot unpack outer wrapper: %w", err)
		}

		hmacKey := internal.KDFa(parentNameAlg.GetHash(), seed, []byte("INTEGRITY"), nil, nil, parentNameAlg.Size()*8)
		h := hmac.New(func() hash.Hash { return parentNameAlg.NewHash() }, hmacKey)
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), outerIntegrity) {
			return nil, errors.New("outer integrity digest is invalid")
		}

		symKey := internal.KDFa(parentNameAlg.GetHash(), seed, []byte("STORAGE"), name, nil, int(parentSymmetricAlg.KeyBits.Sym))

		if err := cryptSymmetricDecrypt(SymAlgorithmId(parentSymmetricAlg.Algorithm), symKey, make([]byte, parentSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, xerrors.Errorf("cannot remove outer wrapper: %w", err)
		}
	}

	if hasInnerWrapper {
		// Remove inner wrapper
		if err := cryptSymmetricDecrypt(SymAlgorithmId(symmetricAlg.Algorithm), encryptionKey, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, xerrors.Errorf("cannot remove inner wrapper: %w", err)
		}

		r := bytes.NewReader(duplicate)

		var innerIntegrity []byte
		if _, err := mu.UnmarshalFromReader(r, &innerIntegrity); err != nil {
			return nil, xerrors.Errorf("cannot unpack inner integrity digest: %w", err)
		}

		duplicate, err = ioutil.ReadAll(r)
		if err != nil {
			return nil, xerrors.Errorf("cannot unpack inner wrapper: %w", err)
		}

		h := public.NameAlg.NewHash()
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), innerIntegrity) {
			return nil, errors.New("inner integrity digest is invalid")
		}
	}

	var sensitive sensitiveSized
	if _, err := mu.UnmarshalFromBytes(duplicate, &sensitive); err != nil {
		return nil, xerrors.Errorf("cannot unmarhsal sensitive: %w", err)
	}

	return sensitive.Ptr, nil
}

// CreateDuplicationObjectFromSensitive creates a duplication object that can be imported in to a
// TPM from the supplied sensitive area.
//
// If symmetricAlg is supplied and the Algorithm field is not SymObjectAlgorithmNull, this function
// will apply an inner wrapper to the duplication object. If encryptionKeyIn is supplied, it will be
// used as the symmetric key for the inner wrapper. It must have a size appropriate for the selected
// symmetric algorithm. If encryptionKeyIn is not supplied, a symmetric key will be created and
// returned
//
// If parentPublic is supplied, an outer wrapper will be applied to the duplication object. The
// parentPublic argument should correspond to the public area of the storage key to which the
// duplication object will be imported. When applying the outer wrapper, the seed used to derice the
// symmetric key and HMAC key will be encrypted using parentPublic and returned.
func CreateDuplicationObjectFromSensitive(sensitive *Sensitive, public, parentPublic *Public, encryptionKeyIn Data, symmetricAlg *SymDefObject) (encryptionKeyOut Data, duplicate Private, outSymSeed EncryptedSecret, err error) {
	if public.Attrs&(AttrFixedTPM|AttrFixedParent) != 0 {
		return nil, nil, nil, errors.New("object must be a duplication root")
	}

	if public.Attrs&AttrEncryptedDuplication != 0 {
		if symmetricAlg == nil || symmetricAlg.Algorithm == SymObjectAlgorithmNull {
			return nil, nil, nil, errors.New("symmetric algorithm must be supplied for an object with AttrEncryptedDuplication")
		}
		if parentPublic == nil {
			return nil, nil, nil, errors.New("parent object must be supplied for an object with AttrEncryptedDuplication")
		}
	}

	name, err := public.Name()
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot compute name: %w", err)
	}

	applyInnerWrapper := false
	if symmetricAlg != nil && symmetricAlg.Algorithm != SymObjectAlgorithmNull {
		applyInnerWrapper = true
		if len(encryptionKeyIn) > 0 && len(encryptionKeyIn) != int(symmetricAlg.KeyBits.Sym/8) {
			return nil, nil, nil, errors.New("the supplied symmetric key has the wrong length")
		}

		if !symmetricAlg.Algorithm.Available() {
			return nil, nil, nil, errors.New("symmetric algorithm for inner wrapper is not available")
		}
	}

	var seed []byte
	var outerSymmetric *SymDefObject
	applyOuterWrapper := false
	if parentPublic != nil {
		applyOuterWrapper = true
		if !parentPublic.IsStorage() {
			return nil, nil, nil, errors.New("parent object must be a storage key")
		}
		outerSymmetric = &parentPublic.Params.AsymDetail().Symmetric
		if !outerSymmetric.Algorithm.Available() {
			return nil, nil, nil, errors.New("symmetric algorithm for outer wrapper is not available")
		}
		outSymSeed, seed, err = cryptSecretEncrypt(parentPublic, []byte("DUPLICATE"))
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot create encrypted symmetric seed: %w", err)
		}
	}

	authValue := sensitive.AuthValue
	sensitive = &Sensitive{
		Type:      sensitive.Type,
		AuthValue: make(Auth, public.NameAlg.Size()),
		SeedValue: sensitive.SeedValue,
		Sensitive: sensitive.Sensitive}
	copy(sensitive.AuthValue, authValue)

	duplicate, err = mu.MarshalToBytes(sensitiveSized{sensitive})
	if err != nil {
		panic(fmt.Sprintf("cannot marshal sensitive: %v", err))
	}

	if applyInnerWrapper {
		// Apply inner wrapper
		h := public.NameAlg.NewHash()
		h.Write(duplicate)
		h.Write(name)

		innerIntegrity := h.Sum(nil)

		duplicate, err = mu.MarshalToBytes(innerIntegrity, mu.RawBytes(duplicate))
		if err != nil {
			panic(fmt.Sprintf("cannot prepend integrity: %v", err))
		}

		if len(encryptionKeyIn) == 0 {
			encryptionKeyIn = make([]byte, symmetricAlg.KeyBits.Sym/8)
			if _, err := rand.Read(encryptionKeyIn); err != nil {
				return nil, nil, nil, xerrors.Errorf("cannot read random bytes for key for inner wrapper: %w", err)
			}
			encryptionKeyOut = encryptionKeyIn
		}

		if err := cryptSymmetricEncrypt(SymAlgorithmId(symmetricAlg.Algorithm), encryptionKeyIn, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot apply inner wrapper: %w", err)
		}
	}

	if applyOuterWrapper {
		// Apply outer wrapper
		symKey := internal.KDFa(parentPublic.NameAlg.GetHash(), seed, []byte("STORAGE"), name, nil, int(outerSymmetric.KeyBits.Sym))

		if err := cryptSymmetricEncrypt(SymAlgorithmId(outerSymmetric.Algorithm), symKey, make([]byte, outerSymmetric.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot apply outer wrapper: %w", err)
		}

		hmacKey := internal.KDFa(parentPublic.NameAlg.GetHash(), seed, []byte("INTEGRITY"), nil, nil, parentPublic.NameAlg.Size()*8)
		h := hmac.New(func() hash.Hash { return parentPublic.NameAlg.NewHash() }, hmacKey)
		h.Write(duplicate)
		h.Write(name)

		outerIntegrity := h.Sum(nil)

		duplicate, err = mu.MarshalToBytes(outerIntegrity, mu.RawBytes(duplicate))
		if err != nil {
			panic(fmt.Sprintf("cannot prepend outer integrity: %v", err))
		}
	}

	return
}
