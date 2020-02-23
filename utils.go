// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"sort"
)

// ComputeCpHash computes a command parameter digest from the specified command code and provided command parameters, using the
// digest algorithm specified by hashAlg. The params argument corresponds to the handle and parameters area of a command (in that
// order), separated by the Separator sentinel value. Handle arguments must be represented by either the Handle type or
// HandleContext type.
//
// The number of command handles and number / type of command parameters can be determined by looking in part 3 of the TPM 2.0
// Library Specification for the specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to a command and set of command
// parameters, such as TPMContext.PolicySigned, TPMContext.PolicySecret, TPMContext.PolicyTicket and TPMContext.PolicyCpHash.
func ComputeCpHash(hashAlg HashAlgorithmId, command CommandCode, params ...interface{}) (Digest, error) {
	var handles []Name
	var i int

	for _, param := range params {
		if param == Separator {
			break
		}
		i++
		switch p := param.(type) {
		case Handle:
			handles = append(handles, makeDummyContext(p).Name())
		case HandleContext:
			handles = append(handles, p.Name())
		default:
			return nil, makeInvalidParamError("params", "parameter in handle area is not a Handle or HandleContext")
		}
	}

	var cpBytes []byte

	if i < len(params)-1 {
		var err error
		cpBytes, err = MarshalToBytes(params[i+1:]...)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal command parameters: %v", err)
		}
	}

	return cryptComputeCpHash(hashAlg, command, handles, cpBytes), nil
}

// ComputePCRDigest computes a digest using the specified algorithm from the provided set of PCR values and the provided PCR
// selection. It is most useful for computing an input to TPMContext.PolicyPCR, and validating quotes and creation data.
func ComputePCRDigest(alg HashAlgorithmId, pcrs PCRSelectionList, values PCRValues) (Digest, error) {
	if !alg.Supported() {
		return nil, fmt.Errorf("unknown digest algorithm %v", alg)
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

// TrialAuthPolicy provides a mechanism for computing authorization policy digests without having to execute a trial authorization
// policy session on the TPM. An advantage of this is that it is possible to compute digests for PolicySecret and PolicyNV assertions
// without knowledge of the authorization value of the authorizing entities used for those commands.
type TrialAuthPolicy struct {
	alg    HashAlgorithmId
	digest Digest
}

// ComputeAuthPolicy creates a new context for computing an authorization policy digest.
func ComputeAuthPolicy(alg HashAlgorithmId) (*TrialAuthPolicy, error) {
	if !alg.Supported() {
		return nil, errors.New("invalid algorithm")
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
	if err := MarshalToWriter(h, pcrs); err != nil {
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
