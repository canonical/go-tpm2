// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"bytes"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io/ioutil"

	"golang.org/x/xerrors"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/internal"
	"github.com/canonical/go-tpm2/mu"
)

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
func UnwrapDuplicationObjectToSensitive(duplicate tpm2.Private, public *tpm2.Public, privKey crypto.PrivateKey, parentNameAlg tpm2.HashAlgorithmId, parentSymmetricAlg *tpm2.SymDefObject, encryptionKey tpm2.Data, inSymSeed tpm2.EncryptedSecret, symmetricAlg *tpm2.SymDefObject) (*tpm2.Sensitive, error) {
	hasInnerWrapper := false
	if symmetricAlg != nil && symmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
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
		if parentNameAlg == tpm2.HashAlgorithmNull {
			return nil, errors.New("invalid parent name algorithm")
		}
		if parentSymmetricAlg == nil || parentSymmetricAlg.Algorithm == tpm2.SymObjectAlgorithmNull {
			return nil, errors.New("invalid symmetric algorithm for outer wrapper")
		}
		if !parentSymmetricAlg.Algorithm.Available() {
			return nil, errors.New("symmetric algorithm for outer wrapper is not available")
		}

		var err error
		seed, err = CryptSecretDecrypt(privKey, parentNameAlg.GetHash(), []byte(tpm2.DuplicateString), inSymSeed)
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

		hmacKey := internal.KDFa(parentNameAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, parentNameAlg.Size()*8)
		h := hmac.New(func() hash.Hash { return parentNameAlg.NewHash() }, hmacKey)
		h.Write(duplicate)
		h.Write(name)

		if !bytes.Equal(h.Sum(nil), outerIntegrity) {
			return nil, errors.New("outer integrity digest is invalid")
		}

		symKey := internal.KDFa(parentNameAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(parentSymmetricAlg.KeyBits.Sym))

		if err := tpm2.CryptSymmetricDecrypt(tpm2.SymAlgorithmId(parentSymmetricAlg.Algorithm), symKey, make([]byte, parentSymmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, xerrors.Errorf("cannot remove outer wrapper: %w", err)
		}
	}

	if hasInnerWrapper {
		// Remove inner wrapper
		if err := tpm2.CryptSymmetricDecrypt(tpm2.SymAlgorithmId(symmetricAlg.Algorithm), encryptionKey, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
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

	var sensitive struct {
		Ptr *tpm2.Sensitive `tpm2:"sized"`
	}
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
func CreateDuplicationObjectFromSensitive(sensitive *tpm2.Sensitive, public, parentPublic *tpm2.Public, encryptionKeyIn tpm2.Data, symmetricAlg *tpm2.SymDefObject) (encryptionKeyOut tpm2.Data, duplicate tpm2.Private, outSymSeed tpm2.EncryptedSecret, err error) {
	if public.Attrs&(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != 0 {
		return nil, nil, nil, errors.New("object must be a duplication root")
	}

	if public.Attrs&tpm2.AttrEncryptedDuplication != 0 {
		if symmetricAlg == nil || symmetricAlg.Algorithm == tpm2.SymObjectAlgorithmNull {
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
	if symmetricAlg != nil && symmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull {
		applyInnerWrapper = true
		if len(encryptionKeyIn) > 0 && len(encryptionKeyIn) != int(symmetricAlg.KeyBits.Sym/8) {
			return nil, nil, nil, errors.New("the supplied symmetric key has the wrong length")
		}

		if !symmetricAlg.Algorithm.Available() {
			return nil, nil, nil, errors.New("symmetric algorithm for inner wrapper is not available")
		}
	}

	var seed []byte
	var outerSymmetric *tpm2.SymDefObject
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
		outSymSeed, seed, err = tpm2.CryptSecretEncrypt(parentPublic, []byte(tpm2.DuplicateString))
		if err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot create encrypted symmetric seed: %w", err)
		}
	}

	authValue := sensitive.AuthValue
	sensitive = &tpm2.Sensitive{
		Type:      sensitive.Type,
		AuthValue: make(tpm2.Auth, public.NameAlg.Size()),
		SeedValue: sensitive.SeedValue,
		Sensitive: sensitive.Sensitive}
	copy(sensitive.AuthValue, authValue)

	sensitiveSized := struct {
		Ptr *tpm2.Sensitive `tpm2:"sized"`
	}{sensitive}
	duplicate, err = mu.MarshalToBytes(sensitiveSized)
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

		if err := tpm2.CryptSymmetricEncrypt(tpm2.SymAlgorithmId(symmetricAlg.Algorithm), encryptionKeyIn, make([]byte, symmetricAlg.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot apply inner wrapper: %w", err)
		}
	}

	if applyOuterWrapper {
		// Apply outer wrapper
		symKey := internal.KDFa(parentPublic.NameAlg.GetHash(), seed, []byte(tpm2.StorageKey), name, nil, int(outerSymmetric.KeyBits.Sym))

		if err := tpm2.CryptSymmetricEncrypt(tpm2.SymAlgorithmId(outerSymmetric.Algorithm), symKey, make([]byte, outerSymmetric.Algorithm.BlockSize()), duplicate); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot apply outer wrapper: %w", err)
		}

		hmacKey := internal.KDFa(parentPublic.NameAlg.GetHash(), seed, []byte(tpm2.IntegrityKey), nil, nil, parentPublic.NameAlg.Size()*8)
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
