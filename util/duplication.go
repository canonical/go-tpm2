// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"crypto"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	tpm2_crypto "github.com/canonical/go-tpm2/crypto"
)

// UnwrapDuplicationObject unwraps the supplied duplication object and
// returns the corresponding sensitive area. The duplication object will
// normally be created by executing the TPM2_Duplicate command.
//
// If outerSecret is supplied then it is assumed that the object
// has an outer wrapper. For an object duplicated with TPM2_Duplicate,
// outerSecret is the seed returned by this command. In this
// case, privKey, outerHashAlg and outerSymmetricAlg must be supplied -
// privKey is the key with which outerSecret is protected (the
// new parent when using TPM2_Duplicate), outerHashAlg is the algorithm used
// for integrity checking and key derivation (the new parent's name
// algorithm when using TPM2_Duplicate) and must not be HashAlgorithmNull,
// and outerSymmetricAlg defines the symmetric algorithm for the outer
// wrapper (the new parent's symmetric algorithm when using
// TPM2_Duplicate) and must not be SymObjectAlgorithmNull).
//
// If innerSymmetricAlg is supplied and the Algorithm field is not
// SymObjectAlgorithmNull, then it is assumed that the object has an
// inner wrapper. In this case, the symmetric key for the inner wrapper
// must be supplied using the innerSymmetricKey argument.
func UnwrapDuplicationObject(duplicate tpm2.Private, public *tpm2.Public, privKey crypto.PrivateKey, outerHashAlg tpm2.HashAlgorithmId, outerSymmetricAlg *tpm2.SymDefObject, outerSecret tpm2.EncryptedSecret, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (*tpm2.Sensitive, error) {
	var seed []byte
	if len(outerSecret) > 0 {
		if privKey == nil {
			return nil, errors.New("parent private key is required for outer wrapper")
		}
		if outerHashAlg != tpm2.HashAlgorithmNull && !outerHashAlg.Available() {
			return nil, fmt.Errorf("digest algorithm %v is not available", outerHashAlg)
		}

		var err error
		seed, err = tpm2_crypto.SecretDecrypt(privKey, outerHashAlg.GetHash(), []byte(tpm2.DuplicateString), outerSecret)
		if err != nil {
			return nil, fmt.Errorf("cannot decrypt symmetric seed: %w", err)
		}
	}

	name, err := public.Name()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name: %w", err)
	}

	return DuplicateToSensitive(duplicate, name, outerHashAlg, outerSymmetricAlg, seed, innerSymmetricAlg, innerSymmetricKey)
}

// CreateDuplicationObject creates a duplication object that can be
// imported in to a TPM from the supplied sensitive area.
//
// If parentPublic is supplied, an outer wrapper will be applied to the
// duplication object. The parentPublic argument should correspond to the
// public area of the storage key to which the duplication object will be
// imported. When applying the outer wrapper, the seed used to derive the
// symmetric key and HMAC key will be encrypted using parentPublic and
// returned.
//
// If innerSymmetricAlg is supplied and the Algorithm field is not
// SymObjectAlgorithmNull, this function will apply an inner wrapper to
// the duplication object. If innerSymmetricKey is supplied, it will be
// used as the symmetric key for the inner wrapper. It must have a size
// appropriate for the selected symmetric algorithm. If
// innerSymmetricKey is not supplied, a symmetric key will be created and
// returned.
func CreateDuplicationObject(sensitive *tpm2.Sensitive, public, parentPublic *tpm2.Public, innerSymmetricKey tpm2.Data, innerSymmetricAlg *tpm2.SymDefObject) (innerSymmetricKeyOut tpm2.Data, duplicate tpm2.Private, outerSecret tpm2.EncryptedSecret, err error) {
	if public.Attrs&(tpm2.AttrFixedTPM|tpm2.AttrFixedParent) != 0 {
		return nil, nil, nil, errors.New("object must be a duplication root")
	}

	if public.Attrs&tpm2.AttrEncryptedDuplication != 0 {
		if innerSymmetricAlg == nil || innerSymmetricAlg.Algorithm == tpm2.SymObjectAlgorithmNull {
			return nil, nil, nil, errors.New("inner symmetric algorithm must be supplied for an object with AttrEncryptedDuplication")
		}
		if parentPublic == nil {
			return nil, nil, nil, errors.New("parent object must be supplied for an object with AttrEncryptedDuplication")
		}
	}

	name, err := public.Name()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cannot compute name: %w", err)
	}

	var seed []byte
	var outerHashAlg tpm2.HashAlgorithmId
	var outerSymmetricAlg *tpm2.SymDefObject
	if parentPublic != nil {
		outerHashAlg = parentPublic.NameAlg
		outerSymmetricAlg = &parentPublic.Params.AsymDetail(parentPublic.Type).Symmetric

		if parentPublic.NameAlg != tpm2.HashAlgorithmNull && !parentPublic.NameAlg.Available() {
			return nil, nil, nil, fmt.Errorf("digest algorithm %v is not available", parentPublic.NameAlg)
		}
		if !parentPublic.IsStorageParent() || !parentPublic.IsAsymmetric() {
			return nil, nil, nil, errors.New("parent object must be an asymmetric storage key")
		}
		outerSecret, seed, err = tpm2_crypto.SecretEncrypt(parentPublic.Public(), parentPublic.NameAlg.GetHash(), []byte(tpm2.DuplicateString))
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot create encrypted outer symmetric seed: %w", err)
		}
	}

	innerSymmetricKeyOut, duplicate, err = SensitiveToDuplicate(sensitive, name, outerHashAlg, outerSymmetricAlg, seed, innerSymmetricAlg, innerSymmetricKey)
	if err != nil {
		return nil, nil, nil, err
	}

	return innerSymmetricKeyOut, duplicate, outerSecret, nil
}
