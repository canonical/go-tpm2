// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"fmt"

	"github.com/canonical/go-tpm2"
	internal_util "github.com/canonical/go-tpm2/internal/util"
	"github.com/canonical/go-tpm2/mu"
)

// UnwrapOuter removes an outer wrapper from the supplied sensitive data blob. The
// supplied name is associated with the data.
//
// It checks the integrity HMAC is valid using the specified digest algorithm and
// a key derived from the supplied seed and returns an error if the check fails.
//
// It then decrypts the data blob using the specified symmetric algorithm and a
// key derived from the supplied seed and name.
func UnwrapOuter(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	return internal_util.UnwrapOuter(hashAlg, symmetricAlg, name, seed, useIV, data)
}

// ProduceOuterWrap adds an outer wrapper to the supplied data. The supplied name
// is associated with the data.
//
// It encrypts the data using the specified symmetric algorithm and a key derived
// from the supplied seed and name.
//
// It then prepends an integrity HMAC of the encrypted data and the supplied
// name using the specified digest algorithm and a key derived from the supplied
// seed.
func ProduceOuterWrap(hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, name tpm2.Name, seed []byte, useIV bool, data []byte) ([]byte, error) {
	return internal_util.ProduceOuterWrap(hashAlg, symmetricAlg, name, seed, useIV, data)
}

// PrivateToSensitive unwraps a TPM private area into its corresponding
// sensitive structure. The supplied name is the name of the object
// associated with sensitive.
//
// The removes the outer wrapper from the private area using the specified
// digest algorithm, symmetric algorithm and seed. These values are
// associated with the parent storage key that that is used to load the
// object into the TPM. The seed is part of the parent storage key's
// sensitive area and will only be known for objects created outside of the
// TPM and then imported, or objects created inside of the TPM that can be
// duplicated and unwrapped outside of the TPM.
func PrivateToSensitive(private tpm2.Private, name tpm2.Name, hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, seed []byte) (sensitive *tpm2.Sensitive, err error) {
	data, err := UnwrapOuter(hashAlg, symmetricAlg, name, seed, true, private)
	if err != nil {
		return nil, fmt.Errorf("cannot unwrap outer wrapper: %w", err)
	}

	if _, err := mu.UnmarshalFromBytes(data, mu.MakeSizedDest(&sensitive)); err != nil {
		return nil, fmt.Errorf("cannot unmarhsal sensitive: %w", err)
	}

	return sensitive, nil
}

// SensitiveToPrivate creates a TPM private area from the supplied
// sensitive structure. The supplied name is the name of the object
// associated with sensitive.
//
// This applies an outer wrapper to the sensitive structure using the
// specified digest algorithm, symmetric algorithm and seed. These values
// are associated with the parent storage key that that will be used to
// load the object into the TPM. The seed is part of the parent storage
// key's sensitive area and will only be known for objects created outside
// of the TPM and then imported, or objects created inside of the TPM that
// can be duplicated and unwrapped outside of the TPM.
func SensitiveToPrivate(sensitive *tpm2.Sensitive, name tpm2.Name, hashAlg tpm2.HashAlgorithmId, symmetricAlg *tpm2.SymDefObject, seed []byte) (tpm2.Private, error) {
	private, err := mu.MarshalToBytes(mu.MakeSizedSource(&sensitive))
	if err != nil {
		return nil, fmt.Errorf("cannot marshal sensitive: %w", err)
	}

	private, err = ProduceOuterWrap(hashAlg, symmetricAlg, name, seed, true, private)
	if err != nil {
		return nil, fmt.Errorf("cannot apply outer wrapper: %w", err)
	}

	return private, nil
}
