// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
)

func computeNameHash(alg tpm2.HashAlgorithmId, handles []tpm2.Name) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("algorithm is not available")
	}

	h := alg.NewHash()

	for _, handle := range handles {
		h.Write(handle.Name())
	}

	return h.Sum(nil), nil
}

// ComputeNameHash computes a digest from the supplied handles using the specified digest
// algorithm.
//
// The result of this is useful with [tpm2.TPMContext.PolicyNameHash].
func ComputeNameHash(alg tpm2.HashAlgorithmId, handles ...Named) (tpm2.Digest, error) {
	var handleNames []tpm2.Name
	for i, handle := range handles {
		name := handle.Name()
		if !name.IsValid() {
			return nil, fmt.Errorf("invalid name for handle %d", i)
		}
		handleNames = append(handleNames, name)
	}
	return computeNameHash(alg, handleNames)
}
