// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util

import (
	"crypto"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// ComputePCRDigest computes a digest using the specified algorithm from the provided set of PCR
// values and the provided PCR selections. The digest is computed the same way as PCRComputeCurrentDigest
// as defined in the TPM reference implementation. It is most useful for computing an input to
// TPMContext.PolicyPCR or TrialAuthPolicy.PolicyPCR, and for validating quotes and creation data.
//
// This will panic if the specified digest algorithm is not available.
func ComputePCRDigest(alg crypto.Hash, pcrs tpm2.PCRSelectionList, values tpm2.PCRValues) (tpm2.Digest, error) {
	h := alg.New()

	mu.MustCopyValue(&pcrs, pcrs)

	for _, s := range pcrs {
		if _, ok := values[s.Hash]; !ok {
			return nil, fmt.Errorf("the provided values don't contain digests for the selected PCR bank %v", s.Hash)
		}
		for _, i := range s.Select {
			d, ok := values[s.Hash][i]
			if !ok {
				return nil, fmt.Errorf("the provided values don't contain a digest for PCR%d in bank %v", i, s.Hash)
			}
			h.Write(d)
		}
	}

	return h.Sum(nil), nil
}

// ComputePCRDigestSimple computes a digest using the specified algorithm from all of the provided set
// of PCR values. The digest is computed the same way as PCRComputeCurrentDigest as defined in the TPM
// reference implementation. It returns the PCR selection associated with the computed digest.
//
// This will panic if the specified digest algorithm is not available.
func ComputePCRDigestSimple(alg crypto.Hash, values tpm2.PCRValues) (tpm2.PCRSelectionList, tpm2.Digest) {
	pcrs := values.SelectionList()
	digest, err := ComputePCRDigest(alg, pcrs, values)
	if err != nil {
		panic(fmt.Sprintf("ComputePCRDigest failed: %v", err))
	}

	return pcrs, digest
}
