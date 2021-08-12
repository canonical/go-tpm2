// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// This file contains types defined in section 7 (Handles) in
// part 2 of the library spec.

// Handle corresponds to the TPM_HANDLE type, and is a numeric
// identifier that references a resource on the TPM.
type Handle uint32

// Type returns the type of the handle.
func (h Handle) Type() HandleType {
	return HandleType(h >> 24)
}

// HandleType corresponds to the TPM_HT type, and is used to
// identify the type of a Handle.
type HandleType uint8

// BaseHandle returns the first handle for the handle type.
func (h HandleType) BaseHandle() Handle {
	return Handle(h) << 24
}
