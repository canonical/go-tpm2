// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// This file contains types defined in section 13 (NV Storage Structures)
// in part 2 of the library spec.

// NVType corresponds to the TPM_NT type.
type NVType uint32

// WithAttrs returns NVAttributes for this type with the specified attributes set.
func (t NVType) WithAttrs(attrs NVAttributes) NVAttributes {
	return NVAttributes(t<<4) | attrs
}

// NVPinCounterParams corresponds to the TPMS_NV_PIN_COUNTER_PARAMETERS type.
type NVPinCounterParams struct {
	Count uint32
	Limit uint32
}

// NVAttributes corresponds to the TPMA_NV type, and represents the attributes of a NV index. When exchanged with the TPM, some bits
// are reserved to encode the type of the NV index (NVType).
type NVAttributes uint32

// Type returns the NVType encoded in a NVAttributes value.
func (a NVAttributes) Type() NVType {
	return NVType((a & 0xf0) >> 4)
}

// AttrsOnly returns the NVAttributes without the encoded NVType.
func (a NVAttributes) AttrsOnly() NVAttributes {
	return a & ^NVAttributes(0xf0)
}

// NVPublic corresponds to the TPMS_NV_PUBLIC type, which describes a NV index.
type NVPublic struct {
	Index      Handle          // Handle of the NV index
	NameAlg    HashAlgorithmId // NameAlg is the digest algorithm used to compute the name of the index
	Attrs      NVAttributes    // Attributes of this index
	AuthPolicy Digest          // Authorization policy for this index
	Size       uint16          // Size of this index
}

// Name computes the name of this NV index
func (p *NVPublic) Name() (Name, error) {
	if !p.NameAlg.Available() {
		return nil, fmt.Errorf("unsupported name algorithm or algorithm not linked into binary: %v", p.NameAlg)
	}
	hasher := p.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(hasher, p); err != nil {
		return nil, fmt.Errorf("cannot marshal public object: %v", err)
	}
	return mu.MustMarshalToBytes(p.NameAlg, mu.RawBytes(hasher.Sum(nil))), nil
}

func (p *NVPublic) compareName(name Name) bool {
	n, err := p.Name()
	if err != nil {
		return false
	}
	return bytes.Equal(n, name)
}
