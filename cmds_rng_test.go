// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/rand"
	"testing"
)

func TestGetRandom(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	props, err := tpm.GetCapabilityTPMProperties(PropertyMaxDigest, 1)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	maxDigest := props[0].Value

	for _, data := range []struct {
		desc  string
		bytes uint16
	}{
		{
			desc:  "20Bytes",
			bytes: 20,
		},
		{
			desc:  "32Bytes",
			bytes: 32,
		},
		{
			desc:  "48Bytes",
			bytes: 48,
		},
		{
			desc:  "64Bytes",
			bytes: 64,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			random, err := tpm.GetRandom(data.bytes)
			if err != nil {
				t.Fatalf("GetRandom failed: %v", err)
			}
			size := int(data.bytes)
			if uint32(data.bytes) > maxDigest {
				size = int(maxDigest)
			}
			if len(random) != size {
				t.Errorf("Unexpected random data length (%d)", len(random))
			}
		})
	}
}

func TestStirRandom(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	inData := make([]byte, 128)
	rand.Read(inData)

	if err := tpm.StirRandom(inData); err != nil {
		t.Errorf("StirRandom failed: %v", err)
	}
}
