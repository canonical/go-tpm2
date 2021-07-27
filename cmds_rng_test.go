// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto/rand"
	"testing"

	"github.com/canonical/go-tpm2/testutil"
)

func TestGetRandom(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, 0)
	defer closeTPM()

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
			desc:  "512Bytes",
			bytes: 512,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			random, err := tpm.GetRandom(data.bytes)
			if err != nil {
				t.Fatalf("GetRandom failed: %v", err)
			}
			if len(random) != int(data.bytes) {
				t.Errorf("Unexpected random data length (%d)", len(random))
			}
		})
	}
}

func TestStirRandom(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureNV)
	defer closeTPM()

	inData := make([]byte, 128)
	rand.Read(inData)

	if err := tpm.StirRandom(inData); err != nil {
		t.Errorf("StirRandom failed: %v", err)
	}
}
