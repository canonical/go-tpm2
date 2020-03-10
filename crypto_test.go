// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"reflect"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/go-tpm2/internal/crypto"
)

func TestCryptoSymmetricModeConversions(t *testing.T) {
	if reflect.TypeOf(SymModeId(0)).Kind() != reflect.TypeOf(crypto.SymmetricMode(0)).Kind() {
		t.Errorf("Incompatible types")
	}

	for _, data := range []struct{
		desc string
		mode SymModeId
		cryptoMode crypto.SymmetricMode
	}{
		{
			desc: "SymModeNull",
			mode: SymModeNull,
			cryptoMode: crypto.SymmetricModeNull,
		},
		{
			desc: "SymModeCTR",
			mode: SymModeCTR,
			cryptoMode: crypto.SymmetricModeCTR,
		},
		{
			desc: "SymModeOFB",
			mode: SymModeOFB,
			cryptoMode: crypto.SymmetricModeOFB,
		},
		{
			desc: "SymModeCBC",
			mode: SymModeCBC,
			cryptoMode: crypto.SymmetricModeCBC,
		},
		{
			desc: "SymModeCFB",
			mode: SymModeCFB,
			cryptoMode: crypto.SymmetricModeCFB,
		},
		{
			desc: "SymModeECB",
			mode: SymModeECB,
			cryptoMode: crypto.SymmetricModeECB,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			if uint16(data.mode) != uint16(data.cryptoMode) {
				t.Errorf("Invalid value (%d vs %d)", data.mode, data.cryptoMode)
			}
		})
	}
}
