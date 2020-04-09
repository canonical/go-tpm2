// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"reflect"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
	"github.com/chrisccoulson/go-tpm2/internal"
)

func TestCryptoSymmetricModeConversions(t *testing.T) {
	if reflect.TypeOf(SymModeId(0)).Kind() != reflect.TypeOf(internal.SymmetricMode(0)).Kind() {
		t.Errorf("Incompatible types")
	}

	for _, data := range []struct {
		desc       string
		mode       SymModeId
		cryptoMode internal.SymmetricMode
	}{
		{
			desc:       "SymModeNull",
			mode:       SymModeNull,
			cryptoMode: internal.SymmetricModeNull,
		},
		{
			desc:       "SymModeCTR",
			mode:       SymModeCTR,
			cryptoMode: internal.SymmetricModeCTR,
		},
		{
			desc:       "SymModeOFB",
			mode:       SymModeOFB,
			cryptoMode: internal.SymmetricModeOFB,
		},
		{
			desc:       "SymModeCBC",
			mode:       SymModeCBC,
			cryptoMode: internal.SymmetricModeCBC,
		},
		{
			desc:       "SymModeCFB",
			mode:       SymModeCFB,
			cryptoMode: internal.SymmetricModeCFB,
		},
		{
			desc:       "SymModeECB",
			mode:       SymModeECB,
			cryptoMode: internal.SymmetricModeECB,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			if uint16(data.mode) != uint16(data.cryptoMode) {
				t.Errorf("Invalid value (%d vs %d)", data.mode, data.cryptoMode)
			}
		})
	}
}
