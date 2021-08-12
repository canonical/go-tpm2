// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/canonical/go-tpm2"
)

func TestHandle(t *testing.T) {
	for _, data := range []struct {
		desc       string
		handle     Handle
		handleType HandleType
	}{
		{
			desc:       "PCR",
			handle:     0x0000000a,
			handleType: HandleTypePCR,
		},
		{
			desc:       "NVIndex",
			handle:     0x0180ff00,
			handleType: HandleTypeNVIndex,
		},
		{
			desc:       "HMACSession",
			handle:     0x02000001,
			handleType: HandleTypeHMACSession,
		},
		{
			desc:       "PolicySession",
			handle:     0x03000001,
			handleType: HandleTypePolicySession,
		},
		{
			desc:       "Permanent",
			handle:     HandleOwner,
			handleType: HandleTypePermanent,
		},
		{
			desc:       "Transient",
			handle:     0x80000003,
			handleType: HandleTypeTransient,
		},
		{
			desc:       "Persistent",
			handle:     0x81000000,
			handleType: HandleTypePersistent,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			if data.handle.Type() != data.handleType {
				t.Errorf("Unexpected handle type (got %x, expected %x)", data.handle.Type(), data.handleType)
			}
		})
	}
}
