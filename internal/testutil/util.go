// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"encoding/hex"
	"testing"

	. "gopkg.in/check.v1"
)

// DecodeHexString decodes the supplied hex string in to a byte slice.
func DecodeHexString(c *C, s string) []byte {
	b, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return b
}

// DecodeHexStringT decodes the supplied hex string in to a byte slice.
func DecodeHexStringT(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return b
}
