// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"encoding/hex"

	. "gopkg.in/check.v1"
)

func DecodeHexString(c *C, s string) []byte {
	b, err := hex.DecodeString(s)
	c.Assert(err, IsNil)
	return b
}
