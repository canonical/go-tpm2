// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"testing"

	. "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

func init() {
	AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }
