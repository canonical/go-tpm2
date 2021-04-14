// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"flag"
	"fmt"
	"os"
	"testing"

	. "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

func init() {
	AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if TPMBackend == TPMBackendMssim {
			simulatorCleanup, err := LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()
		}

		return m.Run()
	}())
}
