// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"flag"
	"fmt"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func init() {
	testutil.AddCommandLineFlags()
}

func authSessionHandle(sc tpm2.SessionContext) tpm2.Handle {
	if sc == nil {
		return tpm2.HandlePW
	}
	return sc.Handle()
}

func Test(t *testing.T) { TestingT(t) }

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if testutil.TPMBackend == testutil.TPMBackendMssim {
			simulatorCleanup, err := testutil.LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()
		}

		return m.Run()
	}())
}
