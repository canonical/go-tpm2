// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"
)

func MockWrapMssimTCTI(fn func(tpm2.TCTI, TPMFeatureFlags) (*TCTI, error)) (restore func()) {
	origWrapMssimTCTI := wrapMssimTCTI
	wrapMssimTCTI = fn
	return func() {
		wrapMssimTCTI = origWrapMssimTCTI
	}
}
