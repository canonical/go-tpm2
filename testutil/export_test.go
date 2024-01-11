// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"github.com/canonical/go-tpm2"
)

func MockWrapMssimTransport(fn func(tpm2.Transport, TPMFeatureFlags) (*Transport, error)) (restore func()) {
	origWrapMssimTransport := wrapMssimTransport
	wrapMssimTransport = fn
	return func() {
		wrapMssimTransport = origWrapMssimTransport
	}
}
