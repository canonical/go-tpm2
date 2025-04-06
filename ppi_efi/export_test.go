// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi_efi

import (
	"sync"

	efi "github.com/canonical/go-efilib"
)

func MockVars(vars efi.VarsBackend) (restore func()) {
	orig := customVars
	customVars = vars
	return func() {
		customVars = orig
	}
}

func ResetPPI() {
	ppiOnce = sync.Once{}
	ppiInstance = nil
	ppiErr = nil
}
