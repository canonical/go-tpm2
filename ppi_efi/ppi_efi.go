// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package ppi_efi provides a way of interacting with the TCG PC Client Physical Presence Interface via EFI variables
*/
package ppi_efi

import (
	"sync"

	efi "github.com/canonical/go-efilib"
	internal_ppi "github.com/canonical/go-tpm2/internal/ppi"
	internal_ppi_efi "github.com/canonical/go-tpm2/internal/ppi_efi"
	"github.com/canonical/go-tpm2/ppi"
)

// ErrUnavailable indicates that the EFI based physical presence interface
// is not available.
var ErrUnavailable = internal_ppi_efi.ErrUnavailable

var (
	ppiOnce     sync.Once
	ppiInstance ppi.PPI
	ppiErr      error

	customVars efi.VarsBackend
)

// PPI returns a global EFI based PPI instance. If no support is available,
// an [ErrUnavailable] error is returned. Calling this function will always
// return either a pointer to the same interface or the same error for the
// lifetime of a process.
func PPI() (ppi.PPI, error) {
	ppiOnce.Do(func() {
		var backend internal_ppi.PPIBackend
		var version ppi.Version
		backend, version, ppiErr = internal_ppi_efi.NewBackend(customVars)
		if ppiErr != nil {
			return
		}

		ppiInstance = internal_ppi.New(ppi.EFI, version, backend)
	})

	return ppiInstance, ppiErr
}
