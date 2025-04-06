// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"sync/atomic"

	"github.com/canonical/go-tpm2/ppi"
)

var (
	forcedPpiType uint32
)

const (
	forcePpiTypeSet    uint32 = 1 << 30
	forcePpiTypeLocked uint32 = 1 << 31
)

// ForcePPIType can be used to force the PPI implementation that is returned from
// [RawDevice.PhysicalPresenceInterface] on any device. This will panic if it is
// called after [RawDevice.PhysicalPresenceInterface] has been called for any device.
// If the forced PPI implementation isn't available, then any calls to
// [RawDevice.PhysicalPresenceInterface] will return an error rather than falling
// back to an available implementation.
func ForcePPIType(ppiType ppi.Type) {
	for {
		val := atomic.LoadUint32(&forcedPpiType)
		if val&forcePpiTypeLocked > 0 {
			// This happens once loadForcedPpiType has been called.
			panic("cannot call ForcePPIType once RawDevice.PhysicalPresenceInterface has been called for any device")
		}

		// Update forcedPpiType atomically to reflect that this function
		// has been called and to store the type that was requested.
		newval := forcePpiTypeSet | uint32(ppiType)
		if atomic.CompareAndSwapUint32(&forcedPpiType, val, newval) {
			break
		}

		// We raced with another caller or a caller of loadForcedPpiType,
		// so try again.
	}
}

func loadForcedPpiType() (ppiType ppi.Type, set bool) {
	for {
		val := atomic.LoadUint32(&forcedPpiType)
		if val&forcePpiTypeSet > 0 {
			// ForcePPIType has been called.
			ppiType = ppi.Type(val & 0x3)
			set = true
		}

		if val&forcePpiTypeLocked > 0 {
			// This function has already been called, so there
			// will be no more updates to forcedPpiType.
			break
		}

		// Update forcedPpiType to indicate that it should no longer
		// be modified.
		newval := val | forcePpiTypeLocked
		if atomic.CompareAndSwapUint32(&forcedPpiType, val, newval) {
			break
		}

		// We raced with another caller or a caller of ForcePPIType,
		// so try again.
	}

	return ppiType, set
}
