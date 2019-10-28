// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 10 - Testing

import (
	"fmt"
)

type suType uint8

const (
	suTypeReset suType = iota
	suTypeRestart
	suTypeResume
)

func computeStartupType(startupType StartupType, time *TimeInfo) suType {
	if startupType == StartupState {
		return suTypeResume
	}
	if time.ClockInfo.RestartCount == 0 {
		return suTypeReset
	}
	return suTypeRestart
}

// Startup executes the TPM2_Startup command with the specified StartupType. If this isn't preceded by _TPM_Init then it will return
// a *TPMError error with an error code of ErrorInitialize. The shutdown and startup sequence determines how the TPM responds to this
// call:
//  * A call with startupType == StartupClear preceded by a call to TPMContext.Shutdown with shutdownType == StartupClear or without
//    a preceding call to TPMContext.Shutdown will cause a TPM reset.
//  * A call with startupType == StartupClear preceded by a call to TPMContext.Shutdown with shutdownType == StartupState will cause
//    a TPM restart.
//  * A call with startupType == StartupState preceded by a call to TPMContext.Shutdown with shutdownType == StartupState will cause
//    a TPM resume.
//  * A call with startupType == StartupState that isn't preceded by a call to TPMContext.Shutdown with shutdownType == StartupState
//    will fail with an error.
//
// If called with startupType == StartupState, a *TPMError error with an error code of ErrorNVUninitialized will be returned if the
// saved state cannot be recovered. In this case, the function must be called with startupType == StartupClear.
//
// In addition to performing the startup actions described in the TPM Library Specification, on successful completion, all
// ResourceContext instances tracked by this TPMContext that correspond to transient objects or sessions will be invalidated as they
// are flushed from the TPM.
func (t *TPMContext) Startup(startupType StartupType) error {
	if err := t.RunCommand(CommandStartup, nil, Separator, startupType); err != nil {
		return err
	}

	time, err := t.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain reset count after Startup: %v", err)
	}

	st := computeStartupType(startupType, time)

	for _, rc := range t.resources {
		switch r := rc.(type) {
		case *nvIndexContext:
			if st == suTypeResume {
				continue
			}

			// If TPMA_NV_WRITE_DEFINE is clear or TPMA_NV_WRITTEN is clear, then
			// TPMA_NV_WRITE_LOCKED is cleared on restart or reset
			if r.public.Attrs&AttrNVWriteDefine == 0 || r.public.Attrs&AttrNVWritten == 0 {
				r.clearAttr(AttrNVWriteLocked)
			}

			// If the index is not a TPM_NT_COUNTER and TPMA_NV_CLEAR_STCLEAR is set and this is a
			// reset or restart, or TPMA_NV_ORDERLY is set and this is a reset, then TPMA_NV_WRITTEN
			// is cleared
			if r.public.Attrs.Type() != NVTypeCounter &&
				(r.public.Attrs&AttrNVClearStClear > 0 || (r.public.Attrs&AttrNVOrderly > 0 && st == suTypeReset)) {
				r.clearAttr(AttrNVWritten)
			}
			// TPMA_NV_READ_LOCKED is cleared on a restart or reset
			r.clearAttr(AttrNVReadLocked)
		case *objectContext:
			if rc.Handle().Type() == HandleTypePersistent {
				continue
			}
			t.evictResourceContext(rc)
		case *sessionContext:
			t.evictResourceContext(rc)
		}

	}
	return nil
}

// Shutdown executes the TPM2_Shutdown command with the specified StartupType, and is used to prepare the TPM for a power cycle.
// Calling this with shutdownType == StartupClear prepares the TPM for a TPM reset. Calling it with shutdownType == StartupState
// prepares the TPM for either a TPM restart or TPM resume, depending on how TPMContext.Startup is called. Some commands executed
// after TPMContext.Shutdown but before a power cycle will nullify the effect of this function.
func (t *TPMContext) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, nil, Separator, shutdownType)
}
