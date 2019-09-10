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

func computeStartupType(startupType StartupType, origTime, newTime *TimeInfo) suType {
	if startupType == StartupState {
		return suTypeResume
	}
	if origTime == nil || newTime.ClockInfo.ResetCount > origTime.ClockInfo.ResetCount {
		return suTypeReset
	}
	return suTypeRestart
}

func (t *TPMContext) Startup(startupType StartupType) error {
	origTime, err := t.ReadClock()
	if err != nil {
		tpmErr, isTPMErr := err.(TPMError)
		if !isTPMErr || tpmErr.Code != ErrorInitialize {
			return fmt.Errorf("cannot obtain reset count before Startup: %v", err)
		}
	}

	if err := t.RunCommand(CommandStartup, nil, Separator, startupType); err != nil {
		return err
	}

	newTime, err := t.ReadClock()
	if err != nil {
		return fmt.Errorf("cannot obtain reset count after Startup: %v", err)
	}

	st := computeStartupType(startupType, origTime, newTime)

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
				(r.public.Attrs&AttrNVClearStClear > 0 ||
					(r.public.Attrs&AttrNVOrderly > 0 && st == suTypeReset)) {
				r.clearAttr(AttrNVWritten)
			}
			// TPMA_NV_READ_LOCKED is cleared on a restart or reset
			r.clearAttr(AttrNVReadLocked)
		case *objectContext:
			if rc.Handle()&HandleTypePersistentObject == HandleTypePersistentObject {
				continue
			}
			t.evictResourceContext(rc)
		case *sessionContext:
			t.evictResourceContext(rc)
		}

	}
	return nil
}

func (t *TPMContext) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, nil, Separator, shutdownType)
}
