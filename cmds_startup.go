// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) Startup(startupType StartupType) error {
	if err := t.RunCommand(CommandStartup, nil, Separator, startupType); err != nil {
		return err
	}
	if startupType != StartupClear {
		return nil
	}

	for _, rc := range t.resources {
		nvRc, isNV := rc.(*nvIndexContext)
		if !isNV {
			continue
		}

		if nvRc.public.Attrs&AttrNVWriteDefine == 0 && nvRc.public.Attrs&AttrNVWritten > 0 {
			nvRc.clearAttr(AttrNVWriteLocked)
		}
		if nvRc.public.Attrs&AttrNVClearStClear > 0 {
			nvRc.clearAttr(AttrNVWritten)
		}
		nvRc.clearAttr(AttrNVReadLocked)
	}
	return nil
}

func (t *tpmContext) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, nil, Separator, shutdownType)
}
