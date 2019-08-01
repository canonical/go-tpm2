// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

func (t *tpmContext) NVDefineSpace(authHandle Handle, auth Auth, publicInfo *NVPublic, authHandleAuth interface{},
	sessions ...*Session) error {
	if publicInfo == nil {
		return makeInvalidParamError("publicInfo", "nil value")
	}

	return t.RunCommand(CommandNVDefineSpace, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator, auth,
		(*NVPublic2B)(publicInfo))
}

func (t *tpmContext) NVUndefineSpace(authHandle Handle, nvIndex ResourceContext,
	authHandleAuth interface{}) error {
	if err := t.RunCommand(CommandNVUndefineSpace, nil,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, nvIndex); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

func (t *tpmContext) NVUndefineSpaceSpecial(nvIndex ResourceContext, platform Handle, nvIndexAuth,
	platformAuth interface{}) error {
	if err := t.RunCommand(CommandNVUndefineSpaceSpecial, nil,
		ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth},
		HandleWithAuth{Handle: platform, Auth: platformAuth}); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

func (t *tpmContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic NVPublic2B
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, sessions, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return (*NVPublic)(&nvPublic), nvName, nil
}

func (t *tpmContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for nvIndex: %v", err)
	}

	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}

func (t *tpmContext) NVWrite(authContext, nvIndex ResourceContext, data MaxNVBuffer, offset uint16,
	authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVWrite, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, data,
		offset); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *tpmContext) NVIncrement(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVIncrement, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *tpmContext) NVExtend(authContext, nvIndex ResourceContext, data MaxNVBuffer, authContextAuth interface{},
	sessions ...*Session) error {
	if err := t.RunCommand(CommandNVExtend, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		data); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *tpmContext) NVSetBits(authContext, nvIndex ResourceContext, bits uint64,
	authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVSetBits, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		bits); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *tpmContext) NVWriteLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVWriteLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWriteLocked)
	return nil
}

func (t *tpmContext) NVGlobalWriteLock(authHandle Handle, authHandleAuth interface{}) error {
	if err := t.RunCommand(CommandNVGlobalWriteLock, nil,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}); err != nil {
		return err
	}

	for _, rc := range t.resources {
		nvRc, isNV := rc.(*nvIndexContext)
		if !isNV {
			continue
		}

		if nvRc.public.Attrs&AttrNVGlobalLock > 0 {
			nvRc.setAttr(AttrNVWriteLocked)
		}
	}
	return nil
}

func (t *tpmContext) NVRead(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuth interface{},
	sessions ...*Session) (MaxNVBuffer, error) {
	var data MaxNVBuffer
	if err := t.RunCommand(CommandNVRead, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, size, offset,
		Separator, Separator, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (t *tpmContext) NVReadLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVReadLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVReadLocked)
	return nil
}

func (t *tpmContext) NVChangeAuth(nvIndex ResourceContext, newAuth Auth, nvIndexAuth interface{},
	sessions ...*Session) error {
	return t.RunCommand(CommandNVChangeAuth, sessions, ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth},
		Separator, newAuth)
}
