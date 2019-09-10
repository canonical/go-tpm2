// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 31 - Non-volatile Storage

import (
	"fmt"
)

func (t *TPMContext) NVDefineSpace(authHandle Handle, auth Auth, publicInfo *NVPublic, authHandleAuth interface{},
	sessions ...*Session) error {
	if publicInfo == nil {
		return makeInvalidParamError("publicInfo", "nil value")
	}

	return t.RunCommand(CommandNVDefineSpace, sessions,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator, auth,
		nvPublicSized{publicInfo})
}

func (t *TPMContext) NVUndefineSpace(authHandle Handle, nvIndex ResourceContext,
	authHandleAuth interface{}) error {
	if err := t.RunCommand(CommandNVUndefineSpace, nil,
		HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, nvIndex); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

func (t *TPMContext) NVUndefineSpaceSpecial(nvIndex ResourceContext, platform Handle, nvIndexAuth,
	platformAuth interface{}) error {
	if err := t.RunCommand(CommandNVUndefineSpaceSpecial, nil,
		ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth},
		HandleWithAuth{Handle: platform, Auth: platformAuth}); err != nil {
		return err
	}

	t.evictResourceContext(nvIndex)
	return nil
}

func (t *TPMContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic nvPublicSized
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, sessions, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return nvPublic.Ptr, nvName, nil
}

func (t *TPMContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for nvIndex: %v", err)
	}

	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}

func (t *TPMContext) NVWrite(authContext, nvIndex ResourceContext, data MaxNVBuffer, offset uint16,
	authContextAuth interface{}, sessions ...*Session) error {
	if err := t.RunCommand(CommandNVWrite, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, data,
		offset); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *TPMContext) NVIncrement(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVIncrement, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *TPMContext) NVExtend(authContext, nvIndex ResourceContext, data MaxNVBuffer, authContextAuth interface{},
	sessions ...*Session) error {
	if err := t.RunCommand(CommandNVExtend, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		data); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *TPMContext) NVSetBits(authContext, nvIndex ResourceContext, bits uint64,
	authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVSetBits, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator,
		bits); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWritten)
	return nil
}

func (t *TPMContext) NVWriteLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVWriteLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVWriteLocked)
	return nil
}

func (t *TPMContext) NVGlobalWriteLock(authHandle Handle, authHandleAuth interface{}) error {
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

func (t *TPMContext) NVRead(authContext, nvIndex ResourceContext, size, offset uint16, authContextAuth interface{},
	sessions ...*Session) (MaxNVBuffer, error) {
	var data MaxNVBuffer
	if err := t.RunCommand(CommandNVRead, sessions,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex, Separator, size, offset,
		Separator, Separator, &data); err != nil {
		return nil, err
	}

	return data, nil
}

func (t *TPMContext) NVReadLock(authContext, nvIndex ResourceContext, authContextAuth interface{}) error {
	if err := t.RunCommand(CommandNVReadLock, nil,
		ResourceWithAuth{Context: authContext, Auth: authContextAuth}, nvIndex); err != nil {
		return err
	}

	nvIndex.(*nvIndexContext).setAttr(AttrNVReadLocked)
	return nil
}

func (t *TPMContext) NVChangeAuth(nvIndex ResourceContext, newAuth Auth, nvIndexAuth interface{},
	sessions ...*Session) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, ResourceWithAuth{Context: nvIndex, Auth: nvIndexAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing resource context with authorization for nvIndex: %v",
			err)
	}
	s, err = t.validateAndAppendSessionParam(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandNVChangeAuth, s, nvIndex, Separator, newAuth)
	if err != nil {
		return err
	}

	// If the session is not bound to nvIndex, the TPM will respond with a HMAC generated with a key
	// derived from newAuth. If the session is bound, the TPM will respond with a HMAC generated from the
	// original key
	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		ctx.sessionParams[0].session =
			&Session{Context: authSession.Context, Attrs: authSession.Attrs, AuthValue: newAuth}
	}

	return t.processResponse(ctx)
}

// func (t *TPMContext) NVCertify(signContext, authContext, nvIndex ResourceContext, qualifyingData Data,
//	inScheme *SigScheme, size, offset uint16, signContextAuth, authContextAuth interface{},
//	sessions ...*Session) (AttestRaw, *Signature, error) {
// }
