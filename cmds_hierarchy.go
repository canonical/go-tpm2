// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 24 - Hierarchy Commands

import (
	"fmt"
)

func (t *TPMContext) CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, primaryObjectAuth interface{},
	sessions ...*Session) (ResourceContext, *Public, *CreationData, Digest, *TkCreation, Name, error) {
	if inPublic == nil {
		return nil, nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	var objectHandle Handle

	var outPublic publicSized
	var creationData creationDataSized
	var creationHash Digest
	var creationTicket TkCreation
	var name Name

	if err := t.RunCommand(CommandCreatePrimary, sessions,
		HandleWithAuth{Handle: primaryObject, Auth: primaryObjectAuth}, Separator,
		sensitiveCreateSized{inSensitive}, publicSized{inPublic}, outsideInfo, creationPCR, Separator,
		&objectHandle, Separator, &outPublic, &creationData, &creationHash, &creationTicket,
		&name); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	outPubCopy := outPublic.Ptr.Copy()
	if outPubCopy != nil {
		objectContext.public = *outPubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, outPublic.Ptr, creationData.Ptr, creationHash,
		&creationTicket, name, nil
}

func (t *TPMContext) Clear(authHandle Handle, authHandleAuth interface{}) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for authHandle: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandClear, s, authHandle)
	if err != nil {
		return err
	}

	// If the session is not bound to authHandle, the TPM will respond with a HMAC generated with a key
	// derived from the empty auth. If the session is bound, the TPM will respond with a HMAC generated from
	// the original key
	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		ctx.sessionParams[0].session =
			&Session{Context: authSession.Context, Attrs: authSession.Attrs}
	}

	if err := t.processResponse(ctx); err != nil {
		return err
	}

	getHandles := func(handleType Handle, out map[Handle]struct{}) error {
		handles, err := t.GetCapabilityHandles(handleType, CapabilityMaxHandles)
		if err != nil {
			return fmt.Errorf("cannot fetch handles from TPM after clear: %v", err)
		}
		var empty struct{}
		for _, handle := range handles {
			out[handle] = empty
		}
		return nil
	}

	handles := make(map[Handle]struct{})
	if err := getHandles(HandleTypeTransientObject, handles); err != nil {
		return err
	}
	if err := getHandles(HandleTypePersistentObject, handles); err != nil {
		return err
	}

	for _, rc := range t.resources {
		switch c := rc.(type) {
		case *objectContext:
			if _, exists := handles[c.handle]; exists {
				continue
			}
		case *nvIndexContext:
			if c.public.Attrs&AttrNVPlatformCreate > 0 {
				continue
			}
		case *sessionContext:
			continue
		}

		t.evictResourceContext(rc)
	}

	return nil
}

func (t *TPMContext) ClearControl(authHandle Handle, disable bool, authHandleAuth interface{}) error {
	return t.RunCommand(CommandClearControl, nil, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth},
		Separator, disable)
}

func (t *TPMContext) HierarchyChangeAuth(authHandle Handle, newAuth Auth, authHandleAuth interface{},
	sessions ...*Session) error {
	var s []*sessionParam
	s, err := t.validateAndAppendSessionParam(s, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth})
	if err != nil {
		return fmt.Errorf("error whilst processing handle with authorization for authHandle: %v", err)
	}
	s, err = t.validateAndAppendSessionParam(s, sessions)
	if err != nil {
		return fmt.Errorf("error whilst processing non-auth sessions: %v", err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(CommandHierarchyChangeAuth, s, authHandle, Separator,
		newAuth)
	if err != nil {
		return err
	}

	// If the session is not bound to authHandle, the TPM will respond with a HMAC generated with a key
	// derived from newAuth. If the session is bound, the TPM will respond with a HMAC generated from the
	// original key
	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		ctx.sessionParams[0].session =
			&Session{Context: authSession.Context, Attrs: authSession.Attrs, AuthValue: newAuth}
	}

	return t.processResponse(ctx)
}
