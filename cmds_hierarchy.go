// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

func (t *tpmContext) CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, primaryObjectAuth interface{},
	sessions ...*Session) (ResourceContext, *Public, *CreationData, Digest, *TkCreation, Name, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle

	var outPublic Public2B
	var creationData CreationData2B
	var creationHash Digest
	var creationTicket TkCreation
	var name Name

	if err := t.RunCommand(CommandCreatePrimary,
		HandleWithAuth{Handle: primaryObject, Auth: primaryObjectAuth}, Separator,
		(*SensitiveCreate2B)(inSensitive), (*Public2B)(inPublic), outsideInfo, creationPCR, Separator,
		&objectHandle, Separator, &outPublic, &creationData, &creationHash, &creationTicket,
		&name, Separator, sessions); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	outPubCopy := (*Public)(&outPublic).Copy()
	if outPubCopy != nil {
		objectContext.public = *outPubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, (*Public)(&outPublic), (*CreationData)(&creationData), creationHash,
		&creationTicket, name, nil
}

func (t *tpmContext) Clear(authHandle Handle, authHandleAuth interface{}) error {
	responseCode, responseTag, response, err :=
		t.RunCommandAndReturnRawResponse(CommandClear,
			HandleWithAuth{Handle: authHandle, Auth: authHandleAuth})
	if err != nil {
		return err
	}

	updatedAuthHandleAuth := authHandleAuth
	var sc *sessionContext

	// If the session is not bound to authHandle, the TPM will respond with a HMAC generated with a key
	// derived from the empty auth
	switch s := authHandleAuth.(type) {
	case *Session:
		sc = s.Context.(*sessionContext)
		if !sc.isBoundTo(&permanentContext{handle: authHandle}) {
			updatedAuthHandleAuth = &Session{Context: s.Context, Attrs: s.Attrs}
		}
	}

	if err := t.ProcessResponse(CommandClear, responseCode, responseTag, response, Separator,
		Separator, HandleWithAuth{Handle: authHandle, Auth: updatedAuthHandleAuth}); err != nil {
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
		case *permanentContext:
			continue
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

func (t *tpmContext) ClearControl(authHandle Handle, disable bool, authHandleAuth interface{}) error {
	return t.RunCommand(CommandClearControl, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth},
		Separator, disable)
}

func (t *tpmContext) HierarchyChangeAuth(authHandle Handle, newAuth Auth, authHandleAuth interface{},
	sessions ...*Session) error {
	responseCode, responseTag, response, err :=
		t.RunCommandAndReturnRawResponse(CommandHierarchyChangeAuth,
			HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator, newAuth, Separator,
			sessions)
	if err != nil {
		return err
	}

	updatedAuthHandleAuth := authHandleAuth
	var sc *sessionContext

	// If the session is not bound to authHandle, the TPM will respond with a HMAC generated with a key
	// derived from newAuth
	switch s := authHandleAuth.(type) {
	case *Session:
		sc = s.Context.(*sessionContext)
		if !sc.isBoundTo(&permanentContext{handle: authHandle}) {
			updatedAuthHandleAuth =
				&Session{Context: s.Context, Attrs: s.Attrs, AuthValue: newAuth}
		}
	}

	defer func() {
		// If the session was bound to authHandle, it becomes unbound now. Future commands must provide
		// the value of newAuth with the session for commands operating on authHandle that require
		// an authorization.
		// This is deferred because the HMAC in the response is generated from a key that doesn't include
		// the auth value
		if sc != nil && sc.isBoundTo(&permanentContext{handle: authHandle}) {
			sc.boundResource = nil
		}
	}()

	return t.ProcessResponse(CommandHierarchyChangeAuth, responseCode, responseTag, response, Separator,
		Separator, HandleWithAuth{Handle: authHandle, Auth: updatedAuthHandleAuth}, sessions)
}
