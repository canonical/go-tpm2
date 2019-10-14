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

// Clear executes the TPM2_Clear command to remove all context associated with the current owner. The command
// requires knowledge of the authorization value for either the platform or lockout hierarchy. The hierarchy
// is specified by passing either HandlePlatform or HandleLockout to authHandle. The command requires the user
// auth role for authHandle, provided via authHandleAuth.
//
// On successful completion, as well as the TPM having performed the operations associated with the TPM2_Clear
// command, this function will invalidate all ResourceContext instances of NV indices associated with the current
// owner, and all transient and persistent objects that reside in the storage and endorsement hierarchies.
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

	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		// If the HMAC key for this command includes the auth value for authHandle, the TPM will respond
		// with a HMAC generated with a key based on an empty auth value.
		ctx.sessionParams[0].session =
			&Session{Context: authSession.Context, Attrs: authSession.Attrs}
	}

	if err := t.processResponse(ctx); err != nil {
		return err
	}

	getHandles := func(handleType Handle, out map[Handle]struct{}) error {
		handles, err := t.GetCapabilityHandles(handleType, CapabilityMaxProperties)
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

// ClearControl executes the TPM2_ClearControl command to enable or disable execution of the TPM2_Clear command
// (via the TPMContext.Clear function).
//
// If disable is true, then this command will disable the execution of TPM2_Clear. In this case, the command
// requires knowledge of the authorization value for the platform or lockout hierarchy. The hierarchy is
// specified via the authHandle parameter by setting it to either HandlePlatform or HandleLockout.
//
// If disable is false, then this command will enable execution of TPM2_Clear. In this case, the command requires
// knowledge of the authorization value for the platform hierarchy, and authHandle must be set to HandlePlatform.
//
// The command requires the user auth role for authHandle, provided via authHandleAuth.
func (t *TPMContext) ClearControl(authHandle Handle, disable bool, authHandleAuth interface{}) error {
	return t.RunCommand(CommandClearControl, nil, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth},
		Separator, disable)
}

// HierarchyChangeAuth executes the TPM2_HierarchyChangeAuth command to change the authorization value for the
// hierarchy associated with the authHandle parameter. The command requires the user auth role, provided via
// authHandleAuth.
//
// On successful completion, the authorization value for the hierarchy associated with authHandle will be set
// to the value of newAuth.
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

	authSession := ctx.sessionParams[0].session
	if authSession != nil {
		// If the HMAC key for this command includes the auth value for authHandle, the TPM will respond
		// with a HMAC generated with a key that includes newAuth instead.
		ctx.sessionParams[0].session =
			&Session{Context: authSession.Context, Attrs: authSession.Attrs, AuthValue: newAuth}
	}

	return t.processResponse(ctx)
}
