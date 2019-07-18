package tpm2

func (t *tpmImpl) CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, primaryObjectAuth interface{}) (ResourceContext, *Public,
	*CreationData, Digest, *TkCreation, Name, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle

	var outPublic Public
	var creationData CreationData
	var creationHash Digest
	var creationTicket TkCreation
	var name Name

	if err := t.RunCommand(CommandCreatePrimary,
		HandleWithAuth{Handle: primaryObject, Auth: primaryObjectAuth}, Separator, inSensitive,
		inPublic, outsideInfo, creationPCR, Separator, &objectHandle, Separator, &outPublic,
		&creationData, &creationHash, &creationTicket, &name); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, name: name}
	outPubCopy := outPublic.Copy()
	if outPubCopy != nil {
		objectHandleRc.public = *outPubCopy
	}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, &outPublic, &creationData, creationHash, &creationTicket, name, nil
}

func (t *tpmImpl) Clear(authHandle Handle, authHandleAuth interface{}) error {
	return t.RunCommand(CommandClear, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth})
}

func (t *tpmImpl) ClearControl(authHandle Handle, disable bool, authHandleAuth interface{}) error {
	return t.RunCommand(CommandClearControl, HandleWithAuth{Handle: authHandle, Auth: authHandleAuth},
		Separator, disable)
}

func (t *tpmImpl) HierarchyChangeAuth(authHandle Handle, newAuth Auth, authHandleAuth interface{}) error {
	responseCode, responseTag, response, err :=
		t.RunCommandAndReturnRawResponse(CommandHierarchyChangeAuth,
			HandleWithAuth{Handle: authHandle, Auth: authHandleAuth}, Separator, newAuth)
	if err != nil {
		return err
	}

	updatedAuthHandleAuth := authHandleAuth

	switch s := authHandleAuth.(type) {
	case *Session:
		if s.Handle.(*sessionContext).boundResource.Handle() != authHandle {
			updatedAuthHandleAuth =
				&Session{Handle: s.Handle, Attributes: s.Attributes, AuthValue: newAuth}
		}
	}

	return t.ProcessResponse(CommandHierarchyChangeAuth, responseCode, responseTag, response, Separator,
		Separator, updatedAuthHandleAuth)
}
