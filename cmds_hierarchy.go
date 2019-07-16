package tpm2

func (t *tpmImpl) CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, session interface{}) (ResourceContext, *Public,
	*CreationData, Digest, *TkCreation, Name, error) {
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, nil, InvalidParamError{"nil inPublic"}
	}

	var objectHandle Handle

	var outPublic Public
	var creationData CreationData
	var creationHash Digest
	var creationTicket TkCreation
	var name Name

	if err := t.RunCommand(CommandCreatePrimary, primaryObject, Separator, inSensitive, inPublic,
		outsideInfo, creationPCR, Separator, &objectHandle, Separator, &outPublic, &creationData,
		&creationHash, &creationTicket, &name, Separator, session); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, public: outPublic, name: name}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, &outPublic, &creationData, creationHash, &creationTicket, name, nil
}

func (t *tpmImpl) Clear(authHandle Handle, session interface{}) error {
	return t.RunCommand(CommandClear, authHandle, Separator, Separator, Separator, Separator, session)
}

func (t *tpmImpl) ClearControl(authHandle Handle, disable bool, session interface{}) error {
	return t.RunCommand(CommandClearControl, authHandle, Separator, disable, Separator, Separator,
		Separator, session)
}

func (t *tpmImpl) HierarchyChangeAuth(authHandle Handle, newAuth Auth, session interface{}) error {
	responseCode, responseTag, response, err :=
		t.RunCommandAndReturnRawResponse(CommandHierarchyChangeAuth, authHandle, Separator, newAuth,
			Separator, session)
	if err != nil {
		return err
	}

	updatedSession := session

	switch s := session.(type) {
	case *Session:
		if s.Handle.(*sessionContext).boundResource.Handle() != authHandle {
			updatedSession = &Session{Handle: s.Handle, Attributes: s.Attributes, AuthValue: newAuth}
		}
	}

	return ProcessResponse(CommandHierarchyChangeAuth, responseCode, responseTag, response, Separator,
		Separator, updatedSession)
}
