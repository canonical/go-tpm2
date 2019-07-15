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

	if err := t.RunCommand(CommandCreatePrimary, Format{1, 4}, Format{1, 5}, primaryObject,
		inSensitive, inPublic, outsideInfo, creationPCR, &objectHandle, &outPublic, &creationData,
		&creationHash, &creationTicket, &name, session); err != nil {
		return nil, nil, nil, nil, nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, public: outPublic, name: name}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, &outPublic, &creationData, creationHash, &creationTicket, name, nil
}

func (t *tpmImpl) Clear(authHandle Handle, session interface{}) error {
	return t.RunCommand(CommandClear, Format{1, 0}, Format{0, 0}, authHandle, session)
}

func (t *tpmImpl) ClearControl(authHandle Handle, disable bool, session interface{}) error {
	return t.RunCommand(CommandClearControl, Format{1, 1}, Format{0, 0}, authHandle, disable, session)
}

func (t *tpmImpl) HierarchyChangeAuth(authHandle Handle, newAuth Auth, session interface{}) error {
	responseCode, responseTag, response, err :=
		t.RunCommandAndReturnRawResponse(CommandHierarchyChangeAuth, Format{1, 1}, authHandle, newAuth,
			session)
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

	return ProcessResponse(CommandHierarchyChangeAuth, responseCode, responseTag, response, Format{0, 0},
		updatedSession)
}
