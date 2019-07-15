package tpm2

func (t *tpmImpl) CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, session interface{}) (Resource, *Public, *CreationData,
	Digest, *TkCreation, Name, error) {
	if inSensitive == nil {
		return nil, nil, nil, nil, nil, nil, InvalidParamError{"nil inSensitive"}
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

	resource := &objectResource{handle: objectHandle, public: outPublic, name: name}
	t.addResource(resource)

	return resource, &outPublic, &creationData, creationHash, &creationTicket, name, nil
}

func (t *tpmImpl) Clear(authHandle Handle, session interface{}) error {
	return t.RunCommand(CommandClear, Format{1, 0}, Format{0, 0}, authHandle, session)
}

func (t *tpmImpl) ClearControl(authHandle Handle, disable bool, session interface{}) error {
	return t.RunCommand(CommandClearControl, Format{1, 1}, Format{0, 0}, authHandle, disable, session)
}

func (t *tpmImpl) HierarchyChangeAuth(authHandle Handle, newAuth Auth, session interface{}) error {
	return t.RunCommand(CommandHierarchyChangeAuth, Format{1, 1}, Format{0, 0}, authHandle,
		newAuth, session)
}
