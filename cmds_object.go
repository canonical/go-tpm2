package tpm2

func (t *tpmImpl) Create(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, parentHandleAuth interface{}) (Private, *Public,
	*CreationData, Digest, *TkCreation, error) {
	if parentHandle == nil {
		return nil, nil, nil, nil, nil, InvalidParamError{"nil parentHandle"}
	}
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, InvalidParamError{"nil inPublic"}
	}
	if err := t.checkResourceContextParam(parentHandle); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	var outPrivate Private
	var outPublic Public
	var creationData CreationData
	var creationHash Digest
	var creationTicket TkCreation

	if err := t.RunCommand(CommandCreate, ResourceWithAuth{Handle: parentHandle, Auth: parentHandleAuth},
		Separator, inSensitive, inPublic, outsideInfo, creationPCR, Separator, Separator, &outPrivate,
		&outPublic, &creationData, &creationHash, &creationTicket); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return outPrivate, &outPublic, &creationData, creationHash, &creationTicket, nil
}

func (t *tpmImpl) Load(parentHandle ResourceContext, inPrivate Private, inPublic *Public,
	parentHandleAuth interface{}) (ResourceContext, Name, error) {
	if parentHandle == nil {
		return nil, nil, InvalidParamError{"nil parentHandle"}
	}
	if inPublic == nil {
		return nil, nil, InvalidParamError{"nil inPublic"}
	}
	if err := t.checkResourceContextParam(parentHandle); err != nil {
		return nil, nil, err
	}

	pubCopy := inPublic.Copy()
	if pubCopy == nil {
		return nil, nil, InvalidParamError{"inPublic couldn't be copied"}
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoad, ResourceWithAuth{Handle: parentHandle, Auth: parentHandleAuth},
		Separator, inPrivate, inPublic, Separator, &objectHandle, Separator, &name); err != nil {
		return nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, public: *pubCopy, name: name}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, name, nil
}

func (t *tpmImpl) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle) (ResourceContext, Name,
	error) {
	if inPublic == nil {
		return nil, nil, InvalidParamError{"nil inPublic"}
	}

	pubCopy := inPublic.Copy()
	if pubCopy == nil {
		return nil, nil, InvalidParamError{"inPublic couldn't be copied"}
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoadExternal, Separator, inPrivate, inPublic, hierarchy, Separator,
		&objectHandle, Separator, &name); err != nil {
		return nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, public: *pubCopy, name: name}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, name, nil
}

func (t *tpmImpl) readPublic(objectHandle Handle) (*Public, Name, Name, error) {
	var outPublic Public
	var name Name
	var qualifiedName Name
	if err := t.RunCommand(CommandReadPublic, objectHandle, Separator, Separator, Separator, &outPublic,
		&name, &qualifiedName); err != nil {
		return nil, nil, nil, err
	}
	return &outPublic, name, qualifiedName, nil
}

func (t *tpmImpl) ReadPublic(objectHandle ResourceContext) (*Public, Name, Name, error) {
	if objectHandle == nil {
		return nil, nil, nil, InvalidParamError{"nil objectHandle"}
	}
	if err := t.checkResourceContextParam(objectHandle); err != nil {
		return nil, nil, nil, err
	}
	return t.readPublic(objectHandle.Handle())
}
