package tpm2

import ()

func (t *tpmContext) Create(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, parentHandleAuth interface{}) (Private, *Public,
	*CreationData, Digest, *TkCreation, error) {
	if err := t.checkResourceContextParam(parentHandle, "parentHandle"); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
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

func (t *tpmContext) Load(parentHandle ResourceContext, inPrivate Private, inPublic *Public,
	parentHandleAuth interface{}) (ResourceContext, Name, error) {
	if err := t.checkResourceContextParam(parentHandle, "parentHandle"); err != nil {
		return nil, nil, err
	}
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoad, ResourceWithAuth{Handle: parentHandle, Auth: parentHandleAuth},
		Separator, inPrivate, inPublic, Separator, &objectHandle, Separator, &name); err != nil {
		return nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, name: name}
	pubCopy := inPublic.Copy()
	if pubCopy != nil {
		objectHandleRc.public = *pubCopy
	}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, name, nil
}

func (t *tpmContext) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle) (ResourceContext,
	Name, error) {
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoadExternal, Separator, inPrivate, inPublic, hierarchy, Separator,
		&objectHandle, Separator, &name); err != nil {
		return nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, name: name}
	pubCopy := inPublic.Copy()
	if pubCopy != nil {
		objectHandleRc.public = *pubCopy
	}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, name, nil
}

func (t *tpmContext) readPublic(objectHandle Handle) (*Public, Name, Name, error) {
	var outPublic Public
	var name Name
	var qualifiedName Name
	if err := t.RunCommand(CommandReadPublic, objectHandle, Separator, Separator, Separator, &outPublic,
		&name, &qualifiedName); err != nil {
		return nil, nil, nil, err
	}
	return &outPublic, name, qualifiedName, nil
}

func (t *tpmContext) ReadPublic(objectHandle ResourceContext) (*Public, Name, Name, error) {
	if err := t.checkResourceContextParam(objectHandle, "objectHandle"); err != nil {
		return nil, nil, nil, err
	}
	return t.readPublic(objectHandle.Handle())
}

func (t *tpmContext) Unseal(itemHandle ResourceContext, itemHandleAuth interface{}) (SensitiveData, error) {
	if err := t.checkResourceContextParam(itemHandle, "itemHandle"); err != nil {
		return nil, err
	}

	var outData SensitiveData

	if err := t.RunCommand(CommandUnseal, ResourceWithAuth{Handle: itemHandle, Auth: itemHandleAuth},
		Separator, Separator, Separator, &outData); err != nil {
		return nil, err
	}

	return outData, nil
}

func (t *tpmContext) ObjectChangeAuth(objectHandle, parentHandle ResourceContext, newAuth Auth,
	objectHandleAuth interface{}) (Private, error) {
	if err := t.checkResourceContextParam(objectHandle, "objectHandle"); err != nil {
		return nil, err
	}
	if err := t.checkResourceContextParam(parentHandle, "parentHandle"); err != nil {
		return nil, err
	}

	var outPrivate Private

	if err := t.RunCommand(CommandObjectChangeAuth,
		ResourceWithAuth{Handle: objectHandle, Auth: objectHandleAuth}, parentHandle, Separator, newAuth,
		Separator, Separator, &outPrivate, Separator); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

func (t *tpmContext) CreateLoaded(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	parentHandleAuth interface{}) (ResourceContext, Private, *Public, Name, error) {
	if err := t.checkResourceContextParam(parentHandle, "parentHandle"); err != nil {
		return nil, nil, nil, nil, err
	}
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var outPrivate Private
	var outPublic Public
	var name Name

	if err := t.RunCommand(CommandCreateLoaded,
		ResourceWithAuth{Handle: parentHandle, Auth: parentHandleAuth}, Separator, inSensitive, inPublic,
		Separator, &objectHandle, Separator, &outPrivate, &outPublic, &name); err != nil {
		return nil, nil, nil, nil, err
	}

	objectHandleRc := &objectContext{handle: objectHandle, name: name}
	outPubCopy := outPublic.Copy()
	if outPubCopy != nil {
		objectHandleRc.public = *outPubCopy
	}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, outPrivate, &outPublic, name, nil
}
