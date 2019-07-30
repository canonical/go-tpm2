// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import ()

func (t *tpmContext) Create(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, parentContextAuth interface{},
	sessions ...*Session) (Private, *Public, *CreationData, Digest, *TkCreation, error) {
	if err := t.checkResourceContextParam(parentContext, "parentContext"); err != nil {
		return nil, nil, nil, nil, nil, err
	}
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var outPrivate Private
	var outPublic Public2B
	var creationData CreationData2B
	var creationHash Digest
	var creationTicket TkCreation

	if err := t.RunCommand(CommandCreate, ResourceWithAuth{Context: parentContext, Auth: parentContextAuth},
		Separator, (*SensitiveCreate2B)(inSensitive), (*Public2B)(inPublic), outsideInfo, creationPCR,
		Separator, Separator, &outPrivate, &outPublic, &creationData, &creationHash,
		&creationTicket, Separator, sessions); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return outPrivate, (*Public)(&outPublic), (*CreationData)(&creationData), creationHash, &creationTicket,
		nil
}

func (t *tpmContext) Load(parentContext ResourceContext, inPrivate Private, inPublic *Public,
	parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Name, error) {
	if err := t.checkResourceContextParam(parentContext, "parentContext"); err != nil {
		return nil, nil, err
	}
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoad, ResourceWithAuth{Context: parentContext, Auth: parentContextAuth},
		Separator, inPrivate, (*Public2B)(inPublic), Separator, &objectHandle, Separator,
		&name, Separator, sessions); err != nil {
		return nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	pubCopy := inPublic.Copy()
	if pubCopy != nil {
		objectContext.public = *pubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, name, nil
}

func (t *tpmContext) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle,
	sessions ...*Session) (ResourceContext, Name, error) {
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoadExternal, Separator, (*Sensitive2B)(inPrivate), (*Public2B)(inPublic),
		hierarchy, Separator, &objectHandle, Separator, &name, Separator, sessions); err != nil {
		return nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	pubCopy := inPublic.Copy()
	if pubCopy != nil {
		objectContext.public = *pubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, name, nil
}

func (t *tpmContext) readPublic(objectHandle Handle, sessions ...*Session) (*Public, Name, Name, error) {
	var outPublic Public2B
	var name Name
	var qualifiedName Name
	if err := t.RunCommand(CommandReadPublic, objectHandle, Separator, Separator, Separator, &outPublic,
		&name, &qualifiedName, Separator, sessions); err != nil {
		return nil, nil, nil, err
	}
	return (*Public)(&outPublic), name, qualifiedName, nil
}

func (t *tpmContext) ReadPublic(objectContext ResourceContext, sessions ...*Session) (*Public, Name, Name, error) {
	if err := t.checkResourceContextParam(objectContext, "objectContext"); err != nil {
		return nil, nil, nil, err
	}
	return t.readPublic(objectContext.Handle(), sessions...)
}

func (t *tpmContext) Unseal(itemContext ResourceContext, itemContextAuth interface{},
	sessions ...*Session) (SensitiveData, error) {
	if err := t.checkResourceContextParam(itemContext, "itemContext"); err != nil {
		return nil, err
	}

	var outData SensitiveData

	if err := t.RunCommand(CommandUnseal, ResourceWithAuth{Context: itemContext, Auth: itemContextAuth},
		Separator, Separator, Separator, &outData, Separator, sessions); err != nil {
		return nil, err
	}

	return outData, nil
}

func (t *tpmContext) ObjectChangeAuth(objectContext, parentContext ResourceContext, newAuth Auth,
	objectContextAuth interface{}, sessions ...*Session) (Private, error) {
	if err := t.checkResourceContextParam(objectContext, "objectContext"); err != nil {
		return nil, err
	}
	if err := t.checkResourceContextParam(parentContext, "parentContext"); err != nil {
		return nil, err
	}

	var outPrivate Private

	if err := t.RunCommand(CommandObjectChangeAuth,
		ResourceWithAuth{Context: objectContext, Auth: objectContextAuth}, parentContext, Separator,
		newAuth, Separator, Separator, &outPrivate, Separator, sessions); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

func (t *tpmContext) CreateLoaded(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Private, *Public, Name, error) {
	if err := t.checkResourceContextParam(parentContext, "parentContext"); err != nil {
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
	var outPublic Public2B
	var name Name

	if err := t.RunCommand(CommandCreateLoaded,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		(*SensitiveCreate2B)(inSensitive), (*Public2B)(inPublic), Separator, &objectHandle, Separator,
		&outPrivate, &outPublic, &name, Separator, sessions); err != nil {
		return nil, nil, nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	outPubCopy := (*Public)(&outPublic).Copy()
	if outPubCopy != nil {
		objectContext.public = *outPubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, outPrivate, (*Public)(&outPublic), name, nil
}
