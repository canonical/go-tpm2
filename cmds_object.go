package tpm2

import (
	"errors"
)

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

func (t *tpmImpl) Unseal(itemHandle ResourceContext, itemHandleAuth interface{}) (SensitiveData, error) {
	if itemHandle == nil {
		return nil, InvalidParamError{"nil itemHandle"}
	}
	if err := t.checkResourceContextParam(itemHandle); err != nil {
		return nil, err
	}

	var outData SensitiveData

	if err := t.RunCommand(CommandUnseal, ResourceWithAuth{Handle: itemHandle, Auth: itemHandleAuth},
		Separator, Separator, Separator, &outData); err != nil {
		return nil, err
	}

	return outData, nil
}

func (t *tpmImpl) ObjectChangeAuth(objectHandle, parentHandle ResourceContext, newAuth Auth,
	objectHandleAuth interface{}) (Private, error) {
	if objectHandle == nil {
		return nil, InvalidParamError{"nil objectHandle"}
	}
	if parentHandle == nil {
		return nil, InvalidParamError{"nil parentHandle"}
	}
	if err := t.checkResourceContextParam(objectHandle); err != nil {
		return nil, err
	}
	if err := t.checkResourceContextParam(parentHandle); err != nil {
		return nil, err
	}

	var outPrivate Private

	responseCode, responseTag, response, err := t.RunCommandAndReturnRawResponse(CommandObjectChangeAuth,
		ResourceWithAuth{Handle: objectHandle, Auth: objectHandleAuth}, parentHandle, Separator, newAuth)
	if err != nil {
		return nil, err
	}

	updatedObjectHandleAuth := objectHandleAuth

	switch s := objectHandleAuth.(type) {
	case *Session:
		if s.Handle.(*sessionContext).boundResource != objectHandle {
			updatedObjectHandleAuth =
				&Session{Handle: s.Handle, Attributes: s.Attributes, AuthValue: newAuth}
		}
	}

	if err := ProcessResponse(CommandHierarchyChangeAuth, responseCode, responseTag, response, Separator,
		&outPrivate, Separator, updatedObjectHandleAuth); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

func (t *tpmImpl) CreateLoaded(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	parentHandleAuth interface{}) (ResourceContext, Private, *Public, Name, error) {
	if parentHandle == nil {
		return nil, nil, nil, nil, InvalidParamError{"nil parentHandle"}
	}
	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}
	if inPublic == nil {
		return nil, nil, nil, nil, InvalidParamError{"nil inPublic"}
	}
	if err := t.checkResourceContextParam(parentHandle); err != nil {
		return nil, nil, nil, nil, err
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

	outPubCopy := outPublic.Copy()
	if outPubCopy == nil {
		return nil, nil, nil, nil, errors.New("cannot copy returned outPublic")
	}

	objectHandleRc := &objectContext{handle: objectHandle, public: *outPubCopy, name: name}
	t.addResourceContext(objectHandleRc)

	return objectHandleRc, outPrivate, &outPublic, name, nil
}
