// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 12 - Object Commands

import (
	"fmt"
)

func (t *TPMContext) Create(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	outsideInfo Data, creationPCR PCRSelectionList, parentContextAuth interface{},
	sessions ...*Session) (Private, *Public, *CreationData, Digest, *TkCreation, error) {
	if inPublic == nil {
		return nil, nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	var outPrivate Private
	var outPublic publicSized
	var creationData creationDataSized
	var creationHash Digest
	var creationTicket TkCreation

	if err := t.RunCommand(CommandCreate, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		sensitiveCreateSized{inSensitive}, publicSized{inPublic}, outsideInfo, creationPCR, Separator,
		Separator, &outPrivate, &outPublic, &creationData, &creationHash,
		&creationTicket); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	return outPrivate, outPublic.Ptr, creationData.Ptr, creationHash, &creationTicket, nil
}

func (t *TPMContext) Load(parentContext ResourceContext, inPrivate Private, inPublic *Public,
	parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Name, error) {
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoad, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator, inPrivate,
		publicSized{inPublic}, Separator, &objectHandle, Separator, &name); err != nil {
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

func (t *TPMContext) LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle,
	sessions ...*Session) (ResourceContext, Name, error) {
	if inPublic == nil {
		return nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	var objectHandle Handle
	var name Name

	if err := t.RunCommand(CommandLoadExternal, sessions, Separator, sensitiveSized{inPrivate},
		publicSized{inPublic}, hierarchy, Separator, &objectHandle, Separator, &name); err != nil {
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

func (t *TPMContext) readPublic(objectHandle Handle, sessions ...*Session) (*Public, Name, Name, error) {
	var outPublic publicSized
	var name Name
	var qualifiedName Name
	if err := t.RunCommand(CommandReadPublic, sessions, objectHandle, Separator, Separator, Separator,
		&outPublic, &name, &qualifiedName); err != nil {
		return nil, nil, nil, err
	}
	return outPublic.Ptr, name, qualifiedName, nil
}

func (t *TPMContext) ReadPublic(objectContext ResourceContext, sessions ...*Session) (*Public, Name, Name, error) {
	if err := t.checkResourceContextParam(objectContext); err != nil {
		return nil, nil, nil, fmt.Errorf("invalid resource context for objectContext: %v", err)
	}

	return t.readPublic(objectContext.Handle(), sessions...)
}

func (t *TPMContext) ActivateCredential(activateContext, keyContext ResourceContext, credentialBlob IDObjectRaw,
	secret EncryptedSecret, activateContextAuth, keyContextAuth interface{}, sessions ...*Session) (Digest,
	error) {
	if credentialBlob == nil {
		return nil, makeInvalidParamError("credentialBlob", "nil value")
	}

	var certInfo Digest
	if err := t.RunCommand(CommandActivateCredential, sessions,
		ResourceWithAuth{Context: activateContext, Auth: activateContextAuth},
		ResourceWithAuth{Context: keyContext, Auth: keyContextAuth}, Separator, credentialBlob, secret,
		Separator, Separator, &certInfo); err != nil {
		return nil, err
	}
	return certInfo, nil
}

func (t *TPMContext) MakeCredential(context ResourceContext, credential Digest, objectName Name,
	sessions ...*Session) (IDObjectRaw, EncryptedSecret, error) {
	var credentialBlob IDObjectRaw
	var secret EncryptedSecret
	if err := t.RunCommand(CommandMakeCredential, sessions, context, Separator, credential, objectName,
		Separator, Separator, &credentialBlob, &secret); err != nil {
		return nil, nil, err
	}
	return credentialBlob, secret, nil
}

func (t *TPMContext) Unseal(itemContext ResourceContext, itemContextAuth interface{},
	sessions ...*Session) (SensitiveData, error) {
	var outData SensitiveData

	if err := t.RunCommand(CommandUnseal, sessions,
		ResourceWithAuth{Context: itemContext, Auth: itemContextAuth}, Separator, Separator, Separator,
		&outData); err != nil {
		return nil, err
	}

	return outData, nil
}

func (t *TPMContext) ObjectChangeAuth(objectContext, parentContext ResourceContext, newAuth Auth,
	objectContextAuth interface{}, sessions ...*Session) (Private, error) {
	var outPrivate Private

	if err := t.RunCommand(CommandObjectChangeAuth, sessions,
		ResourceWithAuth{Context: objectContext, Auth: objectContextAuth}, parentContext, Separator,
		newAuth, Separator, Separator, &outPrivate); err != nil {
		return nil, err
	}

	return outPrivate, nil
}

func (t *TPMContext) CreateLoaded(parentContext ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
	parentContextAuth interface{}, sessions ...*Session) (ResourceContext, Private, *Public, Name, error) {
	if inPublic == nil {
		return nil, nil, nil, nil, makeInvalidParamError("inPublic", "nil value")
	}

	if inSensitive == nil {
		inSensitive = &SensitiveCreate{}
	}

	var objectHandle Handle
	var outPrivate Private
	var outPublic publicSized
	var name Name

	if err := t.RunCommand(CommandCreateLoaded, sessions,
		ResourceWithAuth{Context: parentContext, Auth: parentContextAuth}, Separator,
		sensitiveCreateSized{inSensitive}, publicSized{inPublic}, Separator, &objectHandle, Separator,
		&outPrivate, &outPublic, &name); err != nil {
		return nil, nil, nil, nil, err
	}

	objectContext := &objectContext{handle: objectHandle, name: name}
	outPubCopy := outPublic.Ptr.Copy()
	if outPubCopy != nil {
		objectContext.public = *outPubCopy
	}
	t.addResourceContext(objectContext)

	return objectContext, outPrivate, outPublic.Ptr, name, nil
}
