// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
	"reflect"
)

type objectContextData struct {
	Public *Public2B
	Name
}

type sessionContextData struct {
	HashAlg       AlgorithmId
	BoundResource Name
	SessionKey    Digest
	NonceCaller   Nonce
	NonceTPM      Nonce
}

type resourceContextDataU struct {
	Object  *objectContextData
	Session *sessionContextData
}

func (d resourceContextDataU) Select(selector interface{}, u reflect.Value) (reflect.Value, error) {
	switch selector.(uint8) {
	case contextTypeObject:
		return u.FieldByName("Object"), nil
	case contextTypeSession:
		return u.FieldByName("Session"), nil
	}
	return reflect.Value{}, invalidSelectorError{selector}
}

const (
	contextTypeObject uint8 = iota
	contextTypeSession
)

type resourceContextData struct {
	ContextType uint8
	Data        resourceContextDataU
	TPMBlob     ContextData
}

func (d resourceContextData) Selector(field reflect.StructField) interface{} {
	return d.ContextType
}

func wrapContextBlob(tpmBlob ContextData, context ResourceContext) (ContextData, error) {
	d := resourceContextData{TPMBlob: tpmBlob}

	switch c := context.(type) {
	case *objectContext:
		d.ContextType = contextTypeObject
		d.Data.Object = &objectContextData{Public: (*Public2B)(&c.public), Name: c.name}
	case *sessionContext:
		d.ContextType = contextTypeSession
		d.Data.Session = &sessionContextData{HashAlg: c.hashAlg, BoundResource: c.boundResource,
			SessionKey: c.sessionKey, NonceCaller: c.nonceCaller, NonceTPM: c.nonceTPM}
	}

	data, err := MarshalToBytes(d)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal resource context: %v", err)
	}
	return data, nil
}

func unwrapContextBlob(blob ContextData) (ContextData, ResourceContext, error) {
	var d resourceContextData
	if _, err := UnmarshalFromBytes(blob, &d); err != nil {
		return nil, nil, fmt.Errorf("cannot unmarshal resource context: %v", err)
	}

	switch d.ContextType {
	case contextTypeObject:
		return d.TPMBlob, &objectContext{public: Public(*d.Data.Object.Public),
			name: d.Data.Object.Name}, nil
	case contextTypeSession:
		return d.TPMBlob, &sessionContext{hashAlg: d.Data.Session.HashAlg,
			boundResource: d.Data.Session.BoundResource, sessionKey: d.Data.Session.SessionKey,
			nonceCaller: d.Data.Session.NonceCaller, nonceTPM: d.Data.Session.NonceTPM}, nil
	}

	return nil, nil, fmt.Errorf("invalid saved context type (%d)", d.ContextType)
}

func (t *tpmContext) ContextSave(saveContext ResourceContext) (*Context, error) {
	if err := t.checkResourceContextParam(saveContext, "saveContext"); err != nil {
		return nil, err
	}

	var context Context

	if err := t.RunCommand(CommandContextSave, saveContext, Separator, Separator, Separator,
		&context); err != nil {
		return nil, err
	}

	blob, err := wrapContextBlob(context.Blob, saveContext)
	if err != nil {
		return nil, fmt.Errorf("cannot create context data: %v", err)
	}
	context.Blob = blob

	if saveContext.Handle()&HandleTypeHMACSession == HandleTypeHMACSession ||
		saveContext.Handle()&HandleTypePolicySession == HandleTypePolicySession {
		t.evictResourceContext(saveContext)
	}

	return &context, nil
}

func (t *tpmContext) ContextLoad(context *Context) (ResourceContext, error) {
	if context == nil {
		return nil, makeInvalidParamError("context", "nil value")
	}

	tmpContext := Context{Sequence: context.Sequence, SavedHandle: context.SavedHandle,
		Hierarchy: context.Hierarchy}
	blob, rc, err := unwrapContextBlob(context.Blob)
	if err != nil {
		return nil, fmt.Errorf("cannot unwrap context data: %v", err)
	}
	tmpContext.Blob = blob

	var loadedHandle Handle

	if err := t.RunCommand(CommandContextLoad, Separator, tmpContext, Separator, &loadedHandle); err != nil {
		return nil, err
	}

	switch c := rc.(type) {
	case *objectContext:
		c.handle = loadedHandle
	case *sessionContext:
		c.handle = loadedHandle
	}

	t.addResourceContext(rc)

	return rc, nil
}

func (t *tpmContext) FlushContext(flushContext ResourceContext) error {
	if err := t.checkResourceContextParam(flushContext, "flushContext"); err != nil {
		return err
	}

	if err := t.RunCommand(CommandFlushContext, Separator, flushContext.Handle()); err != nil {
		return err
	}

	t.evictResourceContext(flushContext)
	return nil
}

func (t *tpmContext) EvictControl(auth Handle, objectContext ResourceContext, persistentHandle Handle,
	authAuth interface{}) (ResourceContext, error) {
	if err := t.checkResourceContextParam(objectContext, "objectContext"); err != nil {
		return nil, err
	}

	if err := t.RunCommand(CommandEvictControl, HandleWithAuth{Handle: auth, Auth: authAuth},
		objectContext, Separator, persistentHandle); err != nil {
		return nil, err
	}

	if objectContext.Handle() == persistentHandle {
		t.evictResourceContext(objectContext)
		return nil, nil
	}
	return t.WrapHandle(persistentHandle)
}
