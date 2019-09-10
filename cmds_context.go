// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 28 - Context Management

import (
	"fmt"
	"reflect"
)

type objectContextData struct {
	Public *Public `tpm2:"sized"`
	Name   Name
}

type sessionContextData struct {
	HashAlg        AlgorithmId
	SessionType    SessionType
	PolicyHMACType policyHMACType
	IsBound        bool
	BoundEntity    Name
	SessionKey     Digest
	NonceCaller    Nonce
	NonceTPM       Nonce
	Symmetric      *SymDef
}

type resourceContextDataU struct {
	Data interface{}
}

func (d resourceContextDataU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(uint8) {
	case contextTypeObject:
		return reflect.TypeOf((*objectContextData)(nil)), nil
	case contextTypeSession:
		return reflect.TypeOf((*sessionContextData)(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

const (
	contextTypeObject uint8 = iota
	contextTypeSession
)

type resourceContextData struct {
	ContextType uint8
	Data        resourceContextDataU `tpm2:"selector:ContextType"`
	TPMBlob     ContextData
}

func wrapContextBlob(tpmBlob ContextData, context ResourceContext) (ContextData, error) {
	d := resourceContextData{TPMBlob: tpmBlob}

	switch c := context.(type) {
	case *objectContext:
		d.ContextType = contextTypeObject
		d.Data.Data = &objectContextData{Public: &c.public, Name: c.name}
	case *sessionContext:
		d.ContextType = contextTypeSession
		d.Data.Data = &sessionContextData{HashAlg: c.hashAlg, SessionType: c.sessionType,
			PolicyHMACType: c.policyHMACType, IsBound: c.isBound, BoundEntity: c.boundEntity,
			SessionKey: c.sessionKey, NonceCaller: c.nonceCaller, NonceTPM: c.nonceTPM,
			Symmetric: c.symmetric}
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
		dd := d.Data.Data.(*objectContextData)
		return d.TPMBlob, &objectContext{public: Public(*dd.Public), name: dd.Name}, nil
	case contextTypeSession:
		dd := d.Data.Data.(*sessionContextData)
		if !cryptIsKnownDigest(dd.HashAlg) {
			return nil, nil, fmt.Errorf("invalid session hash algorithm %v", dd.HashAlg)
		}
		return d.TPMBlob, &sessionContext{hashAlg: dd.HashAlg, sessionType: dd.SessionType,
			policyHMACType: dd.PolicyHMACType, isBound: dd.IsBound, boundEntity: dd.BoundEntity,
			sessionKey: dd.SessionKey, nonceCaller: dd.NonceCaller, nonceTPM: dd.NonceTPM,
			symmetric: dd.Symmetric}, nil
	}

	return nil, nil, fmt.Errorf("invalid saved context type (%d)", d.ContextType)
}

func (t *TPMContext) ContextSave(saveContext ResourceContext) (*Context, error) {
	var context Context

	if err := t.RunCommand(CommandContextSave, nil, saveContext, Separator, Separator, Separator,
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

func (t *TPMContext) ContextLoad(context *Context) (ResourceContext, error) {
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

	if err := t.RunCommand(CommandContextLoad, nil, Separator, tmpContext, Separator,
		&loadedHandle); err != nil {
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

func (t *TPMContext) FlushContext(flushContext ResourceContext) error {
	if err := t.checkResourceContextParam(flushContext); err != nil {
		return fmt.Errorf("invalid resource context for flushContext: %v", err)
	}

	if err := t.RunCommand(CommandFlushContext, nil, Separator, flushContext.Handle()); err != nil {
		return err
	}

	t.evictResourceContext(flushContext)
	return nil
}

func (t *TPMContext) EvictControl(auth Handle, objectContext ResourceContext, persistentHandle Handle,
	authAuth interface{}) (ResourceContext, error) {
	if err := t.RunCommand(CommandEvictControl, nil, HandleWithAuth{Handle: auth, Auth: authAuth},
		objectContext, Separator, persistentHandle); err != nil {
		return nil, err
	}

	if objectContext.Handle() == persistentHandle {
		t.evictResourceContext(objectContext)
		return nil, nil
	}
	return t.WrapHandle(persistentHandle)
}
