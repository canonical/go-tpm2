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

// ContextSave executes the TPM2_ContextSave command on the handle referenced by saveContext, in order to save
// the context associated with that handle outside of the TPM. The TPM encrypts and integrity protects the
// context with a key derived from the hierarchy proof. If saveContext does not correspond to a transient object or
// a session, then it will return an error.
//
// On successful completion, it returns a Context instance that can be passed to TPMContext.ContextLoad. Note that
// this function wraps the context data returned from the TPM with some host-side state associated with the
// resource, so that it can be restored fully in TPMContext.ContextLoad. If saveContext corresponds to a session,
// then TPM2_ContextSave also flushes resources associated with the session from the TPM (it becomes an active
// session rather than a loaded session). In this case, saveContext is invalidated.
//
// Note that if saveContext corresponds to a session, the host-side state that is added to the returned context
// blob includes the session key.
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

	if saveContext.Handle().Type() == HandleTypeHMACSession ||
		saveContext.Handle().Type() == HandleTypePolicySession {
		t.evictResourceContext(saveContext)
	}

	return &context, nil
}

// ContextLoad executes the TPM2_ContextLoad command with the supplied Context, in order to restore a context
// previously saved from TPMContext.ContextSave. On successful completion, it returns a ResourceContext which
// corresponds to the resource loaded in to the TPM.
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

// FlushContext executes the TPM2_FlushContext command on the handle referenced by flushContext, in order to flush
// resources associated with it from the TPM. If flushContext does not correspond to a transient object or a
// session, then it will return with an error.
//
// On successful completion, flushContext is invalidated. If flushContext corresponded to a session, then it will
// no longer be possible to restore that session with TPMContext.ContextLoad, even if it was previously saved with
// TPMContext.ContextSave.
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

// EvictControl executes the TPM2_EvictControl command on the handle referenced by objectContext. To persist a
// transient object, objectContext should correspond to the transient object and persistentHandle should specify
// the persistent handle to which the resource associated with objectContext should be persisted. To evict a
// persistent object, objectContext should correspond to the persistent object and persistentHandle should be
// the handle associated with that resource.
//
// The auth handle specifies a hierarchy - it should be HandlePlatform for objects within the platform hierarchy,
// or HandleOwner for objects within the storage or endorsement hierarchies. If the object is in the null
// hierarchy, this function will return an error. The auth handle requires the user auth role, provided via
// authAuth.
//
// On successful completion of persisting a transient object, it returns a ResourceContext that corresponds to the
// persistent object. On successful completion of evicting a persistent object, it returns a nil ResourceContext,
// and objectContext will be invalidated.
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
