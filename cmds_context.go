// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 28 - Context Management

import (
	"errors"
	"fmt"
	"reflect"
)

type objectContextData struct {
	Public *Public `tpm2:"sized"`
	Name   Name
}

type sessionContextData struct {
	HashAlg        HashAlgorithmId
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

func wrapContextBlob(tpmBlob ContextData, context ResourceContext) ContextData {
	d := resourceContextData{TPMBlob: tpmBlob}

	switch c := context.(type) {
	case *objectContext:
		d.ContextType = contextTypeObject
		d.Data.Data = &objectContextData{Public: &c.public, Name: c.name}
	case *sessionContext:
		d.ContextType = contextTypeSession
		d.Data.Data = &sessionContextData{
			HashAlg:        c.hashAlg,
			SessionType:    c.sessionType,
			PolicyHMACType: c.policyHMACType,
			IsBound:        c.isBound,
			BoundEntity:    c.boundEntity,
			SessionKey:     c.sessionKey,
			NonceCaller:    c.nonceCaller,
			NonceTPM:       c.nonceTPM,
			Symmetric:      c.symmetric}
	}

	data, err := MarshalToBytes(d)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal wrapped resource context data: %v", err))
	}
	return data
}

// ContextSave executes the TPM2_ContextSave command on the handle referenced by saveContext, in order to save the context associated
// with that handle outside of the TPM. The TPM encrypts and integrity protects the context with a key derived from the hierarchy
// proof. If saveContext does not correspond to a transient object or a session, then it will return an error.
//
// On successful completion, it returns a Context instance that can be passed to TPMContext.ContextLoad. Note that this function
// wraps the context data returned from the TPM with some host-side state associated with the resource, so that it can be restored
// fully in TPMContext.ContextLoad. If saveContext corresponds to a session, then TPM2_ContextSave also flushes resources associated
// with the session from the TPM (it becomes an active session rather than a loaded session). In this case, saveContext is marked as
// not loaded and can not be used for any authorizations.
//
// If saveContext corresponds to a session, the host-side state that is added to the returned context blob includes the session key.
//
// If saveContext corresponds to a session and no more contexts can be saved, a *TPMError error will be returned with an error code
// of ErrorTooManyContexts. If a context ID cannot be assigned for the session, a *TPMWarning error with a warning code of
// WarningContextGap will be returned.
func (t *TPMContext) ContextSave(saveContext ResourceContext) (*Context, error) {
	if sc, isSession := saveContext.(*sessionContext); isSession {
		if sc.flags&sessionContextFull == 0 {
			return nil, errors.New("cannot context save a session with an incomplete ResourceContext")
		}
	}

	var context Context

	if err := t.RunCommand(CommandContextSave, nil,
		saveContext, Separator,
		Separator,
		Separator,
		&context); err != nil {
		return nil, err
	}

	context.Blob = wrapContextBlob(context.Blob, saveContext)

	if sc, isSession := saveContext.(*sessionContext); isSession {
		sc.flags &= ^sessionContextLoaded
	}

	return &context, nil
}

// ContextLoad executes the TPM2_ContextLoad command with the supplied Context, in order to restore a context previously saved from
// TPMContext.ContextSave.
//
// If the size field of the integrity HMAC in the context blob is greater than the size of the largest digest algorithm, a *TPMError
// with an error code of ErrorSize is returned. If the context blob is shorter than the size indicated for the integrity HMAC, a
// *TPMError with an error code of ErrorInsufficient is returned.
//
// If the size of the context's integrity HMAC does not match the context integrity digest algorithm for the TPM, or the context
// blob is too short, a *TPMParameterError error with an error code of ErrorSize will be returned. If the integrity HMAC check fails,
// a *TPMParameterError with an error code of ErrorIntegrity will be returned.
//
// If the hierarchy that the context is part of is disabled, a *TPMParameterError error with an error code of ErrorHierarchy will be
// returned.
//
// If the context corresponds to a session but the handle doesn't reference a saved session or the sequence number is invalid, a
// *TPMParameterError error with an error code of ErrorHandle will be returned.
//
// If the context corresponds to a session and no more sessions can be created until the oldest session is context loaded, and context
// doesn't correspond to the oldest session, a *TPMWarning error with a warning code of WarningContextGap will be returned.
//
// If there are no more slots available for objects or loaded sessions, a *TPMWarning error with a warning code of either
// WarningSessionMemory or WarningObjectMemory will be returned.
//
// On successful completion, it returns a ResourceContext which corresponds to the resource loaded in to the TPM.
func (t *TPMContext) ContextLoad(context *Context) (ResourceContext, error) {
	if context == nil {
		return nil, makeInvalidParamError("context", "nil value")
	}

	var d resourceContextData
	if _, err := UnmarshalFromBytes(context.Blob, &d); err != nil {
		return nil, fmt.Errorf("cannot unmarshal context data blob: %v", err)
	}

	switch d.ContextType {
	case contextTypeObject:
		if context.SavedHandle.Type() != HandleTypeTransient {
			return nil, errors.New("cannot load context: inconsistent attributes")
		}
	case contextTypeSession:
		if context.SavedHandle.Type() != HandleTypeHMACSession && context.SavedHandle.Type() != HandleTypePolicySession {
			return nil, errors.New("cannot load context: inconsistent attributes")
		}
		if !cryptIsKnownDigest(d.Data.Data.(*sessionContextData).HashAlg) {
			return nil, fmt.Errorf("cannot load context: invalid session hash algorithm %v", d.Data.Data.(*sessionContextData).HashAlg)
		}
	default:
		return nil, errors.New("cannot load context: inconsistent attributes")
	}

	tpmContext := Context{
		Sequence:    context.Sequence,
		SavedHandle: context.SavedHandle,
		Hierarchy:   context.Hierarchy,
		Blob:        d.TPMBlob}

	var loadedHandle Handle

	if err := t.RunCommand(CommandContextLoad, nil,
		Separator,
		tpmContext, Separator,
		&loadedHandle); err != nil {
		return nil, err
	}

	var rc ResourceContext

	switch d.ContextType {
	case contextTypeObject:
		dd := d.Data.Data.(*objectContextData)
		rc = &objectContext{handle: loadedHandle, public: Public(*dd.Public), name: dd.Name}
		t.addResourceContext(rc)
	case contextTypeSession:
		dd := d.Data.Data.(*sessionContextData)
		r, exists := t.resources[normalizeHandleForMap(loadedHandle)]
		var sc *sessionContext
		if !exists {
			sc = &sessionContext{handle: loadedHandle}
			rc = sc
			t.addResourceContext(rc)
		} else {
			sc = r.(*sessionContext)
			sc.handle = loadedHandle
			rc = r
		}
		sc.flags = sessionContextFull | sessionContextLoaded
		sc.hashAlg = dd.HashAlg
		sc.sessionType = dd.SessionType
		sc.policyHMACType = dd.PolicyHMACType
		sc.isBound = dd.IsBound
		sc.boundEntity = dd.BoundEntity
		sc.sessionKey = dd.SessionKey
		sc.nonceCaller = dd.NonceCaller
		sc.nonceTPM = dd.NonceTPM
		sc.symmetric = dd.Symmetric
	}

	return rc, nil
}

// FlushContext executes the TPM2_FlushContext command on the handle referenced by flushContext, in order to flush resources
// associated with it from the TPM. If flushContext does not correspond to a transient object or a session, then it will return
// with an error.
//
// On successful completion, flushContext is invalidated. If flushContext corresponded to a session, then it will no longer be
// possible to restore that session with TPMContext.ContextLoad, even if it was previously saved with TPMContext.ContextSave.
func (t *TPMContext) FlushContext(flushContext ResourceContext) error {
	if err := t.checkResourceContextParam(flushContext); err != nil {
		return fmt.Errorf("invalid resource context for flushContext: %v", err)
	}

	if err := t.RunCommand(CommandFlushContext, nil,
		Separator,
		flushContext.Handle()); err != nil {
		return err
	}

	t.evictResourceContext(flushContext)
	return nil
}

// EvictControl executes the TPM2_EvictControl command on the handle referenced by object. To persist a transient object,
// object should correspond to the transient object and persistentHandle should specify the persistent handle to which the
// resource associated with object should be persisted. To evict a persistent object, object should correspond to the
// persistent object and persistentHandle should be the handle associated with that resource.
//
// The auth handle specifies a hierarchy - it should be HandlePlatform for objects within the platform hierarchy, or HandleOwner for
// objects within the storage or endorsement hierarchies. If auth is HandlePlatform but object corresponds to an object outside
// of the platform hierarchy, or auth is HandleOwner but object corresponds to an object inside of the platform hierarchy, a
// *TPMHandleError error with an error code of ErrorHierarchy will be returned for handle index 2. The auth handle requires
// authorization with the user auth role, provided via authAuth.
//
// If object corresponds to a transient object that only has a public part loaded, or which has the AttrStClear attribute set,
// then a *TPMHandleError error with an error code of ErrorAttributes will be returned for handle index 2.
//
// If object corresponds to a persistent object and persistentHandle is not the handle for that object, a *TPMHandleError error
// with an error code of ErrorHandle will be returned for handle index 2.
//
// If object corresponds to a transient object and persistentHandle is not in the correct range determined by the value of
// auth, a *TPMParameterError error with an error code of ErrorRange will be returned.
//
// If there is insuffient space to persist a transient object, a *TPMError error with an error code of ErrorNVSpace will be returned.
// If a persistent object already exists at the specified handle, a *TPMError error with an error code of ErrorNVDefined will be
// returned.
//
// On successful completion of persisting a transient object, it returns a ResourceContext that corresponds to the persistent object.
// On successful completion of evicting a persistent object, it returns a nil ResourceContext, and object will be invalidated.
func (t *TPMContext) EvictControl(auth Handle, object ResourceContext, persistentHandle Handle, authAuth interface{}, sessions ...*Session) (ResourceContext, error) {
	if err := t.RunCommand(CommandEvictControl, sessions,
		HandleWithAuth{Handle: auth, Auth: authAuth}, object, Separator,
		persistentHandle); err != nil {
		return nil, err
	}

	if object.Handle() == persistentHandle {
		t.evictResourceContext(object)
		return nil, nil
	}

	public := &object.(*objectContext).public
	objectContext := &objectContext{handle: persistentHandle, name: object.Name()}
	public.copyTo(&objectContext.public)
	t.addResourceContext(objectContext)

	return objectContext, nil
}
