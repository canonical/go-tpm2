// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// HandleContext corresponds to an entity that resides on the TPM. Implementations of HandleContext maintain some host-side
// state in order to be able to participate in HMAC sessions and session-based parameter encryption. HandleContext instances are
// tracked by the TPMContext that created them (when the corresponding TPM entity is created or loaded), and are invalidated when
// the entity is flushed or evicted from the TPM. They may also be invalidated if the TPM indicates it has allocated an entity with
// the same handle as an existing HandleContext - these stale HandleContext instances may occur when working with sessions or
// persistent resources via a resource manager. Once invalidated, they can no longer be used.
type HandleContext interface {
	// Handle returns the handle of the corresponding entity on the TPM. If the HandleContext has been invalidated because the
	// corresponding entity has been flushed from the TPM or the TPM indicated that this HandleContext is stale by allocating
	// another entity with the same handle, this will return HandleUnassigned
	Handle() Handle
	Name() Name // The name of the entity
}

// SessionContext corresponds to a session that resides on the TPM.
type SessionContext interface {
	HandleContext
	NonceTPM() Nonce   // The most recent TPM nonce value
	IsAudit() bool     // Whether the session has been used for audit
	IsExclusive() bool // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes
}

type handleContextPrivate interface {
	invalidate()
}

type untrackedContext Handle

func (r untrackedContext) Handle() Handle {
	return Handle(r)
}

func (r untrackedContext) Name() Name {
	name := make(Name, binary.Size(r))
	binary.BigEndian.PutUint32(name, uint32(r))
	return name
}

type permanentContext struct {
	handle Handle
}

func (r *permanentContext) Handle() Handle {
	return r.handle
}

func (r *permanentContext) Name() Name {
	name := make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return name
}

func (r *permanentContext) invalidate() {
	r.handle = HandleUnassigned
}

type objectContext struct {
	handle Handle
	public Public
	name   Name
}

func (r *objectContext) Handle() Handle {
	return r.handle
}

func (r *objectContext) Name() Name {
	return r.name
}

func (r *objectContext) invalidate() {
	r.handle = HandleUnassigned
	r.public = Public{}
	r.name = make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(r.name, uint32(r.handle))
}

type nvIndexContext struct {
	handle Handle
	public NVPublic
	name   Name
}

func (r *nvIndexContext) Handle() Handle {
	return r.handle
}

func (r *nvIndexContext) Name() Name {
	return r.name
}

func (r *nvIndexContext) invalidate() {
	r.handle = HandleUnassigned
	r.public = NVPublic{}
	r.name = make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(r.name, uint32(r.handle))
}

func (r *nvIndexContext) setAttr(a NVAttributes) {
	r.public.Attrs |= a
	name, _ := r.public.Name()
	r.name = name
}

func (r *nvIndexContext) clearAttr(a NVAttributes) {
	r.public.Attrs &= ^a
	name, _ := r.public.Name()
	r.name = name
}

type sessionContext struct {
	handle         Handle
	usable         bool
	isAudit        bool
	isExclusive    bool
	hashAlg        HashAlgorithmId
	sessionType    SessionType
	policyHMACType policyHMACType
	isBound        bool
	boundEntity    Name
	sessionKey     []byte
	nonceCaller    Nonce
	nonceTPM       Nonce
	symmetric      *SymDef
}

func (r *sessionContext) Handle() Handle {
	return r.handle
}

func (r *sessionContext) Name() Name {
	name := make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return name
}

func (r *sessionContext) invalidate() {
	r.handle = HandleUnassigned
}

func (r *sessionContext) NonceTPM() Nonce {
	return r.nonceTPM
}

func (r *sessionContext) IsAudit() bool {
	return r.isAudit
}

func (r *sessionContext) IsExclusive() bool {
	return r.isExclusive
}

func makeIncompleteSessionContext(t *TPMContext, handle Handle) (HandleContext, error) {
	hr := handle & 0x00ffffff
	h, err := t.GetCapabilityHandles(hr|(Handle(HandleTypeLoadedSession)<<24), 1)
	if err != nil {
		return nil, err
	}
	if len(h) > 0 && h[0] == handle {
		return &sessionContext{handle: handle}, nil
	}
	h, err = t.GetCapabilityHandles(hr|(Handle(HandleTypeSavedSession)<<24), 1)
	if err != nil {
		return nil, err
	}
	if len(h) > 0 && h[0]&0x00ffffff == hr {
		return &sessionContext{handle: hr | (Handle(HandleTypeHMACSession) << 24)}, nil
	}
	return nil, nil
}

func makeNVIndexContext(t *TPMContext, handle Handle) (HandleContext, error) {
	pub, name, err := t.NVReadPublic(untrackedContext(handle))
	if err != nil {
		return nil, err
	}
	if n, err := pub.Name(); err != nil {
		return nil, &InvalidResponseError{CommandNVReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, &InvalidResponseError{CommandNVReadPublic, "name and public area don't match"}
	}
	return &nvIndexContext{handle: handle, public: *pub, name: name}, nil
}

func makeObjectContext(t *TPMContext, handle Handle) (HandleContext, error) {
	pub, name, _, err := t.ReadPublic(untrackedContext(handle))
	if err != nil {
		return nil, err
	}
	if n, err := pub.Name(); err != nil {
		return nil, &InvalidResponseError{CommandReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, &InvalidResponseError{CommandReadPublic, "name and public area don't match"}
	}
	return &objectContext{handle: handle, public: *pub, name: name}, nil
}

func normalizeHandleForMap(handle Handle) Handle {
	if handle.Type() != HandleTypePolicySession {
		return handle
	}
	return (handle & 0x00ffffff) | (Handle(HandleTypeHMACSession) << 24)
}

func (t *TPMContext) evictHandleContext(rc HandleContext) {
	if err := t.checkHandleContextParam(rc); err != nil {
		panic(fmt.Sprintf("Attempting to evict an invalid resource context: %v", err))
	}
	delete(t.resources, normalizeHandleForMap(rc.Handle()))
	rc.(handleContextPrivate).invalidate()
}

func (t *TPMContext) addHandleContext(rc HandleContext) {
	if rc.Handle() == HandleUnassigned {
		panic("Attempting to add a closed resource context")
	}
	handle := normalizeHandleForMap(rc.Handle())
	if existing, exists := t.resources[handle]; exists && existing != rc {
		t.evictHandleContext(existing)
	}
	t.resources[handle] = rc
}

func (t *TPMContext) checkHandleContextParam(rc HandleContext) error {
	if rc == nil {
		return errors.New("nil value")
	}
	if _, isUntracked := rc.(untrackedContext); isUntracked {
		return nil
	}
	if rc.Handle() == HandleUnassigned {
		return errors.New("resource has been closed")
	}
	erc, exists := t.resources[normalizeHandleForMap(rc.Handle())]
	if !exists || erc != rc {
		return errors.New("resource belongs to another TPM context")
	}
	return nil
}

// WrapHandle creates and returns a HandleContext for the specified handle. TPMContext will maintain a reference to the returned
// HandleContext until it is flushed or evicted from the TPM or if the TPM indicates that it has created a new resource with the same
// handle - these stale HandleContext instances may occur when working with sessions and persistent resources via a resource manager.
// If the TPMContext is already tracking an active HandleContext for the specified handle, it returns the existing HandleContext.
//
// If a new HandleContext has to be created and the handle references a NV index or an object, it will execute a command to read the
// public area from the TPM in order to initialize state that is maintained on the host side. It will return a ResourceUnavailableError
// error if the specified handle references a NV index or object that is currently unavailable. It should be noted that this command is
// executed without any sessions and therefore does not benefit from any integrity protections other than a consistency cross-check
// that is performed on the returned data to make sure that the name and public area match. Applications should consider the
// implications of this during subsequent use of the HandleContext.
//
// It always succeeds if the specified handle references a permanent resource.
func (t *TPMContext) WrapHandle(handle Handle) (HandleContext, error) {
	if rc, exists := t.resources[handle]; exists {
		return rc, nil
	}

	var rc HandleContext
	var err error

	switch handle.Type() {
	case HandleTypeNVIndex:
		rc, err = makeNVIndexContext(t, handle)
	case HandleTypeHMACSession, HandleTypePolicySession:
		rc, err = makeIncompleteSessionContext(t, handle)
		if rc == nil {
			return nil, ResourceUnavailableError{handle}
		}
	case HandleTypeTransient, HandleTypePersistent:
		rc, err = makeObjectContext(t, handle)
	default:
		panic("invalid handle type")
	}

	if err != nil {
		switch e := err.(type) {
		case *TPMWarning:
			if e.Code == WarningReferenceH0 {
				return nil, ResourceUnavailableError{handle}
			}
		case *TPMHandleError:
			if e.Code() == ErrorHandle {
				return nil, ResourceUnavailableError{handle}
			}
		}
		return nil, err
	}

	t.addHandleContext(rc)

	return rc, nil
}

// WrapSessionHandle creates and returns a SessionContext for the specified handle. TPMContext will maintain a reference to the
// returned SessionContext until it is flushed from the TPM or if the TPM indicates that it has created a new session with the same
// handle - these stale SessionContext instances may occur when working with sessions via a resource manager. If the TPMContext is
// already tracking an active SessionContext for the specified handle, it returns the existing SessionContext.
//
// If a new SessionContext has to be created, this command will execute some commands to determine if the session exists on the TPM,
// either as a saved or loaded session. If the session is saved then the returned SessionContext will return a Handle with a HandleType
// of HandleTypeHMACSession regardless of the HandleType of the supplied handle. Regardless of whether the session is saved or loaded,
// the returned SessionContext will not be complete and the session associated with it cannot be used in any command other than
// TPMContext.FlushContext. It will return a ResourceUnavailableError error if no session with the specified handle exists.
func (t *TPMContext) WrapSessionHandle(handle Handle) (SessionContext, error) {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		rc, err := t.WrapHandle(handle)
		if err != nil {
			return nil, err
		}
		return rc.(SessionContext), nil
	default:
		return nil, errors.New("invalid handle type")
	}
}

// GetOrCreatePermanentContext creates a new HandleContext for the specified permanent handle or PCR handle, or returns the existing
// one if the TPMContext already has a reference to one.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
func (t *TPMContext) GetOrCreatePermanentContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
	default:
		panic("invalid handle type")
	}

	if rc, exists := t.resources[handle]; exists {
		return rc
	}

	rc := &permanentContext{handle}
	t.addHandleContext(rc)
	return rc
}

// OwnerHandleContext returns the HandleContext corresponding to the owner hiearchy.
func (t *TPMContext) OwnerHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandleOwner)
}

// NulHandleContext returns the HandleContext corresponding to the null hiearchy.
func (t *TPMContext) NullHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandleNull)
}

// LockoutHandleContext returns the HandleContext corresponding to the lockout hiearchy.
func (t *TPMContext) LockoutHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandleLockout)
}

// EndorsementHandleContext returns the HandleContext corresponding to the endorsement hiearchy.
func (t *TPMContext) EndorsementHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandleEndorsement)
}

// PlatformHandleContext returns the HandleContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandlePlatform)
}

// PlatformNVHandleContext returns the HandleContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformNVHandleContext() HandleContext {
	return t.GetOrCreatePermanentContext(HandlePlatformNV)
}

// PCRHandleContext returns the HandleContext corresponding to the PCR at the specified index. It will panic if pcr is not a valid
// PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) HandleContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetOrCreatePermanentContext(h)
}

// ForgetResource tells the TPMContext to drop its reference to the specified HandleContext without flushing the corresponding
// resources from the TPM.
//
// An error will be returned if the specified context has been invalidated, or if it is being tracked by another TPMContext instance.
//
// On succesful completion, the specified HandleContext will be invalidated and can no longer be used. APIs that return a
// HandleContext for the corresponding TPM resource in the future will return a newly created HandleContext.
func (t *TPMContext) ForgetResource(context HandleContext) error {
	if err := t.checkHandleContextParam(context); err != nil {
		return makeInvalidParamError("context", fmt.Sprintf("%v", err))
	}

	t.evictHandleContext(context)
	return nil
}
