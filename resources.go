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

type handleContextPrivate interface {
	invalidate()
	getAuthValue() []byte
}

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext
	NonceTPM() Nonce   // The most recent TPM nonce value
	IsAudit() bool     // Whether the session has been used for audit
	IsExclusive() bool // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes
}

// ResourceContext is a HandleContext that corresponds to a non-session entity on the TPM.
type ResourceContext interface {
	HandleContext
	SetAuthValue([]byte) // Set the authorization value that will be used when authorization is required for this resource
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
	handle    Handle
	authValue []byte
}

func (r *permanentContext) Handle() Handle {
	return r.handle
}

func (r *permanentContext) Name() Name {
	name := make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return name
}

func (r *permanentContext) SetAuthValue(value []byte) {
	r.authValue = value
}

func (r *permanentContext) invalidate() {
	r.handle = HandleUnassigned
}

func (r *permanentContext) getAuthValue() []byte {
	return r.authValue
}

type objectContext struct {
	handle    Handle
	public    Public
	name      Name
	authValue []byte
}

func (r *objectContext) Handle() Handle {
	return r.handle
}

func (r *objectContext) Name() Name {
	return r.name
}

func (r *objectContext) SetAuthValue(value []byte) {
	r.authValue = value
}

func (r *objectContext) invalidate() {
	r.handle = HandleUnassigned
	r.public = Public{}
	r.name = make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(r.name, uint32(r.handle))
}

func (r *objectContext) getAuthValue() []byte {
	return r.authValue
}

type nvIndexContext struct {
	handle    Handle
	public    NVPublic
	name      Name
	authValue []byte
}

func (r *nvIndexContext) Handle() Handle {
	return r.handle
}

func (r *nvIndexContext) Name() Name {
	return r.name
}

func (r *nvIndexContext) SetAuthValue(value []byte) {
	r.authValue = value
}

func (r *nvIndexContext) invalidate() {
	r.handle = HandleUnassigned
	r.public = NVPublic{}
	r.name = make(Name, binary.Size(r.handle))
	binary.BigEndian.PutUint32(r.name, uint32(r.handle))
}

func (r *nvIndexContext) getAuthValue() []byte {
	return r.authValue
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

func (r *sessionContext) getAuthValue() []byte {
	panic("not implemented for session contexts")
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

func makeIncompleteSessionContext(t *TPMContext, handle Handle) (SessionContext, error) {
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

func makeNVIndexContext(t *TPMContext, handle Handle) (ResourceContext, error) {
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

func makeObjectContext(t *TPMContext, handle Handle) (ResourceContext, error) {
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

// GetOrCreateResourceContext creates and returns a new ResourceContext for the specified handle, or returns the existing one if the
// TPMContext already has a reference to one. TPMContext will maintain a reference to the returned SessionContext until it is flushed
// or evicted from the TPM or if the TPM indicates that it has created a new resource with the same handle - these stale
// ResourceContext instances may occur when working with persistent resources via a resource manager.
//
// If a new ResourceContext has to be created and the handle references a NV index or an object, it will execute a command to read the
// public area from the TPM in order to initialize state that is maintained on the host side. It will return a ResourceUnavailableError
// error if the specified handle references a NV index or object that is currently unavailable. It should be noted that this command is
// executed without any sessions and therefore does not benefit from any integrity protections other than a consistency cross-check
// that is performed on the returned data to make sure that the name and public area match. Applications should consider the
// implications of this during subsequent use of the ResourceContext.
//
// It always succeeds if the specified handle references a permanent resource.
//
// This function will panic if handle doesn't correspond to a PCR handle, permanent handle, NV index, transient object or persistent
// object.
func (t *TPMContext) GetOrCreateResourceContext(handle Handle) (ResourceContext, error) {
	switch handle.Type() {
	case HandleTypePCR, HandleTypePermanent:
		return t.GetOrCreatePermanentContext(handle), nil
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(ResourceContext), nil
		}

		var rc ResourceContext
		var err error
		if handle.Type() == HandleTypeNVIndex {
			rc, err = makeNVIndexContext(t, handle)
		} else {
			rc, err = makeObjectContext(t, handle)
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
	default:
		panic("invalid handle type")
	}
}

// GetOrCreateSessionContext creates and returns a new SessionContext for the specified handle, or returns the existing one if the
// TPMContext already has a reference to one. TPMContext will maintain a reference to the returned SessionContext until it is flushed
// from the TPM or if the TPM indicates that it has created a new session with the same handle - these stale SessionContext instances
// may occur when working with sessions via a resource manager.
//
// If a new SessionContext has to be created, this command will execute some commands to determine if the session exists on the TPM,
// either as a saved or loaded session. If the session is saved then the returned SessionContext will return a Handle with a HandleType
// of HandleTypeHMACSession regardless of the HandleType of the supplied handle. Regardless of whether the session is saved or loaded,
// the returned SessionContext will not be complete and the session associated with it cannot be used in any command other than
// TPMContext.FlushContext. It will return a ResourceUnavailableError error if no session with the specified handle exists.
//
// This function will panic if handle doesn't correspond to a session.
func (t *TPMContext) GetOrCreateSessionContext(handle Handle) (SessionContext, error) {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(SessionContext), nil
		}
		rc, err := makeIncompleteSessionContext(t, handle)
		if err != nil {
			return nil, err
		}
		if rc == nil {
			return nil, ResourceUnavailableError{handle}
		}
		t.addHandleContext(rc)
		return rc, nil
	default:
		panic("invalid handle type")
	}
}

// GetOrCreatePermanentContext creates and returns a new ResourceContext for the specified permanent handle or PCR handle, or returns
// the existing one if the TPMContext already has a reference to one.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
func (t *TPMContext) GetOrCreatePermanentContext(handle Handle) ResourceContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(ResourceContext)
		}

		rc := &permanentContext{handle: handle}
		t.addHandleContext(rc)
		return rc
	default:
		panic("invalid handle type")
	}
}

// OwnerHandleContext returns the ResouceContext corresponding to the owner hiearchy.
func (t *TPMContext) OwnerHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleOwner)
}

// NulHandleContext returns the ResourceContext corresponding to the null hiearchy.
func (t *TPMContext) NullHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleNull)
}

// LockoutHandleContext returns the ResourceContext corresponding to the lockout hiearchy.
func (t *TPMContext) LockoutHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleLockout)
}

// EndorsementHandleContext returns the ResourceContext corresponding to the endorsement hiearchy.
func (t *TPMContext) EndorsementHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleEndorsement)
}

// PlatformHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandlePlatform)
}

// PlatformNVHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformNVHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandlePlatformNV)
}

// PCRHandleContext returns the ResourceContext corresponding to the PCR at the specified index. It will panic if pcr is not a valid
// PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) ResourceContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetOrCreatePermanentContext(h)
}

// ForgetHandleContext tells the TPMContext to drop its reference to the specified HandleContext without flushing the corresponding
// resources from the TPM.
//
// An error will be returned if the specified context has been invalidated, or if it is being tracked by another TPMContext instance.
//
// On succesful completion, the specified HandleContext will be invalidated and can no longer be used. APIs that return a
// HandleContext for the corresponding TPM resource in the future will return a newly created HandleContext.
func (t *TPMContext) ForgetHandleContext(context HandleContext) error {
	if err := t.checkHandleContextParam(context); err != nil {
		return makeInvalidParamError("context", fmt.Sprintf("%v", err))
	}

	t.evictHandleContext(context)
	return nil
}
