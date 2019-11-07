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

// ResourceContext corresponds to a resource that resides on the TPM. Implementations of ResourceContext maintain some host-side
// state in order to be able to participate in HMAC sessions and session-based parameter encryption. ResourceContext instances are
// tracked by the TPMContext that created them (when the corresponding TPM resource is created or loaded), and are invalidated when
// the resource is flushed from the TPM. They may also be invalidated if the TPM indicates it has allocated a resource with the
// same handle as an existing ResourceContext - these stale ResourceContext instances may occur when working with sessions or
// persistent resources via a resource manager. Once invalidated, they can no longer be used.
type ResourceContext interface {
	// Handle returns the handle of the resource on the TPM. If the resource has been invalidated because it has been flushed from
	// the TPM or the TPM indicated that this resource context is stale by allocating another resource with the same handle, this will
	// return HandleUnassigned
	Handle() Handle
	Name() Name // The name of the resource
}

type SessionContext interface {
	NonceTPM() Nonce
}

type resourceContextPrivate interface {
	invalidate()
}

type permanentContext Handle

func (r permanentContext) Handle() Handle {
	return Handle(r)
}

func (r permanentContext) Name() Name {
	name := make(Name, binary.Size(r))
	binary.BigEndian.PutUint32(name, uint32(r))
	return name
}

func (r permanentContext) invalidate() {
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

type sessionContextFlags int

const (
	sessionContextFull sessionContextFlags = 1 << iota
	sessionContextLoaded
)

type sessionContext struct {
	handle         Handle
	usable         bool
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

func makeIncompleteSessionContext(t *TPMContext, handle Handle) (ResourceContext, error) {
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
	pub, name, err := t.NVReadPublic(permanentContext(handle))
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
	pub, name, _, err := t.ReadPublic(permanentContext(handle))
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

func (t *TPMContext) evictResourceContext(rc ResourceContext) {
	if _, isPermanent := rc.(permanentContext); isPermanent {
		return
	}
	if err := t.checkResourceContextParam(rc); err != nil {
		panic(fmt.Sprintf("Attempting to evict an invalid resource context: %v", err))
	}
	delete(t.resources, normalizeHandleForMap(rc.Handle()))
	rc.(resourceContextPrivate).invalidate()
}

func (t *TPMContext) addResourceContext(rc ResourceContext) {
	if _, isPermanent := rc.(permanentContext); isPermanent {
		return
	}
	if rc.Handle() == HandleUnassigned {
		panic("Attempting to add a closed resource context")
	}
	handle := normalizeHandleForMap(rc.Handle())
	if existing, exists := t.resources[handle]; exists && existing != rc {
		t.evictResourceContext(existing)
	}
	t.resources[handle] = rc
}

func (t *TPMContext) checkResourceContextParam(rc ResourceContext) error {
	if rc == nil {
		return errors.New("nil value")
	}
	if _, isPermanent := rc.(permanentContext); isPermanent {
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

// WrapHandle creates and returns a ResourceContext for the specified handle. TPMContext will maintain a reference to the returned
// ResourceContext until it is flushed from the TPM or if the TPM indicates that it has created a new resource with the same handle -
// these stale ResourceContext instances may occur when working with sessions and persistent resources via a resource manager. If the
// TPMContext is already tracking an active ResourceContext for the specified handle, it returns the existing ResourceContext.
//
// If the handle references a NV index or an object, it will execute a command to read the public area from the TPM in order to
// initialize state that is maintained on the host side. It will return a ResourceUnavailableError error if the specified handle
// references a NV index or object that is currently unavailable. It should be noted that this command is executed without any
// sessions and therefore does not benefit from any integrity protections other than a consistency cross-check that is performed on
// the returned data to make sure that the name and public area match. Applications should consider the implications of this during
// subsequent use of the ResourceContext.
//
// If the handle references a session, it will execute some commands to determine if the session exists on the TPM, either as a
// saved or loaded session. If the session is saved then the returned ResourceContext will return a Handle with a HandleType of
// HandleTypeHMACSession regardless of the HandleType of the supplied handle. Regardless of whether the session is saved or loaded,
// the returned ResourceContext will not be complete and the session associated with it cannot be used in any command other than
// TPMContext.FlushContext. It will return a ResourceUnavailableError error if no session with the specified handle exists.
//
// It will return an error if handle references a PCR index or a session.
//
// It always succeeds if the specified handle references a permanent resource.
func (t *TPMContext) WrapHandle(handle Handle) (ResourceContext, error) {
	if rc, exists := t.resources[handle]; exists {
		return rc, nil
	}

	var rc ResourceContext
	var err error

	switch handle.Type() {
	case HandleTypePCR:
		err = errors.New("cannot wrap a PCR handle")
	case HandleTypeNVIndex:
		rc, err = makeNVIndexContext(t, handle)
	case HandleTypeHMACSession, HandleTypePolicySession:
		rc, err = makeIncompleteSessionContext(t, handle)
		if rc == nil {
			return nil, ResourceUnavailableError{handle}
		}
	case HandleTypePermanent:
		rc = permanentContext(handle)
	case HandleTypeTransient, HandleTypePersistent:
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

	t.addResourceContext(rc)

	return rc, nil
}

// ForgetResource tells the TPMContext to drop its reference to the specified ResourceContext without flushing the corresponding
// resources from the TPM.
//
// An error will be returned if the specified context has been invalidated, or if it is being tracked by another TPMContext instance.
//
// On succesful completion, the specified ResourceContext will be invalidated and can no longer be used. APIs that return a
// ResourceContext for the corresponding TPM resource in the future will return a newly created ResourceContext.
func (t *TPMContext) ForgetResource(context ResourceContext) error {
	if err := t.checkResourceContextParam(context); err != nil {
		return err
	}

	switch context.Handle().Type() {
	case HandleTypePCR:
		panic("Got context for a PCR index, which shouldn't happen")
	case HandleTypePermanent:
		// Permanent resources aren't tracked by TPMContext, and permanentContext is just a typedef of
		// Handle anyway. Just do nothing in this case
		return nil
	}

	t.evictResourceContext(context)

	return nil
}
