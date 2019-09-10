// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ResourceContext corresponds to a resource that resides on the TPM. Implementations of ResourceContext maintain
// some host-side state in order to be able to participate in HMAC sessions and session-based parameter encryption.
// ResourceContext instances are tracked by the TPMContext that created them (when the corresponding TPM resouce
// is created or loaded), and are invalidated when the resource is flushed from the TPM. Once invalidated, they
// can no longer be used.
type ResourceContext interface {
	// Handle returns the handle of the resource on the TPM. If the resource has been flushed from the TPM,
	// this will return HandleNull
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
	name := make([]byte, 4)
	binary.BigEndian.PutUint32(name, uint32(r))
	return Name(name)
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
	r.handle = HandleNull
	r.public = Public{}
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
	r.handle = HandleNull
	r.public = NVPublic{}
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
	hashAlg        AlgorithmId
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
	name := make([]byte, 4)
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return Name(name)
}

func (r *sessionContext) invalidate() {
	r.handle = HandleNull
}

func (r *sessionContext) NonceTPM() Nonce {
	return r.nonceTPM
}

func makeNVIndexContext(t *TPMContext, handle Handle) (ResourceContext, error) {
	pub, name, err := t.nvReadPublic(handle)
	if err != nil {
		return nil, err
	}
	return &nvIndexContext{handle: handle, public: *pub, name: name}, nil
}

func makeObjectContext(t *TPMContext, handle Handle) (ResourceContext, error) {
	pub, name, _, err := t.readPublic(handle)
	if err != nil {
		return nil, err
	}
	return &objectContext{handle: handle, public: *pub, name: name}, nil
}

func (t *TPMContext) evictResourceContext(rc ResourceContext) {
	if _, isPermanent := rc.(permanentContext); isPermanent {
		panic("Attempting to evict a permanent resource context")
	}
	if err := t.checkResourceContextParam(rc); err != nil {
		panic(fmt.Sprintf("Attempting to evict an invalid resource context: %v", err))
	}
	delete(t.resources, rc.Handle())
	rc.(resourceContextPrivate).invalidate()
}

func (t *TPMContext) addResourceContext(rc ResourceContext) {
	if _, isPermanent := rc.(permanentContext); isPermanent {
		return
	}
	if rc.Handle() == HandleNull {
		panic("Attempting to add a closed resource context")
	}
	if _, exists := t.resources[rc.Handle()]; exists {
		panic(fmt.Sprintf("Resource object for handle 0x%08x already exists", rc.Handle()))
	}
	t.resources[rc.Handle()] = rc
}

func (t *TPMContext) checkResourceContextParam(rc ResourceContext) error {
	if rc == nil {
		return errors.New("nil value")
	}
	if _, isPermanent := rc.(permanentContext); isPermanent {
		return nil
	}
	if rc.Handle() == HandleNull {
		return errors.New("resource has been closed")
	}
	erc, exists := t.resources[rc.Handle()]
	if !exists || erc != rc {
		return errors.New("resource belongs to another TPM context")
	}
	return nil
}

// WrapHandle creates and returns a ResourceContext for the specified handle. TPMContext will maintain a reference
// to the returned ResourceContext until it is flushed from the TPM. If the TPMContext is already tracking a
// ResourceContext for the specified handle, it returns the existing ResourceContext.
//
// If the handle references a NV index or an object, it will execute some TPM commands to initialize state that is
// maintained on the host side. An error will be returned if this fails. It will return an error if the specified
// handle references a NV index or object that does not currently reside on the TPM.
//
// It will return an error if handle references a PCR index or a session. It is not possible to create a
// ResourceContext for a session that is not started by TPMContext.StartAuthSession.
//
// It always succeeds if the specified handle references a permanent resource.
func (t *TPMContext) WrapHandle(handle Handle) (ResourceContext, error) {
	if rc, exists := t.resources[handle]; exists {
		return rc, nil
	}

	var rc ResourceContext
	var err error

	switch (handle & 0xff000000) >> 24 {
	case 0x00:
		err = errors.New("cannot wrap a PCR handle")
	case 0x01:
		rc, err = makeNVIndexContext(t, handle)
	case 0x02, 0x03:
		err = errors.New("cannot wrap the handle of an existing session")
	case 0x40:
		rc = permanentContext(handle)
	case 0x80, 0x81:
		rc, err = makeObjectContext(t, handle)
	}

	if err != nil {
		return nil, err
	}

	t.addResourceContext(rc)

	return rc, nil
}
