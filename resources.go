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

type ResourceContext interface {
	Handle() Handle
	Name() Name
}

type SessionContext interface {
	NonceTPM() Nonce
}

type resourceContextPrivate interface {
	tpmContext() *tpmContext
	setTpmContext(t *tpmContext)
	invalidate()
}

type permanentContext struct {
	tpm    *tpmContext
	handle Handle
}

func (r *permanentContext) Handle() Handle {
	return r.handle
}

func (r *permanentContext) Name() Name {
	name := make([]byte, 4)
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return Name(name)
}

func (r *permanentContext) tpmContext() *tpmContext {
	return r.tpm
}

func (r *permanentContext) setTpmContext(t *tpmContext) {
	r.tpm = t
}

func (r *permanentContext) invalidate() {
	r.tpm = nil
	r.handle = HandleNull
}

type objectContext struct {
	tpm    *tpmContext
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

func (r *objectContext) tpmContext() *tpmContext {
	return r.tpm
}

func (r *objectContext) setTpmContext(t *tpmContext) {
	r.tpm = t
}

func (r *objectContext) invalidate() {
	r.tpm = nil
	r.handle = HandleNull
}

type nvIndexContext struct {
	tpm    *tpmContext
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

func (r *nvIndexContext) tpmContext() *tpmContext {
	return r.tpm
}

func (r *nvIndexContext) setTpmContext(t *tpmContext) {
	r.tpm = t
}

func (r *nvIndexContext) invalidate() {
	r.tpm = nil
	r.handle = HandleNull
}

type sessionContext struct {
	tpm         *tpmContext
	handle      Handle
	hashAlg     AlgorithmId
	sessionType SessionType
	policyHMACType
	boundResource Name
	sessionKey    []byte
	nonceCaller   Nonce
	nonceTPM      Nonce
	symmetric     *SymDef
}

func (r *sessionContext) Handle() Handle {
	return r.handle
}

func (r *sessionContext) Name() Name {
	name := make([]byte, 4)
	binary.BigEndian.PutUint32(name, uint32(r.handle))
	return Name(name)
}

func (r *sessionContext) tpmContext() *tpmContext {
	return r.tpm
}

func (r *sessionContext) setTpmContext(t *tpmContext) {
	r.tpm = t
}

func (r *sessionContext) invalidate() {
	r.tpm = nil
	r.handle = HandleNull
}

func (r *sessionContext) isBoundTo(context ResourceContext) bool {
	if context == nil {
		return false
	}
	return bytes.Equal(context.Name(), r.boundResource)
}

func (r *sessionContext) NonceTPM() Nonce {
	return r.nonceTPM
}

func makeNVIndexContext(t *tpmContext, handle Handle) (ResourceContext, error) {
	pub, name, err := t.nvReadPublic(handle)
	if err != nil {
		return nil, err
	}
	return &nvIndexContext{handle: handle, public: *pub, name: name}, nil
}

func makeObjectContext(t *tpmContext, handle Handle) (ResourceContext, error) {
	pub, name, _, err := t.readPublic(handle)
	if err != nil {
		return nil, err
	}
	return &objectContext{handle: handle, public: *pub, name: name}, nil
}

func (t *tpmContext) evictResourceContext(rc ResourceContext) {
	rcp := rc.(resourceContextPrivate)
	if rcp.tpmContext() == nil {
		return
	}
	if rcp.tpmContext() != t {
		panic("Attempting to evict a resource for another TPM instance")
	}
	delete(t.resources, rc.Handle())
	rcp.invalidate()
}

func (t *tpmContext) addResourceContext(rc ResourceContext) {
	rcp := rc.(resourceContextPrivate)
	if rcp.tpmContext() != nil {
		panic("Attempting to add a resource to more than one TPM instance")
	}
	if _, exists := t.resources[rc.Handle()]; exists {
		panic("Resource object for handle already exists")
	}
	rcp.setTpmContext(t)
	t.resources[rc.Handle()] = rc

}

func (t *tpmContext) checkResourceContextParam(rc ResourceContext, name string) error {
	if rc == nil {
		return fmt.Errorf("invalid resource context for %s: nil", name)
	}
	rcp := rc.(resourceContextPrivate)
	if rcp.tpmContext() == nil {
		return fmt.Errorf("invalid resource context for %s: resource has been closed", name)
	}
	if rcp.tpmContext() != t {
		return fmt.Errorf("invalid resource context for %s: resource belongs to another tpm2.TPM "+
			"instance", name)
	}
	return nil
}

func (t *tpmContext) WrapHandle(handle Handle) (ResourceContext, error) {
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
		rc = &permanentContext{handle: handle}
	case 0x80, 0x81:
		rc, err = makeObjectContext(t, handle)
	}

	if err != nil {
		return nil, err
	}

	t.addResourceContext(rc)

	return rc, nil
}
