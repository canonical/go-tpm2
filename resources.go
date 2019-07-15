package tpm2

import (
	"fmt"
)

type Resource interface {
	Handle() Handle
}

type resourcePrivate interface {
	Tpm() *tpmImpl
	SetTpm(t *tpmImpl)
}

type permanentResource struct {
	tpm    *tpmImpl
	handle Handle
}

func (r *permanentResource) Handle() Handle {
	return r.handle
}

func (r *permanentResource) Tpm() *tpmImpl {
	return r.tpm
}

func (r *permanentResource) SetTpm(t *tpmImpl) {
	r.tpm = t
}

type objectResource struct {
	tpm    *tpmImpl
	handle Handle
	public Public
	name   Name
}

func (r *objectResource) Handle() Handle {
	return r.handle
}

func (r *objectResource) Tpm() *tpmImpl {
	return r.tpm
}

func (r *objectResource) SetTpm(t *tpmImpl) {
	r.tpm = t
}

type nvIndexResource struct {
	tpm    *tpmImpl
	handle Handle
	name   Name
}

func (r *nvIndexResource) Handle() Handle {
	return r.handle
}

func (r *nvIndexResource) Tpm() *tpmImpl {
	return r.tpm
}

func (r *nvIndexResource) SetTpm(t *tpmImpl) {
	r.tpm = t
}

func makeNVIndexResource(t *tpmImpl, handle Handle) (Resource, error) {
	_, name, err := t.nvReadPublic(handle)
	if err != nil {
		return nil, err
	}
	return &nvIndexResource{handle: handle, name: name}, nil
}

func makeObjectResource(t *tpmImpl, handle Handle) (Resource, error) {
	pub, name, _, err := t.readPublic(handle)
	if err != nil {
		return nil, err
	}
	return &objectResource{handle: handle, public: *pub, name: name}, nil
}

func (t *tpmImpl) evictResource(resource Resource) {
	rp := resource.(resourcePrivate)
	if rp.Tpm() == nil {
		return
	}
	if rp.Tpm() != t {
		panic("Attempting to evict a resource for another TPM instance")
	}
	rp.SetTpm(nil)
	delete(t.resources, resource.Handle())
}

func (t *tpmImpl) addResource(resource Resource) {
	rp := resource.(resourcePrivate)
	if rp.Tpm() != nil {
		panic("Attempting to add a resource to more than one TPM instance")
	}
	if _, exists := t.resources[resource.Handle()]; exists {
		panic("Resource object for handle already exists")
	}
	rp.SetTpm(t)
	t.resources[resource.Handle()] = resource

}

func (t *tpmImpl) checkResourceParam(resource Resource) error {
	rp := resource.(resourcePrivate)
	if rp.Tpm() == nil {
		return InvalidResourceParamError{fmt.Sprintf("resource has been closed")}
	}
	if resource.(resourcePrivate).Tpm() != t {
		return InvalidResourceParamError{fmt.Sprintf("resource belongs to another TPM instance")}
	}
	return nil
}

func (t *tpmImpl) WrapHandle(handle Handle) (Resource, error) {
	if resource, exists := t.resources[handle]; exists {
		return resource, nil
	}

	var resource Resource
	var err error

	switch (handle & 0xff000000) >> 24 {
	case 0x00:
		// PCR
	case 0x01:
		resource, err = makeNVIndexResource(t, handle)
	case 0x02:
		// HMAC session
	case 0x03:
		// Policy session
	case 0x40:
		resource = &permanentResource{handle: handle}
	case 0x80, 0x81:
		resource, err = makeObjectResource(t, handle)
	}

	if err != nil {
		return nil, err
	}

	t.addResource(resource)

	return resource, nil
}
