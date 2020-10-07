// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (r *permanentContext) GetAuthValue() []byte {
	return r.auth
}

type TestResourceContext interface {
	GetAuthValue() []byte
}

func (r *objectContext) GetPublic() *Public {
	return r.d.Data.Object
}

type TestObjectResourceContext interface {
	GetPublic() *Public
}

func (r *nvIndexContext) GetPublic() *NVPublic {
	return r.d.Data.NV
}

type TestNVIndexResourceContext interface {
	GetPublic() *NVPublic
}

func (r *sessionContext) GetAttrs() SessionAttributes {
	return r.attrs
}

func (r *sessionContext) GetScData() *sessionContextData {
	return r.d.Data.Session
}

type TestSessionContext interface {
	GetAttrs() SessionAttributes
	GetScData() *sessionContextData
}

var TestComputeBindName = computeBindName
