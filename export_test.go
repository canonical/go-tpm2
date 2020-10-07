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

type ObjectContext = objectContext

func (r *ObjectContext) GetPublic() *Public {
	return r.d.Data.Object
}

type NvIndexContext = nvIndexContext

func (r *NvIndexContext) GetPublic() *NVPublic {
	return r.d.Data.NV
}

type TestSessionContext = sessionContext

func (r *TestSessionContext) GetAttrs() SessionAttributes {
	return r.attrs
}

func (r *TestSessionContext) GetScData() *sessionContextData {
	return r.d.Data.Session
}

var TestComputeBindName = computeBindName
