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
	return r.d.Data.Data.(*Public)
}

type TestObjectResourceContext interface {
	GetPublic() *Public
}

func (r *nvIndexContext) GetPublic() *NVPublic {
	return r.d.Data.Data.(*NVPublic)
}

type TestNVIndexResourceContext interface {
	GetPublic() *NVPublic
}

func (r *sessionContext) GetAttrs() SessionAttributes {
	return r.attrs
}

func (r *sessionContext) GetScData() *sessionContextData {
	return r.d.Data.Data.(*sessionContextData)
}

type TestSessionContext interface {
	GetAttrs() SessionAttributes
	GetScData() *sessionContextData
}

func (l PCRSelectionList) TestSubtract(r PCRSelectionList) (PCRSelectionList, error) {
	return l.subtract(r)
}

var TestComputeBindName = computeBindName
