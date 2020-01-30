// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

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

type TestSessionContextData struct {
	*sessionContextData
}

func (r *sessionContext) GetScData() TestSessionContextData {
	return TestSessionContextData{r.d.Data.Data.(*sessionContextData)}
}

type TestSessionContext interface {
	GetScData() TestSessionContextData
}

func (l PCRSelectionList) TestSubtract(r PCRSelectionList) (PCRSelectionList, error) {
	return l.subtract(r)
}

var TestComputeBindName = computeBindName
var TestCryptEncryptSymmetricAES = cryptEncryptSymmetricAES
var TestCryptDecryptSymmetricAES = cryptDecryptSymmetricAES
var TestCryptXORObfuscation = cryptXORObfuscation
