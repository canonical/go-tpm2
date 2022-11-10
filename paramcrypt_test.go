// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
)

type paramcryptSuite struct{}

var _ = Suite(&paramcryptSuite{})

type testSessionParamComputeSessionValueData struct {
	sessionKey       []byte
	resource         ResourceContext
	includeAuthValue bool
	expected         []byte
}

func (s *paramcryptSuite) testSessionParamComputeSessionValue(c *C, data *testSessionParamComputeSessionValueData) {
	session := &mockSessionContext{data: &SessionContextData{SessionKey: data.sessionKey}}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, nil, nil)
	c.Check(p.ComputeSessionValue(), DeepEquals, data.expected)
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueNoIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		sessionKey:       []byte("foo"),
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: false,
		expected:         []byte("foobar")})
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		sessionKey:       []byte("foo"),
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		expected:         []byte("foobar")})
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueNoSessionKeyNoIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: false,
		expected:         []byte("bar")})
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueNoSessionKeyIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		expected:         []byte("bar")})
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueIncludeEmptyAuthValue(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		sessionKey:       []byte("foo"),
		resource:         new(mockResourceContext),
		includeAuthValue: true,
		expected:         []byte("foo")})
}

func (s *paramcryptSuite) TestSessionParamComputeSessionValueNoResource(c *C) {
	s.testSessionParamComputeSessionValue(c, &testSessionParamComputeSessionValueData{
		sessionKey:       []byte("foo"),
		includeAuthValue: false,
		expected:         []byte("foo")})
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceNoEncrypt(c *C) {
	sessions := []*mockSessionContext{new(mockSessionContext)}
	resources := []*mockResourceContext{new(mockResourceContext)}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], resources[0], false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, -1, -1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, HasLen, 0)
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceWithEncrypt(c *C) {
	sessions := []*mockSessionContext{&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("foo")}}}
	resources := []*mockResourceContext{new(mockResourceContext)}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], resources[0], false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, 0, -1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, HasLen, 0)
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceWithExtraEncrypt(c *C) {
	sessions := []*mockSessionContext{
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("foo")}},
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("bar")}}}
	resources := []*mockResourceContext{new(mockResourceContext)}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], resources[0], false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, 1, -1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, DeepEquals, Nonce("bar"))
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceWithExtraEncryptNoAuth(c *C) {
	sessions := []*mockSessionContext{
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("foo")}},
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("bar")}}}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], nil, false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, 1, -1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, HasLen, 0)
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceWithEncryptAndDecrypt(c *C) {
	sessions := []*mockSessionContext{
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("foo")}},
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("xxx")}},
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("bar")}}}
	resources := []*mockResourceContext{new(mockResourceContext)}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], resources[0], false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil),
		newMockSessionParam(sessions[2], nil, false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, 2, 1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, DeepEquals, Nonce("bar"))
}

func (s *paramcryptSuite) TestSessionParamsComputeEncryptNonceWithEncryptAndDecryptSameSession(c *C) {
	sessions := []*mockSessionContext{
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("foo")}},
		&mockSessionContext{data: &SessionContextData{NonceTPM: []byte("bar")}}}
	resources := []*mockResourceContext{new(mockResourceContext)}
	params := []*SessionParam{
		newMockSessionParam(sessions[0], resources[0], false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil)}

	newMockSessionParams(CommandUnseal, params, 1, 1).ComputeEncryptNonce()
	c.Check(params[0].EncryptNonce, HasLen, 0)
}

type testEncryptCommandParameterData struct {
	sessions            []SessionContext
	resources           []ResourceContext
	decryptSessionIndex int

	cpBytes  []byte
	expected []byte
}

func (s *paramcryptSuite) testEncryptCommandParameter(c *C, data *testEncryptCommandParameterData) {
	var sessions []*SessionParam
	for i, s := range data.sessions {
		var r ResourceContext
		if i < len(data.resources) {
			r = data.resources[i]
		}
		sessions = append(sessions, newMockSessionParam(s, r, false, nil, nil))
	}

	params := newMockSessionParams(CommandUnseal, sessions, -1, data.decryptSessionIndex)

	cpBytes := make([]byte, len(data.cpBytes))
	copy(cpBytes, data.cpBytes)

	c.Check(params.EncryptCommandParameter(cpBytes), IsNil)
	c.Check(cpBytes, DeepEquals, data.expected)

	//recovered := make([]byte, len(cpBytes))
	//copy(recovered, cpBytes)
	//
	//if data.decryptSessionIndex >= 0 {
	//	sessionData := data.sessions[data.decryptSessionIndex].(SessionContextInternal).Data()
	//	param := sessions[data.decryptSessionIndex]
	//
	//		n := int(binary.BigEndian.Uint16(recovered))
	//
	//	switch sessionData.Symmetric.Algorithm {
	//	case SymAlgorithmAES:
	//		k := crypto.KDFa(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), []byte(CFBKey), sessionData.NonceCaller, sessionData.NonceTPM, int(sessionData.Symmetric.KeyBits.Sym)+(aes.BlockSize*8))
	//		offset := (sessionData.Symmetric.KeyBits.Sym + 7) / 8
	//		symKey := k[0:offset]
	//		iv := k[offset:]
	//		c.Check(crypto.SymmetricDecrypt(sessionData.Symmetric.Algorithm, symKey, iv, recovered[2:n+2]), IsNil)
	//	case SymAlgorithmXOR:
	//		crypto.XORObfuscation(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), sessionData.NonceCaller, sessionData.NonceTPM, recovered[2:n+2])
	//	}
	//}
	//
	//c.Check(recovered, DeepEquals, data.cpBytes)
	//c.Logf("%x", recovered)

	var expectedDecryptNonce Nonce
	if data.decryptSessionIndex > 0 && sessions[0].IsAuth() {
		expectedDecryptNonce = data.sessions[data.decryptSessionIndex].(SessionContextInternal).Data().NonceTPM
	}
	c.Check(sessions[0].DecryptNonce, DeepEquals, expectedDecryptNonce)
}

func (s *paramcryptSuite) TestEncryptCommandParameterNone(c *C) {
	s.testEncryptCommandParameter(c, &testEncryptCommandParameterData{
		sessions:            []SessionContext{new(mockSessionContext)},
		resources:           []ResourceContext{new(mockResourceContext)},
		decryptSessionIndex: -1,
		cpBytes:             append([]byte{0, 3}, []byte("foobar")...),
		expected:            append([]byte{0, 3}, []byte("foobar")...)})
}

func (s *paramcryptSuite) TestEncryptCommandParameterAES(c *C) {
	s.testEncryptCommandParameter(c, &testEncryptCommandParameterData{
		sessions: []SessionContext{
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("1234")}},
		decryptSessionIndex: 0,
		cpBytes:             append([]byte{0, 3}, []byte("foobar")...),
		expected:            []byte{0x00, 0x03, 0x13, 0x73, 0x6b, 'b', 'a', 'r'}})
}

func (s *paramcryptSuite) TestEncryptCommandParameterXOR(c *C) {
	s.testEncryptCommandParameter(c, &testEncryptCommandParameterData{
		sessions: []SessionContext{
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmXOR,
						KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}}}}},
		resources:           []ResourceContext{new(mockResourceContext)},
		decryptSessionIndex: 0,
		cpBytes:             append([]byte{0, 6}, []byte("foobar")...),
		expected:            []byte{0x00, 0x06, 0x3a, 0x19, 0xc7, 0xd8, 0x4c, 0xb7}})
}

func (s *paramcryptSuite) TestEncryptCommandParameterExtra(c *C) {
	s.testEncryptCommandParameter(c, &testEncryptCommandParameterData{
		sessions: []SessionContext{
			new(mockSessionContext),
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{new(mockResourceContext)},
		decryptSessionIndex: 1,
		cpBytes:             append([]byte{0, 3}, []byte("foobar")...),
		expected:            []byte{0x00, 0x03, 0x10, 0x1d, 0x80, 'b', 'a', 'r'}})
}

func (s *paramcryptSuite) TestEncryptCommandParameterExtraNoAuth(c *C) {
	s.testEncryptCommandParameter(c, &testEncryptCommandParameterData{
		sessions: []SessionContext{
			new(mockSessionContext),
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		decryptSessionIndex: 1,
		cpBytes:             append([]byte{0, 6}, []byte("foobar")...),
		expected:            []byte{0x00, 0x06, 0x10, 0x1d, 0x80, 0xa7, 0x7e, 0x09}})
}

type testDecryptResponseParameterData struct {
	sessions            []SessionContext
	resources           []ResourceContext
	encryptSessionIndex int

	rpBytes  []byte
	expected []byte
}

func (s *paramcryptSuite) testDecryptResponseParameter(c *C, data *testDecryptResponseParameterData) {
	var sessions []*SessionParam
	for i, s := range data.sessions {
		var r ResourceContext
		if i < len(data.resources) {
			r = data.resources[i]
		}
		sessions = append(sessions, newMockSessionParam(s, r, false, nil, nil))
	}

	rpBytes := make([]byte, len(data.rpBytes))
	copy(rpBytes, data.rpBytes)

	//if len(rpBytes) != len(data.expected) {
	//	rpBytes = make([]byte, len(data.expected))
	//	copy(rpBytes, data.expected)
	//
	//	if data.encryptSessionIndex >= 0 {
	//		sessionData := data.sessions[data.encryptSessionIndex].(SessionContextInternal).Data()
	//		param := sessions[data.encryptSessionIndex]
	//
	//		n := int(binary.BigEndian.Uint16(rpBytes))
	//
	//		switch sessionData.Symmetric.Algorithm {
	//		case SymAlgorithmAES:
	//			k := crypto.KDFa(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), []byte(CFBKey), sessionData.NonceTPM, sessionData.NonceCaller, int(sessionData.Symmetric.KeyBits.Sym)+(aes.BlockSize*8))
	//			offset := (sessionData.Symmetric.KeyBits.Sym + 7) / 8
	//			symKey := k[0:offset]
	//			iv := k[offset:]
	//			c.Check(crypto.SymmetricEncrypt(sessionData.Symmetric.Algorithm, symKey, iv, rpBytes[2:n+2]), IsNil)
	//		case SymAlgorithmXOR:
	//			crypto.XORObfuscation(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), sessionData.NonceTPM, sessionData.NonceCaller, rpBytes[2:n+2])
	//		}
	//	}
	//
	//	c.Logf("%x", rpBytes)
	//}

	params := newMockSessionParams(CommandUnseal, sessions, data.encryptSessionIndex, -1)

	c.Check(params.DecryptResponseParameter(rpBytes), IsNil)
	c.Check(rpBytes, DeepEquals, data.expected)
}

func (s *paramcryptSuite) TestDecryptResponseParameterNone(c *C) {
	s.testDecryptResponseParameter(c, &testDecryptResponseParameterData{
		sessions:            []SessionContext{new(mockSessionContext)},
		resources:           []ResourceContext{new(mockResourceContext)},
		encryptSessionIndex: -1,
		rpBytes:             append([]byte{0, 3}, []byte("barfoo")...),
		expected:            append([]byte{0, 3}, []byte("barfoo")...)})
}

func (s *paramcryptSuite) TestDecryptResponseParameterAES(c *C) {
	s.testDecryptResponseParameter(c, &testDecryptResponseParameterData{
		sessions: []SessionContext{
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("1234")}},
		encryptSessionIndex: 0,
		rpBytes:             []byte{0x00, 0x03, 0xf6, 0x86, 0x65, 'f', 'o', 'o'},
		expected:            append([]byte{0, 3}, []byte("barfoo")...)})
}

func (s *paramcryptSuite) TestDecryptResponseParameterXOR(c *C) {
	s.testDecryptResponseParameter(c, &testDecryptResponseParameterData{
		sessions: []SessionContext{
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmXOR,
						KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}}}}},
		resources:           []ResourceContext{new(mockResourceContext)},
		encryptSessionIndex: 0,
		rpBytes:             []byte{0x00, 0x06, 0xb8, 0x5d, 0xe0, 0xa8, 0x1a, 0x5d},
		expected:            append([]byte{0, 6}, []byte("barfoo")...)})
}

func (s *paramcryptSuite) TestDecryptResponseParameterExtra(c *C) {
	s.testDecryptResponseParameter(c, &testDecryptResponseParameterData{
		sessions: []SessionContext{
			new(mockSessionContext),
			&mockSessionContext{
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{new(mockResourceContext)},
		encryptSessionIndex: 1,
		rpBytes:             []byte{0x00, 0x03, 0x85, 0x5e, 0xfb, 'f', 'o', 'o'},
		expected:            append([]byte{0, 3}, []byte("barfoo")...)})
}

func TestParameterEncryptionSingleExtra(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			for _, data2 := range []struct {
				desc  string
				attrs SessionAttributes
			}{
				{
					desc:  "Command",
					attrs: AttrCommandEncrypt,
				},
				{
					desc:  "Response",
					attrs: AttrResponseEncrypt,
				},
				{
					desc:  "CommandAndResponse",
					attrs: AttrCommandEncrypt | AttrResponseEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					run1 := func(t *testing.T, authSession SessionContext) ResourceContext {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						template := Public{
							Type:    ObjectTypeKeyedHash,
							NameAlg: HashAlgorithmSHA256,
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
							Params: &PublicParamsU{
								KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						sessionContext.SetAttrs(AttrContinueSession | data2.attrs)
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, authSession, sessionContext)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, err := tpm.Load(primary, outPrivate, outPublic, authSession, sessionContext)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}
						objectContext.SetAuthValue(testAuth)

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(objectContext.Name(), expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object ResourceContext, authSession SessionContext) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						attrs := AttrContinueSession | (data2.attrs &^ AttrCommandEncrypt)
						sc := sessionContext.WithAttrs(attrs)
						if attrs&AttrResponseEncrypt == 0 {
							sc = nil
						}
						data, err := tpm.Unseal(object, authSession, sc)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, nil)
						defer flushContext(t, tpm, object)
						run2(t, object, nil)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						sessionContext.SetAttrs(AttrContinueSession)
						object := run1(t, sessionContext)
						defer flushContext(t, tpm, object)
						run2(t, object, sessionContext)
					})
				})
			}
		})
	}
}

func TestParameterEncryptionSharedWithAuth(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			for _, data2 := range []struct {
				desc  string
				attrs SessionAttributes
			}{
				{
					desc:  "Command",
					attrs: AttrCommandEncrypt,
				},
				{
					desc:  "Response",
					attrs: AttrResponseEncrypt,
				},
				{
					desc:  "CommandAndResponse",
					attrs: AttrCommandEncrypt | AttrResponseEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
					if err != nil {
						t.Fatalf("StartAuthSession failed: %v", err)
					}
					defer flushContext(t, tpm, sessionContext)
					sessionContext.SetAttrs(AttrContinueSession | data2.attrs)

					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					template := Public{
						Type:    ObjectTypeKeyedHash,
						NameAlg: HashAlgorithmSHA256,
						Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
						Params: &PublicParamsU{
							KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
					sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

					outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, sessionContext)
					if err != nil {
						t.Fatalf("Create failed: %v", err)
					}

					objectContext, err := tpm.Load(primary, outPrivate, outPublic, sessionContext)
					if err != nil {
						t.Fatalf("Load failed: %v", err)
					}
					defer flushContext(t, tpm, objectContext)
					objectContext.SetAuthValue(testAuth)

					expectedName, err := outPublic.Name()
					if err != nil {
						t.Fatalf("Cannot compute name: %v", err)
					}
					if !bytes.Equal(objectContext.Name(), expectedName) {
						t.Errorf("Unexpected name")
					}

					data, err := tpm.Unseal(objectContext, sessionContext.ExcludeAttrs(AttrCommandEncrypt))
					if err != nil {
						t.Fatalf("Unseal failed: %v", err)
					}

					if !bytes.Equal(data, secret) {
						t.Errorf("Got unexpected data")
					}
				})
			}
		})
	}
}

func TestParameterEncryptionMultipleExtra(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			for _, data2 := range []struct {
				desc   string
				attrs1 SessionAttributes
				attrs2 SessionAttributes
			}{
				{
					desc:   "1",
					attrs1: AttrCommandEncrypt,
					attrs2: AttrResponseEncrypt,
				},
				{
					desc:   "2",
					attrs1: AttrResponseEncrypt,
					attrs2: AttrCommandEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					run1 := func(t *testing.T, authSession SessionContext) ResourceContext {
						sessionContext1, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext1)

						sessionContext2, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext2)

						template := Public{
							Type:    ObjectTypeKeyedHash,
							NameAlg: HashAlgorithmSHA256,
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
							Params: &PublicParamsU{
								KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						sessionContext1.SetAttrs(AttrContinueSession | data2.attrs1)
						sessionContext2.SetAttrs(AttrContinueSession | data2.attrs2)
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, authSession, sessionContext1, sessionContext2)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, err := tpm.Load(primary, outPrivate, outPublic, authSession, sessionContext1, sessionContext2)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}
						objectContext.SetAuthValue(testAuth)

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(objectContext.Name(), expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object ResourceContext, authSession SessionContext) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						attrs := AttrContinueSession | data2.attrs1
						sc := sessionContext.WithAttrs(attrs)
						if attrs&AttrResponseEncrypt == 0 {
							sc = nil
						}
						data, err := tpm.Unseal(object, authSession, sc)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, nil)
						defer flushContext(t, tpm, object)
						run2(t, object, nil)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						sessionContext.SetAttrs(AttrContinueSession)
						object := run1(t, sessionContext)
						defer flushContext(t, tpm, object)
						run2(t, object, sessionContext)
					})
				})
			}
		})
	}
}
