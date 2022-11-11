// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"testing"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/crypto"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
)

type authSuite struct {
	testutil.BaseTest
}

var _ = Suite(&authSuite{})

func newMockSessionParam(session SessionContext, associatedResource ResourceContext, includeAuthValue bool, decryptNonce, encryptNonce Nonce) *SessionParam {
	var r ResourceContextInternal
	if associatedResource != nil {
		r = associatedResource.(ResourceContextInternal)
	}
	var s SessionContextInternal
	if session != nil {
		s = session.(SessionContextInternal)
	}

	return &SessionParam{
		Session:            s,
		AssociatedResource: r,
		IncludeAuthValue:   includeAuthValue,
		DecryptNonce:       decryptNonce,
		EncryptNonce:       encryptNonce}
}

func newMockSessionParams(commandCode CommandCode, sessions []*SessionParam, encryptSessionIndex, decryptSessionIndex int) *SessionParams {
	return &SessionParams{
		CommandCode:         commandCode,
		Sessions:            sessions,
		EncryptSessionIndex: encryptSessionIndex,
		DecryptSessionIndex: decryptSessionIndex}
}

func (s *authSuite) TestNewExtraSessionParam(c *C) {
	session := &mockSessionContext{data: &SessionContextData{SessionType: SessionTypeHMAC}}
	p, err := NewExtraSessionParam(session)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, nil, false, nil, nil))
}

func (s *authSuite) TestNewExtraSessionParamUnloaded(c *C) {
	session := new(mockSessionContext)
	_, err := NewExtraSessionParam(session)
	c.Check(err, ErrorMatches, "incomplete session can only be used in TPMContext.FlushContext")
}

func (s *authSuite) TestNewExtraSessionParamWrongType(c *C) {
	session := &mockSessionContext{data: &SessionContextData{SessionType: SessionTypePolicy}}
	_, err := NewExtraSessionParam(session)
	c.Check(err, ErrorMatches, "invalid session type")
}

func (s *authSuite) TestNewSessionParamForAuthPW(c *C) {
	session := &mockSessionContext{
		handle: HandlePW,
		data:   new(SessionContextData)}
	resource := &mockResourceContext{handle: HandleOwner}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, false, nil, nil))
}

func (s *authSuite) TestNewSessionParamForAuthUnboundHMAC(c *C) {
	session := &mockSessionContext{
		handle: 0x02000000,
		data:   &SessionContextData{SessionType: SessionTypeHMAC}}
	resource := &mockResourceContext{handle: HandleOwner}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, true, nil, nil))
}

func (s *authSuite) TestNewSessionParamForAuthBoundHMAC1(c *C) {
	session := &mockSessionContext{
		handle: 0x02000000,
		data: &SessionContextData{
			SessionType: SessionTypeHMAC,
			IsBound:     true,
			BoundEntity: []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xff, 0xff}}}
	resource := &mockResourceContext{
		handle:    HandleOwner,
		name:      []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
		authValue: []byte{0x55, 0x55}}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, false, nil, nil))
}

func (s *authSuite) TestNewSessionParamForAuthBoundHMAC2(c *C) {
	session := &mockSessionContext{
		handle: 0x02000000,
		data: &SessionContextData{
			SessionType: SessionTypeHMAC,
			IsBound:     true,
			BoundEntity: []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}}}
	resource := &mockResourceContext{
		handle:    HandleOwner,
		name:      []byte{0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa},
		authValue: []byte{0x55, 0x55}}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, true, nil, nil))
}

func (s *authSuite) TestNewSessionParamForAuthPolicy(c *C) {
	session := &mockSessionContext{
		handle: 0x03000000,
		data:   &SessionContextData{SessionType: SessionTypePolicy}}
	resource := &mockResourceContext{handle: HandleOwner}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, false, nil, nil))
}

func (s *authSuite) TestNewSessionParamForAuthPolicyAuth(c *C) {
	session := &mockSessionContext{
		handle: 0x03000000,
		data: &SessionContextData{
			SessionType:    SessionTypePolicy,
			PolicyHMACType: PolicyHMACTypeAuth}}
	resource := &mockResourceContext{handle: HandleOwner}
	p, err := NewSessionParamForAuth(session, resource)
	c.Assert(err, IsNil)
	c.Check(p, DeepEquals, newMockSessionParam(session, resource, true, nil, nil))
}

func (s *authSuite) TestSessionParamIsAuthFalse(c *C) {
	p := newMockSessionParam(nil, nil, false, nil, nil)
	c.Check(p.IsAuth(), internal_testutil.IsFalse)
}

func (s *authSuite) TestSessionParamIsAuthTrue(c *C) {
	p := newMockSessionParam(nil, new(mockResourceContext), false, nil, nil)
	c.Check(p.IsAuth(), internal_testutil.IsTrue)
}

func (s *authSuite) TestSessionParamIsPasswordTruePwSession(c *C) {
	session := &mockSessionContext{handle: HandlePW, data: &SessionContextData{}}
	p := newMockSessionParam(session, nil, false, nil, nil)
	c.Check(p.IsPassword(), internal_testutil.IsTrue)
}

func (s *authSuite) TestSessionParamIsPasswordTruePolicySession(c *C) {
	session := &mockSessionContext{
		handle: 0x03000000,
		data: &SessionContextData{
			SessionType:    SessionTypePolicy,
			PolicyHMACType: PolicyHMACTypePassword}}
	p := newMockSessionParam(session, nil, false, nil, nil)
	c.Check(p.IsPassword(), internal_testutil.IsTrue)
}

func (s *authSuite) TestSessionParamIsPasswordFalsePolicySession(c *C) {
	session := &mockSessionContext{
		handle: 0x03000000,
		data: &SessionContextData{
			SessionType: SessionTypePolicy}}
	p := newMockSessionParam(session, nil, false, nil, nil)
	c.Check(p.IsPassword(), internal_testutil.IsFalse)
}

func (s *authSuite) TestSessionParamIsPasswordFalseHMACSession(c *C) {
	session := &mockSessionContext{
		handle: 0x02000000,
		data: &SessionContextData{
			SessionType: SessionTypeHMAC}}
	p := newMockSessionParam(session, nil, false, nil, nil)
	c.Check(p.IsPassword(), internal_testutil.IsFalse)
}

type testSessionParamComputeSessionHMACKeyData struct {
	sessionKey       []byte
	resource         ResourceContext
	includeAuthValue bool
	expected         []byte
}

func (s *authSuite) testSessionParamComputeSessionHMACKey(c *C, data *testSessionParamComputeSessionHMACKeyData) {
	session := &mockSessionContext{data: &SessionContextData{SessionKey: data.sessionKey}}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, nil, nil)
	c.Check(p.ComputeSessionHMACKey(), DeepEquals, data.expected)
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: false,
		expected:         []byte("foo")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		expected:         []byte("foobar")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoSessionKeyNoIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: false,
		expected:         []byte(nil)})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoSessionKeyIncludeAuthValue(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		expected:         []byte("bar")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyIncludeEmptyAuthValue(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		resource:         new(mockResourceContext),
		includeAuthValue: true,
		expected:         []byte("foo")})
}

func (s *authSuite) TestSessionParamComputeSessionHMACKeyNoResource(c *C) {
	s.testSessionParamComputeSessionHMACKey(c, &testSessionParamComputeSessionHMACKeyData{
		sessionKey:       []byte("foo"),
		includeAuthValue: false,
		expected:         []byte("foo")})
}

type testSessionParamComputeCommandHMACData struct {
	hashAlg          HashAlgorithmId
	sessionKey       []byte
	nonceCaller      Nonce
	nonceTPM         Nonce
	attrs            SessionAttributes
	resource         ResourceContext
	includeAuthValue bool
	decryptNonce     Nonce
	encryptNonce     Nonce

	commandCode    CommandCode
	commandHandles []Name
	cpBytes        []byte

	expected []byte
}

func (s *authSuite) testSessionParamComputeCommandHMAC(c *C, data *testSessionParamComputeCommandHMACData) {
	session := &mockSessionContext{data: &SessionContextData{
		HashAlg:     data.hashAlg,
		SessionKey:  data.sessionKey,
		NonceCaller: data.nonceCaller,
		NonceTPM:    data.nonceTPM}, attrs: data.attrs}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, data.decryptNonce, data.encryptNonce)

	h := p.ComputeCommandHMAC(data.commandCode, data.commandHandles, data.cpBytes)
	c.Check(h, DeepEquals, data.expected)
}

func (s *authSuite) TestSessionParamComputeCommandHMACUnbound(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "c2ec178c103828144980213df8cb534554551c2662ddecb13d60e23e8b81b5c9")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACUnboundNoSessionKey(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "3b3e7fdc6ad56e78ff1c9317c2f0dfca3d7e19ef1ad1f84ff462277e169ceb70")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACUnboundNoKey(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         new(mockResourceContext),
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "7eea68509344f1dbd6ac7277398926bbd3c3f2893a745a2bd6e420edf53d8bca")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACBound(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: false,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "5a82eb5cbc7dd73bb8a5e0cb4ab1ca9580b52910d9ebbc9cdb4d3357f2b31b98")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACNoResource(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		includeAuthValue: false,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "5a82eb5cbc7dd73bb8a5e0cb4ab1ca9580b52910d9ebbc9cdb4d3357f2b31b98")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACSHA1(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA1,
		sessionKey:       internal_testutil.DecodeHexString(c, "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "7448d8798a4380162d4b56f9b452e2f6f9e24e7a"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "d6d2cee4ec40cfa5ed80b65db6c16fb8d0772c47")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithDifferentAuthValue(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "31c4c8df09e549f43213d454f086721bacbe07f9b983b54ca1afcf45fbdb3470")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithDifferentSessionKey(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "3790219b2959b0cb2fdf64cb2ce95b993fb6f96ffef55d4ab0874dfa77251bd5")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithDifferentAttributes(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "f074436034eaeae63f5f031ef1a21b95e7adce59e06f2dcfcbad71a2ad1770ea")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithUpdatedNonceCaller(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "c9bf0a8f87ef938b9ccb9bdb67eef3efec5d32de6eda5af5e2d962f8dcfc73d0")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithUpdatedNonceTPM(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "5cd146e7b379326e71d0dd1cffce16b69624311baee8cc76073b875bba682540")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithDecryptSession(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		decryptNonce:     internal_testutil.DecodeHexString(c, "56947de9ea64e970d05d96eb0a54a3e2817b1533ef5606ffbbad3525a4c3e24a"),
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "8d1fceb50c6f1d2eca994429c1b00b249d173b5f3c91f296f7e142743b8fda22")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithEncryptSession(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		encryptNonce:     internal_testutil.DecodeHexString(c, "79364818804e4cad50c6c820c1ad446036ba82949c2753c9f00839c8508f890f"),
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "d8eb6eee55b5ee5e9eb5fd1d928f440d5617bb9d36a3fb85dd9d8a0b1dfa47bf")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACWithDecryptAndEncryptSession(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		decryptNonce:     internal_testutil.DecodeHexString(c, "56947de9ea64e970d05d96eb0a54a3e2817b1533ef5606ffbbad3525a4c3e24a"),
		encryptNonce:     internal_testutil.DecodeHexString(c, "79364818804e4cad50c6c820c1ad446036ba82949c2753c9f00839c8508f890f"),
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expected:         internal_testutil.DecodeHexString(c, "8fbb9b4536b0c8324eb1d4638b140575236b82f0329bebb13192525c309d7747")})
}

func (s *authSuite) TestSessionParamComputeCommandHMACDifferentCommand(c *C) {
	s.testSessionParamComputeCommandHMAC(c, &testSessionParamComputeCommandHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandClearControl,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "0400000a")},
		cpBytes:          []byte{0x01},
		expected:         internal_testutil.DecodeHexString(c, "b967c04071695d4e3598adb1b033780d795f1dee3c7b2ab02dc46202b2ab7067")})
}

type testSessionParamComputeResponseHMACData struct {
	hashAlg          HashAlgorithmId
	sessionKey       []byte
	nonceCaller      Nonce
	nonceTPM         Nonce
	resource         ResourceContext
	includeAuthValue bool
	decryptNonce     Nonce
	encryptNonce     Nonce

	attrs       SessionAttributes
	commandCode CommandCode
	rpBytes     []byte

	expected []byte
	required bool
}

func (s *authSuite) testSessionParamComputeResponseHMAC(c *C, data *testSessionParamComputeResponseHMACData) {
	session := &mockSessionContext{data: &SessionContextData{
		HashAlg:     data.hashAlg,
		SessionKey:  data.sessionKey,
		NonceCaller: data.nonceCaller,
		NonceTPM:    data.nonceTPM}}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, data.decryptNonce, data.encryptNonce)

	h, required := p.ComputeResponseHMAC(AuthResponse{SessionAttributes: data.attrs}, data.commandCode, data.rpBytes)
	c.Check(h, DeepEquals, data.expected)
	c.Check(required, Equals, data.required)
}

func (s *authSuite) TestSessionParamComputeResponseHMACUnbound(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACUnboundNoSessionKey(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "5828acd68f75f3f1aeb37a1256ef21aee50d73e53e8b316ed4802b8942a7be28"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACUnboundNoKey(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         new(mockResourceContext),
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "45c56cd43521cde19cba928ea8bdaf9305f985824a180124cade770310ef614f"),
		required:         false})
}

func (s *authSuite) TestSessionParamComputeResponseHMACBound(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: false,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "87b82babc9d13836e563163e6e87392881dd1bb2c1509662b9f30768a926b3d0"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACNoResource(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		includeAuthValue: false,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "87b82babc9d13836e563163e6e87392881dd1bb2c1509662b9f30768a926b3d0"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACSHA1(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA1,
		sessionKey:       internal_testutil.DecodeHexString(c, "f1d2d2f924e986ac86fdf7b36c94bcdf32beec15"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "e5fa44f2b31c1fb553b6021e7360d07d5d91ff5e"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "7448d8798a4380162d4b56f9b452e2f6f9e24e7a"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "afd6acbfb60f1f6acc1435a08e2d01f7e5e13c46"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentAuthValue(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("bar")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "4cb786ea943fc7ccda067cfd08e84a341555794ab50a669ff8c4557ab370f1d0"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentSessionKey(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "27e58e3a8261fc7bfa5a1ab255da50e8403df3a069fc01f783cc39abcf362936"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentAttributes(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession | AttrAudit | AttrAuditExclusive,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "90205adabcbd77d7ad1f9b884939fb35a805b5375d2be64d0a449dadc06558e6"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentNonceCaller(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "e4ff3a9beaff6d5db07748b1c8a9f9eddfa5d609a42b87c83a91cea4167f069b"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentNonceTPM(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "7d2f7fd60a203df42b0609f54eee5e24608cdce07e2a98cf360b0d59d0fad107"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACWithDecryptAndEncryptSession(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		decryptNonce:     internal_testutil.DecodeHexString(c, "56947de9ea64e970d05d96eb0a54a3e2817b1533ef5606ffbbad3525a4c3e24a"),
		encryptNonce:     internal_testutil.DecodeHexString(c, "79364818804e4cad50c6c820c1ad446036ba82949c2753c9f00839c8508f890f"),
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...),
		expected:         internal_testutil.DecodeHexString(c, "5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd"),
		required:         true})
}

func (s *authSuite) TestSessionParamComputeResponseHMACDifferentCommand(c *C) {
	s.testSessionParamComputeResponseHMAC(c, &testSessionParamComputeResponseHMACData{
		hashAlg:          HashAlgorithmSHA256,
		sessionKey:       internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		nonceTPM:         internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		attrs:            AttrContinueSession,
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 10}, []byte("xxxxxxxxxx")...),
		expected:         internal_testutil.DecodeHexString(c, "eb1235d806ebbb10e49776e9517ab958353a81e9aa03e18b77282be4703db3bb"),
		required:         true})
}

func (s *authSuite) TestSessionParamBuildCommandAuthPW(c *C) {
	resource := &mockResourceContext{authValue: []byte("foo")}

	session := &mockSessionContext{
		handle: HandlePW,
		data:   new(SessionContextData),
		attrs:  AttrContinueSession}
	p := newMockSessionParam(session, resource, false, nil, nil)

	auth := p.BuildCommandAuth(CommandClearControl, []Name{internal_testutil.DecodeHexString(c, "0400000a")}, []byte{0x01})
	c.Check(auth, DeepEquals, &AuthCommand{
		SessionHandle:     HandlePW,
		SessionAttributes: AttrContinueSession,
		HMAC:              []byte("foo")})
}

func (s *authSuite) TestSessionParamBuildCommandAuthPolicyPW(c *C) {
	resource := &mockResourceContext{authValue: []byte("foo")}

	session := &mockSessionContext{
		handle: 0x03000000,
		data: &SessionContextData{
			SessionType:    SessionTypePolicy,
			PolicyHMACType: PolicyHMACTypePassword},
		attrs: AttrContinueSession}
	p := newMockSessionParam(session, resource, false, nil, nil)

	auth := p.BuildCommandAuth(CommandClearControl, []Name{internal_testutil.DecodeHexString(c, "0400000a")}, []byte{0x01})
	c.Check(auth, DeepEquals, &AuthCommand{
		SessionHandle:     session.handle,
		SessionAttributes: AttrContinueSession,
		HMAC:              []byte("foo")})
}

type testSessionParamBuildCommandAuthData struct {
	handle         Handle
	sessionType    SessionType
	policyHMACType PolicyHMACType
	nonceCaller    Nonce
	attrs          SessionAttributes

	resource         ResourceContext
	includeAuthValue bool

	commandCode    CommandCode
	commandHandles []Name
	cpBytes        []byte
}

func (s *authSuite) testSessionParamBuildCommandAuth(c *C, data *testSessionParamBuildCommandAuthData) {
	session := &mockSessionContext{
		handle: data.handle,
		data: &SessionContextData{
			HashAlg:        HashAlgorithmSHA256,
			SessionType:    data.sessionType,
			PolicyHMACType: data.policyHMACType,
			SessionKey:     internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
			NonceCaller:    data.nonceCaller,
			NonceTPM:       internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")},
		attrs: data.attrs}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, nil, nil)

	expectedHmac := p.ComputeCommandHMAC(data.commandCode, data.commandHandles, data.cpBytes)

	auth := p.BuildCommandAuth(data.commandCode, data.commandHandles, data.cpBytes)
	c.Check(auth, DeepEquals, &AuthCommand{
		SessionHandle:     data.handle,
		Nonce:             data.nonceCaller,
		SessionAttributes: data.attrs,
		HMAC:              expectedHmac})
}

func (s *authSuite) TestSessionParamBuildCommandAuthUnbound(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x02000000,
		sessionType:      SessionTypeHMAC,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthDifferentHandle(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x02000003,
		sessionType:      SessionTypeHMAC,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthPolicy(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x03000000,
		sessionType:      SessionTypePolicy,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: false,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthPolicyWithAuthValue(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x03000000,
		sessionType:      SessionTypePolicy,
		policyHMACType:   PolicyHMACTypeAuth,
		nonceCaller:      internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthDifferentNonceCaller(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x02000000,
		sessionType:      SessionTypeHMAC,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthDifferentAttributes(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x02000000,
		sessionType:      SessionTypeHMAC,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession | AttrAudit,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandUnseal,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamBuildCommandAuthDifferentCommand(c *C) {
	s.testSessionParamBuildCommandAuth(c, &testSessionParamBuildCommandAuthData{
		handle:           0x02000000,
		sessionType:      SessionTypeHMAC,
		nonceCaller:      internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		attrs:            AttrContinueSession,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		commandCode:      CommandClearControl,
		commandHandles:   []Name{internal_testutil.DecodeHexString(c, "0400000a")},
		cpBytes:          []byte{0x01}})
}

func (s *authSuite) TestSessionParamProcessResponseAuthPW(c *C) {
	session := &mockSessionContext{
		handle: HandlePW,
		data:   new(SessionContextData),
		attrs:  AttrContinueSession}
	p := newMockSessionParam(session, new(mockResourceContext), false, nil, nil)

	c.Check(p.ProcessResponseAuth(AuthResponse{}, CommandUnseal, []byte{0, 0}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthPolicyPW(c *C) {
	session := &mockSessionContext{
		handle: 0x03000000,
		data: &SessionContextData{
			SessionType:    SessionTypePolicy,
			PolicyHMACType: PolicyHMACTypePassword},
		attrs: AttrContinueSession}
	p := newMockSessionParam(session, new(mockResourceContext), false, nil, nil)

	c.Check(p.ProcessResponseAuth(AuthResponse{}, CommandUnseal, []byte{0, 0}), IsNil)
}

type testSessionParamProcessResponseAuthData struct {
	sessionType    SessionType
	policyHMACType PolicyHMACType

	resource         ResourceContext
	includeAuthValue bool

	nonce Nonce
	attrs SessionAttributes
	hmac  Auth

	commandCode CommandCode
	rpBytes     []byte
}

func (s *authSuite) testSessionParamProcessResponseAuth(c *C, data *testSessionParamProcessResponseAuthData) error {
	session := &mockSessionContext{
		handle: 0x02000000,
		data: &SessionContextData{
			HashAlg:        HashAlgorithmSHA256,
			SessionType:    data.sessionType,
			PolicyHMACType: data.policyHMACType,
			SessionKey:     internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
			NonceCaller:    internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}}
	p := newMockSessionParam(session, data.resource, data.includeAuthValue, nil, nil)

	resp := AuthResponse{
		Nonce:             data.nonce,
		SessionAttributes: data.attrs,
		HMAC:              data.hmac}
	err := p.ProcessResponseAuth(resp, data.commandCode, data.rpBytes)

	if err == nil {
		c.Check(session.data.NonceTPM, DeepEquals, data.nonce)
		c.Check(session.data.IsAudit, Equals, data.attrs&AttrAudit > 0)
		c.Check(session.data.IsExclusive, Equals, data.attrs&AttrAuditExclusive > 0)
	}

	return err
}

func (s *authSuite) TestSessionParamProcessResponseAuthUnbound(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthPolicy(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypePolicy,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: false,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "87b82babc9d13836e563163e6e87392881dd1bb2c1509662b9f30768a926b3d0"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthPolicyWithAuthValue(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		policyHMACType:   PolicyHMACTypeAuth,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseDifferentNonce(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "7d2f7fd60a203df42b0609f54eee5e24608cdce07e2a98cf360b0d59d0fad107"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthDifferentCommand(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "6670807a9d299e1df9256aca76bd98d92d421fa62c6a0838f5bda40c2cddda45"),
		commandCode:      CommandClearControl}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthAudit(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession | AttrAudit,
		hmac:             internal_testutil.DecodeHexString(c, "2643db59c4035372893ab08a64d6d8a0261a09e4b656961d566ff8f767f0889c"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthAuditExclusive(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         &mockResourceContext{authValue: []byte("foo")},
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession | AttrAudit | AttrAuditExclusive,
		hmac:             internal_testutil.DecodeHexString(c, "90205adabcbd77d7ad1f9b884939fb35a805b5375d2be64d0a449dadc06558e6"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamProcessResponseAuthInvalidHMAC(c *C) {
	c.Check(s.testSessionParamProcessResponseAuth(c, &testSessionParamProcessResponseAuthData{
		sessionType:      SessionTypeHMAC,
		resource:         new(mockResourceContext),
		includeAuthValue: true,
		nonce:            internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
		attrs:            AttrContinueSession,
		hmac:             internal_testutil.DecodeHexString(c, "5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd"),
		commandCode:      CommandUnseal,
		rpBytes:          append([]byte{0, 3}, []byte("bar")...)}), ErrorMatches,
		"incorrect HMAC \\(expected: 87b82babc9d13836e563163e6e87392881dd1bb2c1509662b9f30768a926b3d0, got: 5ea73cb92c896cddbe717d16c263eb7ba79d701224d465be6640c018eee557cd\\)")
}

type testSessionParamsAppendSessionForResourceData struct {
	sessions                    []SessionContext
	resources                   []ResourceContext
	expectedEncryptSessionIndex int
	expectedDecryptSessionIndex int
}

func (s *authSuite) testSessionParamsAppendSessionForResource(c *C, data *testSessionParamsAppendSessionForResourceData) {
	c.Assert(len(data.sessions), Equals, len(data.resources))

	params := NewSessionParams()
	var expectedParams []*SessionParam
	for i := range data.sessions {
		c.Check(params.AppendSessionForResource(data.sessions[i], data.resources[i]), IsNil)
		p, err := NewSessionParamForAuth(data.sessions[i], data.resources[i])
		c.Assert(err, IsNil)
		expectedParams = append(expectedParams, p)
	}

	c.Check(params.Sessions, DeepEquals, expectedParams)
	c.Check(params.EncryptSessionIndex, Equals, data.expectedEncryptSessionIndex)
	c.Check(params.DecryptSessionIndex, Equals, data.expectedDecryptSessionIndex)
}

func (s *authSuite) TestSessionParamsAppendSessionForResource(c *C) {
	s.testSessionParamsAppendSessionForResource(c, &testSessionParamsAppendSessionForResourceData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: HandlePW,
				data:   new(SessionContextData),
				attrs:  AttrContinueSession}},
		resources:                   []ResourceContext{new(mockResourceContext)},
		expectedEncryptSessionIndex: -1,
		expectedDecryptSessionIndex: -1,
	})
}

func (s *authSuite) TestSessionParamsAppendSessionForResourceWithEncryptSession(c *C) {
	s.testSessionParamsAppendSessionForResource(c, &testSessionParamsAppendSessionForResourceData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x03000000,
				data:   &SessionContextData{SessionType: SessionTypePolicy},
				attrs:  AttrContinueSession | AttrResponseEncrypt}},
		resources:                   []ResourceContext{new(mockResourceContext)},
		expectedEncryptSessionIndex: 0,
		expectedDecryptSessionIndex: -1,
	})
}

type testSessionParamsAppendExtraSessionsData struct {
	sessions                    []SessionContext
	expectedEncryptSessionIndex int
	expectedDecryptSessionIndex int
}

func (s *authSuite) testSessionParamsAppendExtraSessions(c *C, data *testSessionParamsAppendExtraSessionsData) {
	resource := new(mockResourceContext)
	session := &mockSessionContext{
		handle: HandlePW,
		data:   new(SessionContextData),
		attrs:  AttrContinueSession}

	expectedParams := []*SessionParam{newMockSessionParam(session, resource, false, nil, nil)}
	params := newMockSessionParams(0, []*SessionParam{expectedParams[0]}, -1, -1)

	c.Check(params.AppendExtraSessions(data.sessions...), IsNil)
	for _, s := range data.sessions {
		if s == nil {
			continue
		}
		p, err := NewExtraSessionParam(s)
		c.Assert(err, IsNil)
		expectedParams = append(expectedParams, p)
	}

	c.Check(params.Sessions, DeepEquals, expectedParams)
	c.Check(params.EncryptSessionIndex, Equals, data.expectedEncryptSessionIndex)
	c.Check(params.DecryptSessionIndex, Equals, data.expectedDecryptSessionIndex)
}

func (s *authSuite) TestSessionParamsAppendExtraSessionsAudit(c *C) {
	s.testSessionParamsAppendExtraSessions(c, &testSessionParamsAppendExtraSessionsData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000001,
				data:   &SessionContextData{SessionType: SessionTypeHMAC},
				attrs:  AttrAudit}},
		expectedEncryptSessionIndex: -1,
		expectedDecryptSessionIndex: -1,
	})
}

func (s *authSuite) TestSessionParamsAppendExtraSessionsEncrypt(c *C) {
	s.testSessionParamsAppendExtraSessions(c, &testSessionParamsAppendExtraSessionsData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000001,
				data:   &SessionContextData{SessionType: SessionTypeHMAC},
				attrs:  AttrResponseEncrypt}},
		expectedEncryptSessionIndex: 1,
		expectedDecryptSessionIndex: -1,
	})
}

func (s *authSuite) TestSessionParamsAppendExtraSessionsDecrypt(c *C) {
	s.testSessionParamsAppendExtraSessions(c, &testSessionParamsAppendExtraSessionsData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000001,
				data:   &SessionContextData{SessionType: SessionTypeHMAC},
				attrs:  AttrCommandEncrypt}},
		expectedEncryptSessionIndex: -1,
		expectedDecryptSessionIndex: 1,
	})
}

func (s *authSuite) TestSessionParamsAppendExtraSessionsSkipNils(c *C) {
	s.testSessionParamsAppendExtraSessions(c, &testSessionParamsAppendExtraSessionsData{
		sessions: []SessionContext{
			nil, nil,
			&mockSessionContext{
				handle: 0x02000001,
				data:   &SessionContextData{SessionType: SessionTypeHMAC},
				attrs:  AttrResponseEncrypt}},
		expectedEncryptSessionIndex: 1,
		expectedDecryptSessionIndex: -1,
	})
}

func (s *authSuite) TestSessionParamsComputeCallerNonces(c *C) {
	b := internal_testutil.DecodeHexString(c, "111111112222222233333333444444445555555566666666777777778888888899999999aaaaaaaabbbbbbbbccccccccdddddddd")
	s.AddCleanup(MockRandReader(bytes.NewReader(b)))

	sessions := []*mockSessionContext{
		&mockSessionContext{data: &SessionContextData{NonceCaller: make([]byte, 20)}},
		&mockSessionContext{data: &SessionContextData{NonceCaller: make([]byte, 32)}}}
	params := newMockSessionParams(0, []*SessionParam{
		newMockSessionParam(sessions[0], nil, false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil),
	}, -1, -1)

	c.Check(params.ComputeCallerNonces(), IsNil)
	c.Check(sessions[0].data.NonceCaller, DeepEquals, Nonce(internal_testutil.DecodeHexString(c, "1111111122222222333333334444444455555555")))
	c.Check(sessions[1].data.NonceCaller, DeepEquals, Nonce(internal_testutil.DecodeHexString(c, "66666666777777778888888899999999aaaaaaaabbbbbbbbccccccccdddddddd")))
}

type testSessionParamsBuildCommandAuthAreaData struct {
	rand []byte

	sessions  []SessionContext
	resources []ResourceContext

	encryptSessionIndex int
	decryptSessionIndex int

	commandCode    CommandCode
	commandHandles []Name
	cpBytes        []byte

	expectedCallerNonces []Nonce
	expectedDecryptNonce Nonce
	expectedEncryptNonce Nonce
}

func (s *authSuite) testSessionParamsBuildCommandAuthArea(c *C, data *testSessionParamsBuildCommandAuthAreaData) {
	s.AddCleanup(MockRandReader(bytes.NewReader(data.rand)))

	var sessions []*SessionParam
	for i, s := range data.sessions {
		var r ResourceContext
		if i < len(data.resources) {
			r = data.resources[i]
		}
		sessions = append(sessions, newMockSessionParam(s, r, false, nil, nil))
	}

	params := newMockSessionParams(0, sessions, data.encryptSessionIndex, data.decryptSessionIndex)

	origCpBytes := data.cpBytes
	if data.cpBytes == nil {
		origCpBytes = []byte{}
	}

	cpBytes := make([]byte, len(origCpBytes))
	copy(cpBytes, origCpBytes)

	authArea, err := params.BuildCommandAuthArea(data.commandCode, data.commandHandles, cpBytes)
	c.Check(err, IsNil)

	// check command code was saved
	c.Check(params.CommandCode, Equals, data.commandCode)

	// check caller nonces
	for i, s := range data.sessions {
		if i >= len(data.expectedCallerNonces) {
			break
		}
		c.Check(s.(SessionContextInternal).Data().NonceCaller, DeepEquals, data.expectedCallerNonces[i])
	}

	recovered := make([]byte, len(cpBytes))
	copy(recovered, cpBytes)

	// check command encryption
	if data.decryptSessionIndex >= 0 {
		sessionData := data.sessions[data.decryptSessionIndex].(SessionContextInternal).Data()
		param := sessions[data.decryptSessionIndex]

		n := int(binary.BigEndian.Uint16(recovered))

		switch sessionData.Symmetric.Algorithm {
		case SymAlgorithmAES:
			k := crypto.KDFa(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), []byte(CFBKey), sessionData.NonceCaller, sessionData.NonceTPM, int(sessionData.Symmetric.KeyBits.Sym)+(aes.BlockSize*8))
			offset := (sessionData.Symmetric.KeyBits.Sym + 7) / 8
			symKey := k[0:offset]
			iv := k[offset:]
			c.Check(crypto.SymmetricDecrypt(sessionData.Symmetric.Algorithm, symKey, iv, recovered[2:n+2]), IsNil)
		case SymAlgorithmXOR:
			crypto.XORObfuscation(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), sessionData.NonceCaller, sessionData.NonceTPM, recovered[2:n+2])
		}
	}
	c.Check(recovered, DeepEquals, origCpBytes)

	// check encrypt/decrypt nonces
	c.Check(sessions[0].DecryptNonce, DeepEquals, data.expectedDecryptNonce)
	c.Check(sessions[0].EncryptNonce, DeepEquals, data.expectedEncryptNonce)

	// check auth area
	c.Assert(authArea, HasLen, len(sessions))
	for i, a := range authArea {
		c.Check(a.SessionHandle, Equals, data.sessions[i].Handle())
		c.Check(a.Nonce, DeepEquals, data.sessions[i].(SessionContextInternal).Data().NonceCaller)
		c.Check(a.SessionAttributes, Equals, data.sessions[i].(SessionContextInternal).Attrs())

		var expectedHmac Auth
		if sessions[i].IsPassword() {
			expectedHmac = data.resources[i].(ResourceContextInternal).GetAuthValue()
		} else {
			expectedHmac = sessions[i].ComputeCommandHMAC(data.commandCode, data.commandHandles, cpBytes)
		}
		c.Check(a.HMAC, DeepEquals, expectedHmac)
	}
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaPW(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		sessions:            []SessionContext{&mockSessionContext{handle: HandlePW, data: new(SessionContextData), attrs: AttrContinueSession}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: -1,
		decryptSessionIndex: -1,
		commandHandles:      []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")}})
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaHMAC(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		rand: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")},
				attrs: AttrContinueSession}},
		resources:            []ResourceContext{new(mockResourceContext)},
		commandCode:          CommandUnseal,
		encryptSessionIndex:  -1,
		decryptSessionIndex:  -1,
		commandHandles:       []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expectedCallerNonces: []Nonce{internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}})
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaWithDecryptSession(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		rand: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}},
				attrs: AttrContinueSession | AttrCommandEncrypt}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandNVWrite,
		encryptSessionIndex: -1,
		decryptSessionIndex: 0,
		commandHandles: []Name{
			internal_testutil.DecodeHexString(c, "40000001"),
			internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		cpBytes:              []byte{0x00, 0x03, 0xaa, 0x55, 0xa5, 0x00, 0x10},
		expectedCallerNonces: []Nonce{internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}})
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaWithExtraDecryptSession(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		rand: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd8651121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				},
				attrs: AttrContinueSession},
			&mockSessionContext{
				handle: 0x02000001,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}},
				attrs: AttrContinueSession | AttrCommandEncrypt}},
		resources:           []ResourceContext{new(mockResourceContext)},
		commandCode:         CommandNVWrite,
		encryptSessionIndex: -1,
		decryptSessionIndex: 1,
		commandHandles: []Name{
			internal_testutil.DecodeHexString(c, "40000001"),
			internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		cpBytes: []byte{0x00, 0x03, 0xaa, 0x55, 0xa5, 0x00, 0x10},
		expectedCallerNonces: []Nonce{
			internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
			internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2")},
		expectedDecryptNonce: internal_testutil.DecodeHexString(c, "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d")})
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaWithEncryptSession(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		rand: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")},
				attrs: AttrContinueSession | AttrResponseEncrypt}},
		resources:            []ResourceContext{new(mockResourceContext)},
		commandCode:          CommandUnseal,
		encryptSessionIndex:  0,
		decryptSessionIndex:  -1,
		commandHandles:       []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expectedCallerNonces: []Nonce{internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}})
}

func (s *authSuite) TestSessionParamsBuildCommandAuthAreaWithExtraEncryptSession(c *C) {
	s.testSessionParamsBuildCommandAuthArea(c, &testSessionParamsBuildCommandAuthAreaData{
		rand: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd8651121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")},
				attrs: AttrContinueSession},
			&mockSessionContext{
				handle: 0x02000001,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
					NonceCaller: make([]byte, 32),
					NonceTPM:    internal_testutil.DecodeHexString(c, "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}},
				attrs: AttrContinueSession | AttrCommandEncrypt}},
		resources:            []ResourceContext{new(mockResourceContext)},
		commandCode:          CommandUnseal,
		encryptSessionIndex:  1,
		decryptSessionIndex:  -1,
		commandHandles:       []Name{internal_testutil.DecodeHexString(c, "000bf80b1fa820d95a87cf48f78eb6c298b427fda46207f7b52eaff6fb8ab1590c64")},
		expectedCallerNonces: []Nonce{internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")},
		expectedEncryptNonce: internal_testutil.DecodeHexString(c, "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d")})
}

func (s *authSuite) TestSessionParamsInvalidateSessionContexts(c *C) {
	sessions := []*mockSessionContext{
		&mockSessionContext{handle: 0x02000000},
		&mockSessionContext{handle: 0x03000001},
		&mockSessionContext{handle: 0x02000002}}
	params := newMockSessionParams(0, []*SessionParam{
		newMockSessionParam(sessions[0], nil, false, nil, nil),
		newMockSessionParam(sessions[1], nil, false, nil, nil),
		newMockSessionParam(sessions[2], nil, false, nil, nil),
	}, -1, -1)

	params.InvalidateSessionContexts([]AuthResponse{
		{SessionAttributes: AttrContinueSession},
		{},
		{SessionAttributes: AttrResponseEncrypt}})
	c.Check(sessions[0].Handle(), Equals, Handle(0x02000000))
	c.Check(sessions[1].Handle(), Equals, HandleUnassigned)
	c.Check(sessions[2].Handle(), Equals, HandleUnassigned)
}

type testSessionParamsProcessResponseAuthAreaData struct {
	sessions     []SessionContext
	resources    []ResourceContext
	encryptNonce Nonce

	commandCode         CommandCode
	encryptSessionIndex int

	responseAuth []AuthResponse
	rpBytes      []byte
}

func (s *authSuite) testSessionParamsProcessResponseAuthArea(c *C, data *testSessionParamsProcessResponseAuthAreaData) error {
	var sessions []*SessionParam
	for i, s := range data.sessions {
		var r ResourceContext
		if i < len(data.resources) {
			r = data.resources[i]
		}
		var encryptNonce Nonce
		if i == 0 {
			encryptNonce = data.encryptNonce
		}
		sessions = append(sessions, newMockSessionParam(s, r, false, nil, encryptNonce))
	}

	params := newMockSessionParams(data.commandCode, sessions, data.encryptSessionIndex, -1)

	rpBytes := make([]byte, len(data.rpBytes))
	copy(rpBytes, data.rpBytes)

	if data.encryptSessionIndex >= 0 {
		sessionData := data.sessions[data.encryptSessionIndex].(SessionContextInternal).Data()
		param := sessions[data.encryptSessionIndex]
		auth := data.responseAuth[data.encryptSessionIndex]

		n := int(binary.BigEndian.Uint16(rpBytes))

		switch sessionData.Symmetric.Algorithm {
		case SymAlgorithmAES:
			k := crypto.KDFa(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), []byte(CFBKey), auth.Nonce, sessionData.NonceCaller, int(sessionData.Symmetric.KeyBits.Sym)+(aes.BlockSize*8))
			offset := (sessionData.Symmetric.KeyBits.Sym + 7) / 8
			symKey := k[0:offset]
			iv := k[offset:]
			c.Check(crypto.SymmetricEncrypt(sessionData.Symmetric.Algorithm, symKey, iv, rpBytes[2:n+2]), IsNil)
		case SymAlgorithmXOR:
			crypto.XORObfuscation(sessionData.HashAlg.GetHash(), param.ComputeSessionValue(), auth.Nonce, sessionData.NonceCaller, rpBytes[2:n+2])
		}
	}

	if err := params.ProcessResponseAuthArea(data.responseAuth, rpBytes); err != nil {
		return err
	}

	// check sessions
	for i, s := range data.sessions {
		sessionData := s.(SessionContextInternal).Data()
		auth := data.responseAuth[i]

		c.Check(sessionData.NonceTPM, DeepEquals, auth.Nonce)
		c.Check(sessionData.IsAudit, Equals, auth.SessionAttributes&AttrAudit > 0)
		c.Check(sessionData.IsExclusive, Equals, auth.SessionAttributes&AttrAuditExclusive > 0)

		if auth.SessionAttributes&AttrContinueSession == 0 {
			c.Check(s.Handle(), Equals, HandleUnassigned)
		}
	}

	// check response bytes
	c.Check(rpBytes, DeepEquals, data.rpBytes)

	return nil
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaPW(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions:            []SessionContext{&mockSessionContext{handle: HandlePW, data: new(SessionContextData)}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: -1,
		responseAuth:        []AuthResponse{{SessionAttributes: AttrContinueSession}},
		rpBytes:             append([]byte{0, 6}, []byte("foobar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaHMAC(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: -1,
		responseAuth: []AuthResponse{
			{
				Nonce:             internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				SessionAttributes: AttrContinueSession,
				HMAC:              internal_testutil.DecodeHexString(c, "f5c298228f0195386a623875430b30bfa414e1aa5280dbcb2f656ec5d50890cb"),
			}},
		rpBytes: append([]byte{0, 6}, []byte("foobar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaInvalidHMAC(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: -1,
		responseAuth: []AuthResponse{
			{
				Nonce:             internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				SessionAttributes: AttrContinueSession,
				HMAC:              internal_testutil.DecodeHexString(c, "042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24"),
			}},
		rpBytes: append([]byte{0, 6}, []byte("foobar")...)}), ErrorMatches,
		"encountered an error whilst processing the auth response for session 0: "+
			"incorrect HMAC \\(expected: f5c298228f0195386a623875430b30bfa414e1aa5280dbcb2f656ec5d50890cb, got: 042aea10a0f14f2d391373599be69d53a75dde9951fc3d3cd10b6100aa7a9f24\\)")
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaFlushSession(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: -1,
		responseAuth: []AuthResponse{
			{
				Nonce: internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				HMAC:  internal_testutil.DecodeHexString(c, "a9be82abaff00f33e546d30b08d2cc315cb2a3e20a1ec2b8ed2885e55e3dfcec"),
			}},
		rpBytes: append([]byte{0, 6}, []byte("foobar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaWithDecryptSession(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		commandCode:         CommandUnseal,
		encryptSessionIndex: 0,
		responseAuth: []AuthResponse{
			{
				Nonce:             internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				SessionAttributes: AttrContinueSession | AttrResponseEncrypt,
				HMAC:              internal_testutil.DecodeHexString(c, "e7d274435fa3875f41baaf8f761ebccd27fd3e0805d7327eb86adcfc738909e7"),
			}},
		rpBytes: append([]byte{0, 6}, []byte("foobar")...)}), IsNil)
}

func (s *authSuite) TestSessionParamsProcessResponseAuthAreaWithExtraDecryptSession(c *C) {
	c.Check(s.testSessionParamsProcessResponseAuthArea(c, &testSessionParamsProcessResponseAuthAreaData{
		sessions: []SessionContext{
			&mockSessionContext{
				handle: 0x02000000,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c"),
					NonceCaller: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}},
			&mockSessionContext{
				handle: 0x02000001,
				data: &SessionContextData{
					HashAlg:     HashAlgorithmSHA256,
					SessionType: SessionTypeHMAC,
					SessionKey:  internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
					NonceCaller: internal_testutil.DecodeHexString(c, "1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"),
					NonceTPM:    internal_testutil.DecodeHexString(c, "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa"),
					Symmetric: &SymDef{
						Algorithm: SymAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB}}}}},
		resources:           []ResourceContext{&mockResourceContext{authValue: []byte("foo")}},
		encryptNonce:        internal_testutil.DecodeHexString(c, "9a271f2a916b0b6ee6cecb2426f0b3206ef074578be55d9bc94f6f3fe3ab86aa"),
		commandCode:         CommandUnseal,
		encryptSessionIndex: 1,
		responseAuth: []AuthResponse{
			{
				Nonce:             internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"),
				SessionAttributes: AttrContinueSession,
				HMAC:              internal_testutil.DecodeHexString(c, "a12c72d6febaf47273402bad147feccafbb19ca42f12d10b4b12ef1331e94690"),
			},
			{
				Nonce:             internal_testutil.DecodeHexString(c, "7de1555df0c2700329e815b93b32c571c3ea54dc967b89e81ab73b9972b72d1d"),
				SessionAttributes: AttrResponseEncrypt,
				HMAC:              internal_testutil.DecodeHexString(c, "55c3dffa8b2d32ff4f8bcedc267fa5a5380b47d48ff0e05e46b5f1d9f4a80cae"),
			}},
		rpBytes: append([]byte{0, 6}, []byte("foobar")...)}), IsNil)
}

func TestHMACSessions(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	owner := tpm.OwnerHandleContext()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	primaryECC := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         owner,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "UnboundSaltedRSA",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSaltedECC",
			tpmKey:       primaryECC,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSaltedRSA",
			tpmKey:       primary,
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			template := Public{
				Type:    ObjectTypeRSA,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
				Params: &PublicParamsU{
					RSADetail: &RSAParams{
						Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
						Scheme:    RSAScheme{Scheme: RSASchemeNull},
						KeyBits:   2048,
						Exponent:  0}}}

			sc.SetAttrs(data.sessionAttrs)
			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent session usage failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandCreate, 1) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicySessions(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	secret := []byte("super secret data")

	template := Public{
		Type:       ObjectTypeKeyedHash,
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent | AttrNoDA,
		AuthPolicy: make([]byte, 32),
		Params:     &PublicParamsU{KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
	sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	objectContext.SetAuthValue(testAuth)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSalted",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "BoundUnsalted",
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSalted",
			tpmKey:       primary,
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypePolicy, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			sc.SetAttrs(data.sessionAttrs)
			_, err = tpm.Unseal(objectContext, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, err = tpm.Unseal(objectContext, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent usage of the session failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandUnseal, 1) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
