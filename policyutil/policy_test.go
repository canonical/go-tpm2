// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type mockPolicyExecuteHelper struct {
	loadFn            func(tpm2.Name) (tpm2.ResourceContext, error)
	authorizeFn       func(tpm2.ResourceContext) (tpm2.SessionContext, error)
	signAuthorization func(*tpm2.Public, tpm2.Nonce, tpm2.Nonce) (*PolicyAuthorization, error)
}

func (h *mockPolicyExecuteHelper) Load(name tpm2.Name) (tpm2.ResourceContext, error) {
	if h.loadFn == nil {
		return nil, errors.New("not implemented")
	}
	return h.loadFn(name)
}

func (h *mockPolicyExecuteHelper) Authorize(resource tpm2.ResourceContext) (tpm2.SessionContext, error) {
	if h.authorizeFn == nil {
		return nil, errors.New("not implemented")
	}
	return h.authorizeFn(resource)
}

func (h *mockPolicyExecuteHelper) SignAuthorization(authKey *tpm2.Public, policyRef, nonceTPM tpm2.Nonce) (*PolicyAuthorization, error) {
	if h.signAuthorization == nil {
		return nil, errors.New("not implemented")
	}
	return h.signAuthorization(authKey, policyRef, nonceTPM)
}

type policySuite struct {
	testutil.TPMTest
}

func (s *policySuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&policySuite{})

type testExecutePolicyNVData struct {
	nvPub    *tpm2.NVPublic
	readAuth tpm2.ResourceContext
	contents []byte

	authSession tpm2.SessionContext

	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyNV(c *C, data *testExecutePolicyNVData) error {
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, data.nvPub)
	c.Assert(s.TPM.NVWrite(index, index, data.contents, 0, nil), IsNil)

	readAuth := data.readAuth
	if readAuth == nil {
		readAuth = index
	}

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNV(nvPub, data.operandB, data.offset, data.operation)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	sessionHandle := authSessionHandle(data.authSession)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var helper mockPolicyExecuteHelper
	helper.authorizeFn = func(resource tpm2.ResourceContext) (tpm2.SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, readAuth.Name())
		return data.authSession, nil
	}

	tickets, auths, err := policy.Execute(s.TPM, session, nil, &helper)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)
	if err != nil {
		return err
	}
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyNV)
	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicyNV(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:  internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperand(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:  internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:  internal_testutil.DecodeHexString(c, "00001001"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOffset(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:  internal_testutil.DecodeHexString(c, "0000000010000000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    2,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperation(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:  internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpUnsignedGT})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVFails(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:  internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Assert(err, internal_testutil.ConvertibleTo, &tpm2.TPMError{})
	c.Check(err.(*tpm2.TPMError), DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorPolicy})
}

func (s *policySuite) TestPolicyNVDifferentAuth(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		readAuth:  s.TPM.OwnerHandleContext(),
		contents:  internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithAuthSession(c *C) {
	authSession := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	handle := authSession.Handle()

	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:    internal_testutil.DecodeHexString(c, "0000000000001000"),
		authSession: authSession.WithAttrs(tpm2.AttrContinueSession),
		operandB:    internal_testutil.DecodeHexString(c, "00001000"),
		offset:      4,
		operation:   tpm2.OpEq})
	c.Check(err, IsNil)
	c.Check(s.TPM.DoesHandleExist(handle), internal_testutil.IsTrue)
}

func (s *policySuite) TestPolicyNVMissingIndex(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA | tpm2.AttrNVWritten),
		Size:    8}

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNV(nvPub, nil, 0, tpm2.OpEq)
	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, _, err = policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, ErrorMatches, "cannot create context for PolicyNV index: a resource at handle 0x0181f000 is not available on the TPM")
}

type testExecutePolicySecretData struct {
	authObject tpm2.ResourceContext
	policyRef  tpm2.Nonce
	params     *PolicyExecuteParams

	expectedCpHash     tpm2.Digest
	expectedExpiration int32

	authSession tpm2.SessionContext
}

func (s *policySuite) testPolicySecret(c *C, data *testExecutePolicySecretData) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySecret(data.authObject, data.policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	authObjectHandle := data.authObject.Handle()
	authObjectName := data.authObject.Name()
	sessionHandle := authSessionHandle(data.authSession)
	expectedFlush := false
	if authObjectHandle.Type() == tpm2.HandleTypeTransient {
		expectedFlush = true
	}

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var helper mockPolicyExecuteHelper
	helper.loadFn = func(name tpm2.Name) (tpm2.ResourceContext, error) {
		c.Check(name, DeepEquals, data.authObject.Name())
		return data.authObject, nil
	}
	helper.authorizeFn = func(resource tpm2.ResourceContext) (tpm2.SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, data.authObject.Name())
		return data.authSession, nil
	}

	tickets, auths, err := policy.Execute(s.TPM, session, data.params, &helper)
	if data.expectedExpiration < 0 {
		c.Assert(tickets, internal_testutil.LenEquals, 1)
		c.Check(tickets[0].AuthName, DeepEquals, authObjectName)
		c.Check(tickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(tickets[0].CpHash, DeepEquals, data.expectedCpHash)
		c.Check(tickets[0].Ticket.Tag, Equals, tpm2.TagAuthSecret)
		c.Check(tickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(tickets, internal_testutil.LenEquals, 0)
	}
	c.Check(auths, internal_testutil.LenEquals, 0)
	if err != nil {
		return err
	}

	var policyCommand *testutil.CommandRecordC
	if expectedFlush {
		commands := s.CommandLog()
		c.Assert(commands, internal_testutil.LenEquals, 2)
		policyCommand = commands[0]
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	} else {
		policyCommand = s.LastCommand(c)
	}
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicySecret)
	_, authArea, cpBytes := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	var nonceTPM tpm2.Nonce
	var cpHashA tpm2.Digest
	var policyRef tpm2.Nonce
	var expiration int32
	_, err = mu.UnmarshalFromBytes(cpBytes, &nonceTPM, &cpHashA, &policyRef, &expiration)
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, data.expectedCpHash)
	c.Check(expiration, Equals, data.expectedExpiration)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicySecret(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretNoPolicyRef(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext()})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithParams(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	cpHash := h.Sum(nil)

	params := &PolicySecretParams{
		AuthName:   s.TPM.OwnerHandleContext().Name(),
		PolicyRef:  []byte("foo"),
		CpHash:     CommandParameterDigest(tpm2.HashAlgorithmSHA256, cpHash),
		Expiration: 100}
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:         s.TPM.OwnerHandleContext(),
		policyRef:          params.PolicyRef,
		params:             &PolicyExecuteParams{SecretParams: []*PolicySecretParams{params}},
		expectedCpHash:     cpHash,
		expectedExpiration: params.Expiration})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNonMatchingParams1(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")

	params := &PolicySecretParams{
		AuthName:   s.TPM.OwnerHandleContext().Name(),
		CpHash:     CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil)),
		Expiration: 100}
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo"),
		params:     &PolicyExecuteParams{SecretParams: []*PolicySecretParams{params}}})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNonMatchingParams2(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")

	params := &PolicySecretParams{
		AuthName:   s.TPM.EndorsementHandleContext().Name(),
		PolicyRef:  []byte("foo"),
		CpHash:     CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil)),
		Expiration: 100}
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  params.PolicyRef,
		params:     &PolicyExecuteParams{SecretParams: []*PolicySecretParams{params}}})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithRequestedTicket(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	cpHash := h.Sum(nil)

	params := &PolicySecretParams{
		AuthName:   s.TPM.OwnerHandleContext().Name(),
		PolicyRef:  []byte("foo"),
		CpHash:     CommandParameterDigest(tpm2.HashAlgorithmSHA256, cpHash),
		Expiration: -200}
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:         s.TPM.OwnerHandleContext(),
		policyRef:          params.PolicyRef,
		params:             &PolicyExecuteParams{SecretParams: []*PolicySecretParams{params}},
		expectedCpHash:     cpHash,
		expectedExpiration: params.Expiration})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithSession(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:  s.TPM.OwnerHandleContext(),
		policyRef:   []byte("foo"),
		authSession: s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithWithTransient(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.CreateStoragePrimaryKeyRSA(c),
		policyRef:  []byte("foo")})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretFail(c *C) {
	s.TPM.OwnerHandleContext().SetAuthValue([]byte("1234"))

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Assert(err, internal_testutil.ConvertibleTo, &tpm2.TPMSessionError{})
	c.Check(err.(*tpm2.TPMSessionError), DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

func (s *policySuite) TestPolicySecretTicket(c *C) {
	authObject := s.TPM.OwnerHandleContext()
	policyRef := tpm2.Nonce("foo")

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySecret(authObject, policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var helper mockPolicyExecuteHelper
	helper.loadFn = func(name tpm2.Name) (tpm2.ResourceContext, error) {
		c.Check(name, DeepEquals, authObject.Name())
		return authObject, nil
	}
	helper.authorizeFn = func(resource tpm2.ResourceContext) (tpm2.SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, authObject.Name())
		return nil, nil
	}

	params := &PolicyExecuteParams{
		SecretParams: []*PolicySecretParams{{
			AuthName:   authObject.Name(),
			PolicyRef:  policyRef,
			Expiration: -1000}}}

	tickets, auths, err := policy.Execute(s.TPM, session, params, &helper)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)
	c.Check(auths, internal_testutil.LenEquals, 0)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params = &PolicyExecuteParams{Tickets: tickets}

	tickets, auths, err = policy.Execute(s.TPM, session, params, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)
	c.Check(tickets, DeepEquals, params.Tickets)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

type testExecutePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	params      *PolicyExecuteParams
	provideAuth bool

	signer          crypto.Signer
	includeNonceTPM bool
	cpHashA         tpm2.Digest
	expiration      int32
	signerOpts      crypto.SignerOpts
}

func (s *policySuite) testPolicySigned(c *C, data *testExecutePolicySignedData) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySigned(data.authKey, data.policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var savedAuth *PolicyAuthorization
	providedAuth := false

	var helper mockPolicyExecuteHelper
	helper.signAuthorization = func(authKey *tpm2.Public, policyRef, nonceTPM tpm2.Nonce) (*PolicyAuthorization, error) {
		c.Check(providedAuth, internal_testutil.IsFalse)
		c.Check(authKey, testutil.TPMValueDeepEquals, data.authKey)

		if !data.includeNonceTPM {
			nonceTPM = nil
		}
		auth, err := SignPolicyAuthorization(rand.Reader, data.signer, nonceTPM, data.cpHashA, policyRef, data.expiration, data.signerOpts)
		if err != nil {
			return nil, err
		}
		r := &PolicyAuthorization{
			AuthName:   authKey.Name(),
			PolicyRef:  policyRef,
			NonceTPM:   nonceTPM,
			CpHash:     data.cpHashA,
			Expiration: data.expiration,
			Signature:  auth}
		mu.MustCopyValue(&savedAuth, r)
		return r, nil
	}

	params := data.params
	if data.provideAuth {
		if params == nil {
			params = new(PolicyExecuteParams)
		}

		auth, err := helper.SignAuthorization(data.authKey, data.policyRef, session.NonceTPM())
		c.Assert(err, IsNil)
		params.Authorizations = append(params.Authorizations, auth)
		providedAuth = true
	}

	tickets, auths, err := policy.Execute(s.TPM, session, params, &helper)
	if data.expiration < 0 && err == nil {
		c.Assert(tickets, internal_testutil.LenEquals, 1)
		c.Check(tickets[0].AuthName, DeepEquals, data.authKey.Name())
		c.Check(tickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(tickets[0].CpHash, DeepEquals, data.cpHashA)
		c.Check(tickets[0].Ticket.Tag, Equals, tpm2.TagAuthSigned)
		c.Check(tickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(tickets, internal_testutil.LenEquals, 0)
	}
	if !data.includeNonceTPM && err == nil {
		c.Assert(auths, internal_testutil.LenEquals, 1)
		c.Check(auths[0], DeepEquals, savedAuth)
	} else {
		c.Check(auths, internal_testutil.LenEquals, 0)
	}
	if err != nil {
		return err
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicySigned(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:         pubKey,
		signer:          key,
		includeNonceTPM: true,
		signerOpts:      tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedIncludeTPMNonce(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "bar")

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    h.Sum(nil),
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		expiration: 100,
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithRequestedTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		expiration: -100,
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Assert(err, internal_testutil.ConvertibleTo, &tpm2.TPMParameterError{})
	c.Check(err.(*tpm2.TPMParameterError), DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySigned, Code: tpm2.ErrorSignature}, Index: 5})
}

func (s *policySuite) TestPolicySignedWithProvidedAuth(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:     pubKey,
		policyRef:   []byte("foo"),
		provideAuth: true,
		signer:      key,
		signerOpts:  tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithNonMatchingAuth(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:   pubKey,
		policyRef: []byte("foo"),
		params: &PolicyExecuteParams{
			Authorizations: []*PolicyAuthorization{
				{AuthName: pubKey.Name(), PolicyRef: []byte("bar")}}},
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySigned(authKey, nil)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var helper mockPolicyExecuteHelper
	helper.signAuthorization = func(authKey *tpm2.Public, policyRef, nonceTPM tpm2.Nonce) (*PolicyAuthorization, error) {
		c.Check(authKey, testutil.TPMValueDeepEquals, authKey)

		auth, err := SignPolicyAuthorization(rand.Reader, key, nonceTPM, nil, policyRef, -100, tpm2.HashAlgorithmSHA256)
		if err != nil {
			return nil, err
		}
		return &PolicyAuthorization{
			AuthName:   authKey.Name(),
			PolicyRef:  policyRef,
			NonceTPM:   nonceTPM,
			Expiration: -100,
			Signature:  auth}, nil
	}

	tickets, auths, err := policy.Execute(s.TPM, session, nil, &helper)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)
	c.Check(auths, internal_testutil.LenEquals, 0)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params := &PolicyExecuteParams{Tickets: tickets}

	tickets, auths, err = policy.Execute(s.TPM, session, params, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)
	c.Check(tickets, DeepEquals, params.Tickets)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyAuthValue(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyAuthValue()
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyAuthValue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) testPolicyCommandCode(c *C, code tpm2.CommandCode) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyCommandCode(code)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyCommandCodeNVChangeAuth(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandNVChangeAuth)
}

func (s *policySuite) TestPolicyCommandCodeUnseal(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandUnseal)
}

type testExecutePolicyCounterTimerData struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyCounterTimer(c *C, data *testExecutePolicyCounterTimerData) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	if err != nil {
		return err
	}
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicyCounterTimer1(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedGT})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimer2(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint32(0)))
	binary.BigEndian.PutUint32(operandB, timeInfo.ClockInfo.RestartCount)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    20,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimerFails(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedLT})
	c.Assert(err, internal_testutil.ConvertibleTo, &tpm2.TPMError{})
	c.Check(err.(*tpm2.TPMError), DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyCounterTimer, Code: tpm2.ErrorPolicy})
}

func (s *policySuite) testPolicyCpHash(c *C, cpHashA CpHash) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyCpHash(cpHashA)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyCpHash1(c *C) {
	s.testPolicyCpHash(c, CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())))
}

func (s *policySuite) TestPolicyCpHash2(c *C) {
	s.testPolicyCpHash(c, CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())))
}

func (s *policySuite) TestPolicyCpHashMultipleDigests(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyCpHash(CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())))
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[1].Digest())
}

func (s *policySuite) TestPolicyCpHashMissingDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	pc.RootBranch().PolicyCpHash(CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())))
	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, _, err = policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, ErrorMatches, "no digest for session algorithm available for PolicyCpHash assertion")
}

func (s *policySuite) testPolicyNameHash(c *C, nameHash NameHash) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNameHash(nameHash)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyNameHash1(c *C) {
	s.testPolicyNameHash(c, CommandHandles(tpm2.Name{0x40, 0x00, 0x00, 0x01}))
}

func (s *policySuite) TestPolicyNameHash2(c *C) {
	s.testPolicyNameHash(c, CommandHandles(tpm2.Name{0x40, 0x00, 0x00, 0x0b}))
}

func (s *policySuite) TestPolicyNameHashMultipleDigests(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNameHash(CommandHandles(tpm2.Name{0x40, 0x00, 0x00, 0x01}))
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[1].Digest())
}

func (s *policySuite) TestPolicyNameHashMissingDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	pc.RootBranch().PolicyNameHash(CommandHandles(tpm2.Name{0x40, 0x00, 0x00, 0x01}))
	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, _, err = policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, ErrorMatches, "no digest for session algorithm available for PolicyNameHash assertion")
}

func (s *policySuite) testPolicyPCR(c *C, values tpm2.PCRValues) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyPCR(values)
	expectedDigests, policy, err := pc.Policy()

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	if err != nil {
		return err
	}
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicyPCR(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRDifferentDigestAndSelection(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRFails(c *C) {
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	err := s.testPolicyPCR(c, values)
	c.Assert(err, internal_testutil.ConvertibleTo, &tpm2.TPMParameterError{})
	c.Check(err.(*tpm2.TPMParameterError), DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})
}

type testExecutePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool
}

func (s *policySuite) testPolicyDuplicationSelect(c *C, data *testExecutePolicyDuplicationSelectData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: false})
}

func (s *policySuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyPassword(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyPassword()
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyPassword)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) testPolicyNvWritten(c *C, writtenSet bool) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNvWritten(writtenSet)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, auths, err := policy.Execute(s.TPM, session, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	c.Check(auths, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, false)
}

func (s *policySuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, true)
}
