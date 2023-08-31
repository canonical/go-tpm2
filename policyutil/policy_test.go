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

type mockSessionContext struct {
	session tpm2.SessionContext
	closed  bool
}

func (c *mockSessionContext) Session() tpm2.SessionContext {
	return c.session
}

func (c *mockSessionContext) Close() error {
	c.closed = true
	return nil
}

type mockPolicyResourceAuthorizer struct {
	authorizeFn func(tpm2.ResourceContext) (SessionContext, error)
}

func (h *mockPolicyResourceAuthorizer) NeedAuthorize(resource tpm2.ResourceContext, sessionType tpm2.SessionType) (SessionContext, error) {
	if h.authorizeFn == nil {
		return nil, errors.New("not implemented")
	}
	if sessionType != tpm2.SessionTypeHMAC {
		return nil, errors.New("unexpected session type")
	}
	return h.authorizeFn(resource)
}

type policySuiteNoTPM struct{}

var _ = Suite(&policySuiteNoTPM{})

func (s *policySuiteNoTPM) testMarshalUnmarshalPolicyBranchName(c *C, name PolicyBranchName, expected []byte) {
	b, err := mu.MarshalToBytes(name)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, expected)
	c.Logf("%x", b)

	var recoveredName PolicyBranchName
	_, err = mu.UnmarshalFromBytes(b, &recoveredName)
	c.Check(recoveredName, Equals, name)
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName1(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "foo", []byte{0x00, 0x03, 0x66, 0x6f, 0x6f})
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName2(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "bar", []byte{0x00, 0x03, 0x62, 0x61, 0x72})
}

func (s *policySuiteNoTPM) TestMarshalInvalidPolicyBranchName(c *C) {
	_, err := mu.MarshalToBytes(PolicyBranchName("$foo"))
	c.Check(err, ErrorMatches, `cannot marshal argument 0 whilst processing element of type policyutil.PolicyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestUnmarshalInvalidPolicyBranchName(c *C) {
	var name PolicyBranchName
	_, err := mu.UnmarshalFromBytes([]byte{0x00, 0x04, 0x24, 0x66, 0x6f, 0x6f}, &name)
	c.Check(err, ErrorMatches, `cannot unmarshal argument 0 whilst processing element of type policyutil.PolicyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponent(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLeadingSeparator(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLast(c *C) {
	path := PolicyBranchPath("bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("bar"))
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentEmpty(c *C) {
	path := PolicyBranchPath("")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath(""))
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleLeadingSeparators(c *C) {
	path := PolicyBranchPath("///foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleIntermediateSeparators(c *C) {
	path := PolicyBranchPath("foo////bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("///bar"))
}

func (s *policySuiteNoTPM) TestPolicyValidate(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	validatedDigest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(validatedDigest, DeepEquals, digests[0].Digest())
}

func (s *policySuiteNoTPM) TestPolicyValidateWithBranches(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	digests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	validatedDigest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(validatedDigest, DeepEquals, digests[0].Digest())
}

func (s *policySuiteNoTPM) TestPolicyValidateWithMultipleBranchNodes(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := pc.RootBranch().AddBranchNode(true)
	c.Assert(node1, NotNil)

	b1 := node1.AddBranch("")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := pc.RootBranch().AddBranchNode(true)
	c.Assert(node2, NotNil)

	b3 := node2.AddBranch("")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("")
	c.Check(b4.PolicyCommandCode(tpm2.CommandObjectChangeAuth), IsNil)

	digests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	validatedDigest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(validatedDigest, DeepEquals, digests[0].Digest())
}

func (s *policySuiteNoTPM) TestPolicyValidateMissingDigests(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	c.Check(pc.RootBranch().PolicyCpHash(CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))), IsNil)
	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicyCpHash assertion: missing digest for session algorithm`)
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)
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
	var authSession *mockSessionContext

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, readAuth.Name())
		if data.authSession == nil {
			return nil, nil
		}
		authSession = &mockSessionContext{session: data.authSession}
		return authSession, nil
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, NewTPMResourceLoader(s.TPM, nil, &authorizer), nil)
	c.Check(tickets, internal_testutil.LenEquals, 0)
	if err != nil {
		return err
	}

	commands := s.CommandLog()
	if data.authSession != nil {
		c.Check(authSession.closed, internal_testutil.IsTrue)
	}

	c.Assert(commands, internal_testutil.LenGreaterEquals, 1)
	policyCommand := commands[len(commands)-1]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicyNV)
	_, authArea, _ := policyCommand.UnmarshalCommand(c)
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
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicyNV assertion: TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var e *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorPolicy})
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
}

type testExecutePolicySecretData struct {
	authObject Named
	policyRef  tpm2.Nonce
	params     *PolicyExecuteParams
	resources  *Resources

	expectedCpHash     tpm2.Digest
	expectedExpiration int32

	expectedFlush bool

	authSession tpm2.SessionContext
}

func (s *policySuite) testPolicySecret(c *C, data *testExecutePolicySecretData) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySecret(data.authObject, data.policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	sessionHandle := authSessionHandle(data.authSession)
	var authSession *mockSessionContext

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var authObjectHandle tpm2.Handle
	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, data.authObject.Name())
		authObjectHandle = resource.Handle()
		if data.authSession == nil {
			return nil, nil
		}
		authSession = &mockSessionContext{session: data.authSession}
		return authSession, nil
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), data.params, NewTPMResourceLoader(s.TPM, data.resources, &authorizer), nil)
	if data.expectedExpiration < 0 {
		c.Assert(tickets, internal_testutil.LenEquals, 1)
		c.Check(tickets[0].AuthName, DeepEquals, data.authObject.Name())
		c.Check(tickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(tickets[0].CpHash, DeepEquals, data.expectedCpHash)
		c.Check(tickets[0].Ticket.Tag, Equals, tpm2.TagAuthSecret)
		c.Check(tickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(tickets, internal_testutil.LenEquals, 0)
	}
	if err != nil {
		return err
	}

	commands := s.CommandLog()
	numCommands := 1
	if data.expectedFlush {
		numCommands += 1
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	} else {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsTrue)
	}
	if data.authSession != nil {
		c.Check(authSession.closed, internal_testutil.IsTrue)
	}

	c.Assert(commands, internal_testutil.LenGreaterEquals, numCommands)
	policyCommand := commands[len(commands)-numCommands]
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
	object := s.CreateStoragePrimaryKeyRSA(c)
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: object,
		policyRef:  []byte("foo"),
		resources:  &Resources{Loaded: []tpm2.ResourceContext{object}}})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithWithTransientSaved(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	saved, err := SaveAndFlushResource(s.TPM, object)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:    saved.Name,
		policyRef:     []byte("foo"),
		resources:     &Resources{Saved: []*SavedResource{saved}},
		expectedFlush: true})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithWithTransientLoadable(c *C) {
	parent := s.CreateStoragePrimaryKeyRSA(c)
	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySecret(pub, []byte("foo"))
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	parentHandle := parent.Handle()

	authorizations := 0
	var authObjectHandle tpm2.Handle
	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		switch authorizations {
		case 0:
			c.Check(resource.Name(), DeepEquals, parent.Name())
		case 1:
			c.Check(resource.Name(), DeepEquals, pub.Name())
			authObjectHandle = resource.Handle()
		default:
			return nil, errors.New("unexpected")
		}
		authorizations += 1
		return nil, nil
	}

	resources := &Resources{
		Loaded: []tpm2.ResourceContext{parent},
		Unloaded: []*LoadableResource{
			{
				ParentName: parent.Name(),
				Private:    priv,
				Public:     pub,
			},
		},
	}
	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, NewTPMResourceLoader(s.TPM, resources, &authorizer), nil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesHandleExist(parentHandle), internal_testutil.IsTrue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicySecretFail(c *C) {
	s.TPM.OwnerHandleContext().SetAuthValue([]byte("1234"))

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicySecret assertion: authorization failed for assertion with authName=0x40000001, policyRef=0x666f6f: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)`)
	var ae *AuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, s.TPM.OwnerHandleContext().Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMSessionError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

func (s *policySuite) TestPolicySecretMissingResource(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	saved, err := SaveAndFlushResource(s.TPM, object)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: saved.Name,
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicySecret assertion: cannot load resource with name 0x([[:xdigit:]]{68}): cannot identify resource`)

	var rle *ResourceLoadError
	c.Check(err, internal_testutil.ErrorAs, &rle)
	c.Check(rle.Name, DeepEquals, saved.Name)
}

func (s *policySuite) TestPolicySecretTicket(c *C) {
	authObject := s.TPM.OwnerHandleContext()
	policyRef := tpm2.Nonce("foo")

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySecret(authObject, policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		c.Check(resource.Name(), DeepEquals, authObject.Name())
		return nil, nil
	}

	params := &PolicyExecuteParams{
		SecretParams: []*PolicySecretParams{{
			AuthName:   authObject.Name(),
			PolicyRef:  policyRef,
			Expiration: -1000}}}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, &authorizer), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params = &PolicyExecuteParams{Tickets: tickets}

	tickets, err = policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, &authorizer), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

type testExecutePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	params *PolicyExecuteParams

	signer          crypto.Signer
	includeNonceTPM bool
	cpHashA         CpHash
	expiration      int32
	signerOpts      crypto.SignerOpts
}

func (s *policySuite) testPolicySigned(c *C, data *testExecutePolicySignedData) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicySigned(data.authKey, data.policyRef)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var nonceTPM tpm2.Nonce
	if data.includeNonceTPM {
		nonceTPM = session.NonceTPM()
	}

	auth, err := NewPolicySignedAuthorization(session.HashAlg(), nonceTPM, data.cpHashA, data.expiration)
	c.Assert(err, IsNil)
	c.Check(auth.Sign(rand.Reader, data.authKey, data.policyRef, data.signer, data.signerOpts), IsNil)

	var params *PolicyExecuteParams
	if data.params != nil {
		params = &(*data.params)
	}
	if params == nil {
		params = new(PolicyExecuteParams)
	}

	params.SignedAuthorizations = append(params.SignedAuthorizations, auth)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, nil), nil)
	if data.expiration < 0 && err == nil {
		expectedCpHash, err := data.cpHashA.Digest(session.HashAlg())
		c.Check(err, IsNil)

		c.Assert(tickets, internal_testutil.LenEquals, 1)
		c.Check(tickets[0].AuthName, DeepEquals, data.authKey.Name())
		c.Check(tickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(tickets[0].CpHash, DeepEquals, expectedCpHash)
		c.Check(tickets[0].Ticket.Tag, Equals, tpm2.TagAuthSigned)
		c.Check(tickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(tickets, internal_testutil.LenEquals, 0)
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

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
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
		signer:     key,
		expiration: 100,
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
		signer:     key,
		cpHashA:    CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expiration: -100,
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
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicySigned assertion: `+
		`authorization failed for assertion with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 5 whilst executing command TPM_CC_PolicySigned: TPM_RC_SIGNATURE \(the signature is not valid\)`)
	var ae *AuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySigned, Code: tpm2.ErrorSignature}, Index: 5})
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
			SignedAuthorizations: []*PolicySignedAuthorization{
				{
					Authorization: &PolicyAuthorization{
						AuthKey:   pubKey,
						PolicyRef: []byte("bar"),
					},
				},
			},
		},
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

	auth, err := NewPolicySignedAuthorization(session.HashAlg(), session.NonceTPM(), nil, -100)
	c.Assert(err, IsNil)
	c.Check(auth.Sign(rand.Reader, authKey, nil, key, tpm2.HashAlgorithmSHA256), IsNil)

	params := &PolicyExecuteParams{SignedAuthorizations: []*PolicySignedAuthorization{auth}}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, nil), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 1)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params = &PolicyExecuteParams{Tickets: tickets}

	tickets, err = policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, nil), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())

	return nil
}

func (s *policySuite) TestPolicyCounterTimer1(c *C) {
	c.Skip("test fails in github")

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
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicyCounterTimer assertion: TPM returned an error whilst executing command TPM_CC_PolicyCounterTimer: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var e *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyCounterTimer, Code: tpm2.ErrorPolicy})
}

func (s *policySuite) testPolicyCpHash(c *C, cpHashA CpHash) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyCpHash(cpHashA)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	_, err = policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, ErrorMatches, "cannot process TPM2_PolicyCpHash assertion: missing digest for session algorithm")
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)
}

func (s *policySuite) testPolicyNameHash(c *C, nameHash NameHash) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyNameHash(nameHash)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	_, err = policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, ErrorMatches, "cannot process TPM2_PolicyNameHash assertion: missing digest for session algorithm")
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)
}

type testExecutePolicyORData struct {
	alg tpm2.HashAlgorithmId
}

func (s *policySuite) testPolicyOR(c *C, pHashList tpm2.DigestList) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)), IsNil)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyOR(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(err, IsNil)

	pHashList := tpm2.DigestList{digests[0].Digest()}
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	pHashList = append(pHashList, h.Sum(nil))

	s.testPolicyOR(c, pHashList)
}

func (s *policySuite) TestPolicyORDifferentHashList(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(err, IsNil)

	var pHashList tpm2.DigestList
	for _, data := range []string{"foo", "bar"} {
		h := crypto.SHA256.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}
	pHashList = append(pHashList, digests[0].Digest())

	s.testPolicyOR(c, pHashList)
}

func (s *policySuite) TestPolicyORMultipleDigests(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(err, IsNil)

	pHashListSHA1 := tpm2.DigestList{digests[0].Digest()}
	pHashListSHA256 := tpm2.DigestList{digests[1].Digest()}
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	pHashListSHA1 = append(pHashListSHA1, h.Sum(nil))
	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	pHashListSHA256 = append(pHashListSHA256, h.Sum(nil))

	pc = ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashListSHA256), NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashListSHA1)), IsNil)
	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[1].Digest())
}

func (s *policySuite) TestPolicyORMissingDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(err, IsNil)

	pHashList := tpm2.DigestList{digests[0].Digest()}
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	pHashList = append(pHashList, h.Sum(nil))

	pc = ComputePolicy(tpm2.HashAlgorithmSHA1)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashList)), IsNil)
	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicyOR assertion: cannot process digest at index 0: missing digest for session algorithm`)
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)
}

type testExecutePolicyBranchesData struct {
	usage *PolicySessionUsage
	path  PolicyBranchPath
	cmd   tpm2.CommandCode
}

func (s *policySuite) testPolicyBranches(c *C, data *testExecutePolicyBranchesData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}
	authorizer := &mockPolicyResourceAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) (SessionContext, error) {
			return nil, nil
		},
	}

	s.ForgetCommands()

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, authorizer), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, 4)
	c.Check(log[0].GetCommandCode(c), Equals, tpm2.CommandPolicyNvWritten)
	c.Check(log[1].GetCommandCode(c), Equals, data.cmd)
	c.Check(log[2].GetCommandCode(c), Equals, tpm2.CommandPolicyOR)
	c.Check(log[3].GetCommandCode(c), Equals, tpm2.CommandPolicyCommandCode)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyBranches(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch1",
		cmd:  tpm2.CommandPolicyAuthValue})
}

func (s *policySuite) TestPolicyBranchesNumericSelector(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "$[0]",
		cmd:  tpm2.CommandPolicyAuthValue})
}

func (s *policySuite) TestPolicyBranchesDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch2",
		cmd:  tpm2.CommandPolicySecret})
}

func (s *policySuite) TestPolicyBranchesNumericSelectorDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "$[1]",
		cmd:  tpm2.CommandPolicySecret})
}

func (s *policySuite) TestPolicyBranchAutoSelectNoUsage(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		cmd: tpm2.CommandPolicyAuthValue})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsage(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandHierarchyChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")).CanUseAuthValue(),
		cmd:   tpm2.CommandPolicyAuthValue})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsageDifferentBranch(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandHierarchyChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")),
		cmd:   tpm2.CommandPolicySecret})
}

func (s *policySuite) TestPolicyBranchesMultipleDigests(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[1].Digest())
}

type testExecutePolicyBranchesMultipleNodesData struct {
	usage *PolicySessionUsage
	path  PolicyBranchPath
	cmd1  tpm2.CommandCode
	cmd2  tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesMultipleNodes(c *C, data *testExecutePolicyBranchesMultipleNodesData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := pc.RootBranch().AddBranchNode(true)

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := pc.RootBranch().AddBranchNode(true)

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("branch4")
	c.Check(b4.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		return nil, nil
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, &authorizer), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, 5)
	c.Check(log[0].GetCommandCode(c), Equals, tpm2.CommandPolicyNvWritten)
	c.Check(log[1].GetCommandCode(c), Equals, data.cmd1)
	c.Check(log[2].GetCommandCode(c), Equals, tpm2.CommandPolicyOR)
	c.Check(log[3].GetCommandCode(c), Equals, tpm2.CommandPolicyCommandCode)
	c.Check(log[4].GetCommandCode(c), Equals, tpm2.CommandPolicyOR)

	_, _, cpBytes := log[3].UnmarshalCommand(c)

	var commandCode tpm2.CommandCode
	_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
	c.Check(err, IsNil)
	c.Check(commandCode, Equals, data.cmd2)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyBranchesMultipleNodes1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch3",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesNumericSelectors(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "$[0]/$[0]",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch4",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandHierarchyChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch2/branch4",
		cmd1: tpm2.CommandPolicySecret,
		cmd2: tpm2.CommandHierarchyChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")).CanUseAuthValue(),
		cmd1:  tpm2.CommandPolicyAuthValue,
		cmd2:  tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")),
		cmd1:  tpm2.CommandPolicySecret,
		cmd2:  tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandHierarchyChangeAuth, []Named{tpm2.MakeHandleName(tpm2.HandleOwner)}, tpm2.Auth("foo")),
		cmd1:  tpm2.CommandPolicySecret,
		cmd2:  tpm2.CommandHierarchyChangeAuth})
}

type testExecutePolicyBranchesEmbeddedNodesData struct {
	usage *PolicySessionUsage
	path  PolicyBranchPath
	cmd1  tpm2.CommandCode
	cmd2  tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesEmbeddedNodes(c *C, data *testExecutePolicyBranchesEmbeddedNodesData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := pc.RootBranch().AddBranchNode(true)

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	node2 := b1.AddBranchNode(true)

	b2 := node2.AddBranch("branch2")
	c.Check(b2.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

	b4 := node1.AddBranch("branch4")
	c.Check(b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node3 := b4.AddBranchNode(true)

	b5 := node3.AddBranch("branch5")
	c.Check(b5.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b6 := node3.AddBranch("branch6")
	c.Check(b6.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	var authorizer mockPolicyResourceAuthorizer
	authorizer.authorizeFn = func(resource tpm2.ResourceContext) (SessionContext, error) {
		return nil, nil
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, NewTPMResourceLoader(s.TPM, nil, &authorizer), nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, 5)
	c.Check(log[0].GetCommandCode(c), Equals, tpm2.CommandPolicyNvWritten)
	c.Check(log[1].GetCommandCode(c), Equals, data.cmd1)
	c.Check(log[2].GetCommandCode(c), Equals, tpm2.CommandPolicyCommandCode)
	c.Check(log[3].GetCommandCode(c), Equals, tpm2.CommandPolicyOR)
	c.Check(log[4].GetCommandCode(c), Equals, tpm2.CommandPolicyOR)

	_, _, cpBytes := log[2].UnmarshalCommand(c)

	var commandCode tpm2.CommandCode
	_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
	c.Check(err, IsNil)
	c.Check(commandCode, Equals, data.cmd2)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch2",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesNumericSelectors(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "$[0]/$[0]",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch3",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandHierarchyChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch5",
		cmd1: tpm2.CommandPolicySecret,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes4(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch6",
		cmd1: tpm2.CommandPolicySecret,
		cmd2: tpm2.CommandHierarchyChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneNoUsage1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1",
		cmd1: tpm2.CommandPolicyAuthValue,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneNoUsage2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4",
		cmd1: tpm2.CommandPolicySecret,
		cmd2: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")).CanUseAuthValue(),
		cmd1:  tpm2.CommandPolicyAuthValue,
		cmd2:  tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{make(tpm2.Name, 32)}, tpm2.Auth("foo")),
		cmd1:  tpm2.CommandPolicySecret,
		cmd2:  tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandHierarchyChangeAuth, []Named{tpm2.MakeHandleName(tpm2.HandleOwner)}, tpm2.Auth("foo")),
		cmd1:  tpm2.CommandPolicySecret,
		cmd2:  tpm2.CommandHierarchyChangeAuth})
}

func (s *policySuite) TestPolicyBranchesSelectorOutOfRange(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "$[2]",
	}

	_, err = policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, ErrorMatches, `cannot process branch node: cannot select branch: selected path 2 out of range`)
}

func (s *policySuite) TestPolicyBranchesInvalidSelector(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "$foo",
	}

	_, err = policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, ErrorMatches, `cannot process branch node: cannot select branch: badly formatted path component "\$foo": input does not match format`)
}

func (s *policySuite) TestPolicyBranchesBranchNotFound(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "foo",
	}

	_, err = policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, ErrorMatches, `cannot process branch node: cannot select branch: no branch with name "foo"`)
}

func (s *policySuite) TestPolicyBranchesComputeMissingBranchDigests1(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "7dd279d84a51aee7d2a5b19f0c9d9eb275015347bf98158a65612831cf4352d5")))
}

func (s *policySuite) TestPolicyBranchesComputeMissingBranchDigests2(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode(false)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), params, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuite) testPolicyPCR(c *C, values tpm2.PCRValues) error {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	pc.RootBranch().PolicyPCR(values)
	expectedDigests, policy, err := pc.Policy()

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(tickets, internal_testutil.LenEquals, 0)

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
	c.Check(err, ErrorMatches, `cannot process TPM2_PolicyPCR assertion: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyPCR: TPM_RC_VALUE \(value is out of range or is not correct for the context\)`)
	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})
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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

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

type policySuitePCR struct {
	testutil.TPMTest
}

func (s *policySuitePCR) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV | testutil.TPMFeaturePCR
}

var _ = Suite(&policySuitePCR{})

func (s *policySuitePCR) TestPolicyBranchesAutoSelected(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}}), IsNil)

	b2 := node.AddBranch("")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicyPCR(pcrValues), IsNil)

	expectedDigests, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	tickets, err := policy.Execute(NewTPMSession(s.TPM, session), nil, nil, NewTPMState(s.TPM))
	c.Check(err, IsNil)
	c.Check(tickets, internal_testutil.LenEquals, 0)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigests[0].Digest())
}

func (s *policySuitePCR) TestPolicyBranchesAutoSelectFail(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)

	node := pc.RootBranch().AddBranchNode(true)
	c.Assert(node, NotNil)

	b1 := node.AddBranch("")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}}), IsNil)

	b2 := node.AddBranch("")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicyPCR(pcrValues), IsNil)

	_, policy, err := pc.Policy()
	c.Assert(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = policy.Execute(NewTPMSession(s.TPM, session), nil, nil, NewTPMState(s.TPM))
	c.Check(err, ErrorMatches, `cannot process auto select branch: cannot select branch: no appropriate branches`)
}
