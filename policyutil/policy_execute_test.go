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
	"fmt"
	"io"
	"strings"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type policyExecuteSuite struct {
	testutil.TPMTest
}

func (s *policyExecuteSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&policyExecuteSuite{})

type testExecutePolicyNVData struct {
	nvPub      *tpm2.NVPublic
	readAuth   tpm2.ResourceContext
	readPolicy *Policy
	contents   []byte

	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp

	expectedCommands    int
	expectedAuthorize   bool
	expectedSessionType tpm2.HandleType
}

func (s *policyExecuteSuite) testPolicyNV(c *C, data *testExecutePolicyNVData) error {
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, data.nvPub)
	c.Assert(s.TPM.NVWrite(index, index, data.contents, 0, nil), IsNil)

	readAuth := data.readAuth
	if readAuth == nil {
		readAuth = index
	}

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNV(nvPub, data.operandB, data.offset, data.operation)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var resources *PolicyResourcesData
	if data.readPolicy != nil {
		resources = &PolicyResourcesData{
			Persistent: []PersistentResource{
				{Name: readAuth.Name(), Handle: readAuth.Handle(), Policy: data.readPolicy},
			},
		}
	}

	authorized := false
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			authorized = true
			if !data.expectedAuthorize {
				resource.SetAuthValue([]byte("1234"))
			} else {
				c.Check(resource.Name(), DeepEquals, readAuth.Name())
			}
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(authorized, Equals, data.expectedAuthorize)

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-2]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicyNV)
	_, authArea, _ := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicyNV(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVDifferentOperand(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001001"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVDifferentOffset(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000010000000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              2,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVDifferentOperation(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpUnsignedGT,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVFails(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:             nvPub,
		contents:          internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:          internal_testutil.DecodeHexString(c, "00001000"),
		offset:            4,
		operation:         tpm2.OpEq,
		expectedAuthorize: true,
	})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var e *tpm2.TPMError
	c.Assert(ne, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorPolicy})
}

func (s *policyExecuteSuite) TestPolicyNVDifferentAuth(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		readAuth:            s.TPM.OwnerHandleContext(),
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    8,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVWithPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVWithPolicySessionRequiresAuth(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    8,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVMissingPolicy(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:     nvPub,
		contents:  internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`cannot authorize resource with name 0x([[:xdigit:]]{68}): no auth types available`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var re *ResourceAuthorizeError
	c.Assert(err, internal_testutil.ErrorAs, &re)
	c.Check(re.Name, DeepEquals, nvPub.Name())
}

func (s *policyExecuteSuite) TestPolicyNVPrefersPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyNVWithSubPolicyError(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), nil)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:               nvPub,
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`cannot authorize resource with name 0x([[:xdigit:]]{68}): `+
		`cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x40000001, policyRef=: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \+ TPM_RC_S \+ TPM_RC_1 \(authorization failure without DA implications\)`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var rae *ResourceAuthorizeError
	c.Assert(ne, internal_testutil.ErrorAs, &rae)
	c.Check(rae.Name, DeepEquals, nvPub.Name())

	c.Assert(rae, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var se *tpm2.TPMSessionError
	c.Assert(pe, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

type testExecutePolicySecretData struct {
	authObject Named
	policyRef  tpm2.Nonce
	resources  *PolicyResourcesData

	expectedFlush       bool
	expectedCommands    int
	expectedAuth        int
	expectedSessionType tpm2.HandleType
}

func (s *policyExecuteSuite) testPolicySecret(c *C, data *testExecutePolicySecretData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(data.authObject, data.policyRef)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	nAuths := 0
	var authObjectHandle tpm2.Handle
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			if nAuths == data.expectedAuth {
				c.Check(resource.Name(), DeepEquals, data.authObject.Name())
				authObjectHandle = resource.Handle()
			}
			nAuths++
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, data.resources, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(authObjectHandle, Not(Equals), tpm2.Handle(0))

	offsetEnd := 2
	if data.expectedFlush {
		offsetEnd++
	}

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-offsetEnd]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicySecret)
	_, authArea, cpBytes := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	var nonceTPM tpm2.Nonce
	var cpHashA tpm2.Digest
	var policyRef tpm2.Nonce
	var expiration int32
	_, err = mu.UnmarshalFromBytes(cpBytes, &nonceTPM, &cpHashA, &policyRef, &expiration)
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(nil))
	c.Check(expiration, Equals, int32(0))

	if data.expectedFlush {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	} else {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsTrue)
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicySecret(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		policyRef:           []byte("foo"),
		expectedCommands:    8,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretNoPolicyRef(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		expectedCommands:    8,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithTransientLoadRequiresPolicy(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandLoad)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	template := testutil.NewRSAStorageKeyTemplate()
	template.AuthPolicy = policyDigest

	parent := s.CreatePrimary(c, tpm2.HandleOwner, template)
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
					Policy: policy,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    15,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithTransientPolicySession(c *C) {
	parent := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAStorageKeyTemplate())
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	template := objectutil.NewRSAStorageKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
		objectutil.WithUserAuthMode(objectutil.RequirePolicy),
		objectutil.WithAuthPolicy(policyDigest),
	)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, template, nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
					Policy:     policy,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    15,
		expectedAuth:        1,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithTransient(c *C) {
	parent := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAStorageKeyTemplate())
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    14,
		expectedAuth:        1,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretFail(c *C) {
	s.TPM.OwnerHandleContext().SetAuthValue([]byte("1234"))

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x40000001, policyRef=0x666f6f: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \+ TPM_RC_S \+ TPM_RC_1 \(authorization failure without DA implications\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, s.TPM.OwnerHandleContext().Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMSessionError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

func (s *policyExecuteSuite) TestPolicySecretMissingResource(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: object.Name(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: cannot load resource with name 0x([[:xdigit:]]{68}): resource not found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, object.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var rle *ResourceLoadError
	c.Check(err, internal_testutil.ErrorAs, &rle)
	c.Check(rle.Name, DeepEquals, object.Name())
}

func (s *policyExecuteSuite) TestPolicySecretWithNV(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          nvPub,
		policyRef:           []byte("foo"),
		expectedCommands:    11,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithNVPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    10,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithNVPreferHMACSession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    9,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySecretWithNVMissingPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, _, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x000b2ce1bec1b93901ee1e39517612a216fe496c26fa595fd5cf4149ff8f225e6aa9, policyRef=0x666f6f: `+
		`cannot authorize resource with name 0x000b2ce1bec1b93901ee1e39517612a216fe496c26fa595fd5cf4149ff8f225e6aa9: no auth types available`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, nvPub.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var re *ResourceAuthorizeError
	c.Assert(err, internal_testutil.ErrorAs, &re)
	c.Check(re.Name, DeepEquals, nvPub.Name())
}

type testExecutePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	signer            crypto.Signer
	includeNonceTPM   bool
	cpHashA           tpm2.Digest
	expiration        int32
	signerOpts        crypto.SignerOpts
	externalSensitive *tpm2.Sensitive
}

func (s *policyExecuteSuite) testPolicySigned(c *C, data *testExecutePolicySignedData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySigned(data.authKey, data.policyRef)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionAlg, Equals, session.Params().HashAlg)
			c.Check(sessionNonce, DeepEquals, session.State().NonceTPM)
			c.Check(authKey, DeepEquals, data.authKey.Name())
			c.Check(policyRef, DeepEquals, data.policyRef)

			var cpHash CpHash
			if len(data.cpHashA) > 0 {
				cpHash = CommandParameterDigest(tpm2.HashAlgorithmSHA256, data.cpHashA)
			}
			return SignPolicySignedAuthorization(rand.Reader, &PolicySignedParams{
				HashAlg:    tpm2.HashAlgorithmSHA256,
				NonceTPM:   sessionNonce,
				CpHash:     cpHash,
				Expiration: data.expiration,
			}, data.authKey, policyRef, data.signer, data.signerOpts)
		},
	}
	externalSensitiveResources := &mockExternalSensitiveResources{
		externalSensitive: func(name tpm2.Name) (*tpm2.Sensitive, error) {
			c.Check(data.externalSensitive, NotNil)
			c.Check(name, DeepEquals, data.authKey.Name())
			return data.externalSensitive, nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{SignedAuthorizer: authorizer, ExternalSensitiveResources: externalSensitiveResources}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	if data.expiration < 0 && err == nil {
		c.Assert(result.NewTickets, internal_testutil.LenEquals, 1)
		c.Check(result.NewTickets[0].AuthName, DeepEquals, data.authKey.Name())
		c.Check(result.NewTickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(result.NewTickets[0].CpHash, DeepEquals, data.cpHashA)
		c.Check(result.NewTickets[0].Ticket.Tag, Equals, tpm2.TagAuthSigned)
		c.Check(result.NewTickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	}
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	if len(data.cpHashA) > 0 {
		cpHash, set := result.CpHash()
		c.Check(set, internal_testutil.IsTrue)
		c.Check(cpHash, DeepEquals, data.cpHashA)
	} else {
		_, set = result.CpHash()
		c.Check(set, internal_testutil.IsFalse)
	}
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicySigned(c *C) {
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

func (s *policyExecuteSuite) TestPolicySignedNoPolicyRef(c *C) {
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

func (s *policyExecuteSuite) TestPolicySignedIncludeTPMNonce(c *C) {
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

func (s *policyExecuteSuite) TestPolicySignedWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    cpHashA,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySignedWithExpiration(c *C) {
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

func (s *policyExecuteSuite) TestPolicySignedWithRequestedTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    cpHashA,
		expiration: -100,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySignedHMAC(c *C) {
	hmacKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, hmacKey)
	c.Assert(err, IsNil)

	pubKey, sensitive, err := objectutil.NewHMACKey(rand.Reader, hmacKey, nil, objectutil.WithoutDictionaryAttackProtection())
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:           pubKey,
		policyRef:         []byte("foo"),
		signer:            cryptutil.HMACKey(hmacKey),
		signerOpts:        crypto.SHA256,
		externalSensitive: sensitive,
	})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicySignedWithInvalidSignature(c *C) {
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
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySigned assertion' task in root branch: `+
		`cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 5 whilst executing command TPM_CC_PolicySigned: TPM_RC_SIGNATURE \+ TPM_RC_P \+ TPM_RC_5 \(the signature is not valid\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySigned, Code: tpm2.ErrorSignature}, Index: 5})
}

func (s *policyExecuteSuite) TestPolicySignedWithTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySigned(authKey, nil)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKeyName tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionAlg, Equals, session.Params().HashAlg)
			c.Check(sessionNonce, DeepEquals, session.State().NonceTPM)
			c.Check(authKeyName, DeepEquals, authKey.Name())
			c.Check(policyRef, IsNil)

			return SignPolicySignedAuthorization(rand.Reader, &PolicySignedParams{
				NonceTPM:   sessionNonce,
				Expiration: -100,
			}, authKey, policyRef, key, tpm2.HashAlgorithmSHA256)
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{SignedAuthorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 1)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params := &PolicyExecuteParams{Tickets: result.NewTickets}

	result, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), params)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set = result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyAuthorizeData struct {
	keySign                  *tpm2.Public
	policyRef                tpm2.Nonce
	authorizedPolicies       []*Policy
	path                     string
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
	expectedNvWrittenSet     bool
	expectedNvWritten        bool
}

func (s *policyExecuteSuite) testPolicyAuthorize(c *C, data *testExecutePolicyAuthorizeData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize(data.policyRef, data.keySign)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: data.path,
	}
	resources := &PolicyResourcesData{
		AuthorizedPolicies: data.authorizedPolicies,
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, &TPMPolicyResourcesParams{Authorizer: new(mockAuthorizer)}), NewTPMHelper(s.TPM, nil), params)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	if data.expectedCommandCode == tpm2.CommandCode(0) {
		c.Check(set, internal_testutil.IsFalse)
	} else {
		c.Check(set, internal_testutil.IsTrue)
		c.Check(code, Equals, data.expectedCommandCode)
	}
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, Equals, data.expectedNvWrittenSet)
	c.Check(nvWritten, Equals, data.expectedNvWritten)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicyAuthorize(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyAuthorizeDifferentKeyNameAlg(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey, objectutil.WithNameAlg(tpm2.HashAlgorithmSHA1))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA1), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}
func (s *policyExecuteSuite) TestPolicyAuthorizeWithNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, nil, key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyAuthorizePolicyNotFound(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("bar"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x626172: no policies`)

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("bar"))
}

func (s *policyExecuteSuite) TestPolicyAuthorizeInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("foo"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: no policies`)

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policyExecuteSuite) testPolicyAuthorizeWithSubPolicyBranches(c *C, path string, expectedRequireAuthValue bool, expectedPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		path:                     path,
		expectedRequireAuthValue: expectedRequireAuthValue,
		expectedPath:             strings.Join([]string{fmt.Sprintf("%x", approvedPolicy), expectedPath}, "/"),
		expectedCommandCode:      tpm2.CommandNVChangeAuth,
		expectedNvWrittenSet:     true,
		expectedNvWritten:        true,
	})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyAuthorizeWithSubPolicyBranches(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "", true, "branch1")
}

func (s *policyExecuteSuite) TestPolicyAuthorizeWithSubPolicyBranchesExplicitPath(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "*/branch2", false, "branch2")
}

func (s *policyExecuteSuite) TestPolicyAuthorizeWithMultiplePolicies(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	builder.RootBranch().PolicyPCRValues(values)
	_, policy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy1.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	_, values, err = s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPCRValues(values)
	approvedPolicy, policy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy2.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy1, policy2},
		expectedRequireAuthValue: false,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policyExecuteSuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyAuthValue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) testPolicyCommandCode(c *C, code tpm2.CommandCode) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(code)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	codeResult, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(codeResult, Equals, code)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyCommandCodeNVChangeAuth(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandNVChangeAuth)
}

func (s *policyExecuteSuite) TestPolicyCommandCodeUnseal(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandUnseal)
}

type testExecutePolicyCounterTimerData struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policyExecuteSuite) testPolicyCounterTimer(c *C, data *testExecutePolicyCounterTimerData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicyCounterTimer1(c *C) {
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

func (s *policyExecuteSuite) TestPolicyCounterTimer2(c *C) {
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

func (s *policyExecuteSuite) TestPolicyCounterTimerFails(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedLT})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyCounterTimer assertion' task in root branch: TPM returned an error whilst executing command TPM_CC_PolicyCounterTimer: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var e *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyCounterTimer, Code: tpm2.ErrorPolicy})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyCpHashData struct {
	code    tpm2.CommandCode
	handles []Named
	params  []interface{}
}

func (s *policyExecuteSuite) testPolicyCpHash(c *C, data *testExecutePolicyCpHashData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCpHash(CommandParameters(data.code, data.handles, data.params...))
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	cpHash, set := result.CpHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedCpHash, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, data.code, data.handles, data.params...)
	c.Assert(err, IsNil)
	c.Check(cpHash, DeepEquals, expectedCpHash)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyCpHash1(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policyExecuteSuite) TestPolicyCpHash2(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policyExecuteSuite) testPolicyNameHash(c *C, handles ...Named) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNameHash(CommandHandles(handles...))
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	nameHash, set := result.NameHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedNameHash, err := ComputeNameHash(tpm2.HashAlgorithmSHA256, handles...)
	c.Assert(err, IsNil)
	c.Check(nameHash, DeepEquals, expectedNameHash)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyNameHash1(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x01})
}

func (s *policyExecuteSuite) TestPolicyNameHash2(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x0b})
}

type testExecutePolicyBranchesData struct {
	usage                    *PolicySessionUsage
	path                     string
	ignoreAuthorizations     []PolicyAuthorizationID
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
}

func (s *policyExecuteSuite) testPolicyBranches(c *C, data *testExecutePolicyBranchesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})

		n.AddBranch("branch3", func(b *PolicyBuilderBranch) {
			b.PolicySigned(pubKey, []byte("bar"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage:                data.usage,
		Path:                 data.path,
		IgnoreAuthorizations: data.ignoreAuthorizations,
	}
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}
	signedAuthorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			return SignPolicySignedAuthorization(rand.Reader, nil, pubKey, policyRef, key, crypto.SHA256)
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer, SignedAuthorizer: signedAuthorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWrittenSet, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		c.Check(log[i].GetCommandCode(c), Equals, data.expectedCommands[i])
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyBranches(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policyExecuteSuite) TestPolicyBranchesNumericSelector(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policyExecuteSuite) TestPolicyBranchesDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policyExecuteSuite) TestPolicyBranchesNumericSelectorDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "{1}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policyExecuteSuite) TestPolicyBranchAutoSelectNoUsage(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policyExecuteSuite) TestPolicyBranchAutoSelectWithUsage1(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policyExecuteSuite) TestPolicyBranchAutoSelectWithUsage2(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policyExecuteSuite) TestPolicyBranchAutoSelectWithUsageAndIgnore(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		ignoreAuthorizations: []PolicyAuthorizationID{
			{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
		},
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandLoadExternal,
			tpm2.CommandPolicySigned,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch3"})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "branch1")
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWrittenSet, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyBranchesMultipleNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policyExecuteSuite) testPolicyBranchesMultipleNodes(c *C, data *testExecutePolicyBranchesMultipleNodesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch3", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandNVChangeAuth)
		})

		n.AddBranch("branch4", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandNVWriteLock)
		})
	})

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, data.expectedCommandCode)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodes1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesNumericSelectors(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "{0}/{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodes2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodes3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch2/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "branch2",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "**/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

type testExecutePolicyBranchesEmbeddedNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policyExecuteSuite) testPolicyBranchesEmbeddedNodes(c *C, data *testExecutePolicyBranchesEmbeddedNodesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
			b.AddBranchNode(func(n *PolicyBuilderBranchNode) {
				n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandNVChangeAuth)
				})

				n.AddBranch("branch3", func(b *PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandNVWriteLock)
				})
			})
		})

		n.AddBranch("branch4", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
			b.AddBranchNode(func(n *PolicyBuilderBranchNode) {
				n.AddBranch("branch5", func(b *PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandNVChangeAuth)
				})

				n.AddBranch("branch6", func(b *PolicyBuilderBranch) {
					b.PolicyCommandCode(tpm2.CommandNVWriteLock)
				})
			})
		})
	})

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, data.expectedCommandCode)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodes1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesNumericSelectors(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "{0}/{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodes2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodes3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch5",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodes4(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch6",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch3",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch6",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policyExecuteSuite) TestPolicyBranchesSelectorOutOfRange(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "{2}",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: selected path 2 out of range`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policyExecuteSuite) TestPolicyBranchesInvalidSelector(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "{foo}",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: badly formatted path component "{foo}": expected integer`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policyExecuteSuite) TestPolicyBranchesBranchNotFound(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "foo",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: no branch with name "foo"`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policyExecuteSuite) TestPolicyBranchesMissingBranchDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in branch 'branch1': missing digest for session algorithm`)
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "branch1")
}

func (s *policyExecuteSuite) testPolicyPCRValues(c *C, values tpm2.PCRValues) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPCRValues(values)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicyPCRValues(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCRValues(c, values), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRValuesDifferentDigestAndSelectionSHA1(c *C) {
	s.RequirePCRBank(c, tpm2.HashAlgorithmSHA1)

	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCRValues(c, values), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRValuesDifferentDigestAndSelectionSHA384(c *C) {
	s.RequirePCRBank(c, tpm2.HashAlgorithmSHA384)

	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}},
		{Hash: tpm2.HashAlgorithmSHA384, Select: []int{4}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCRValues(c, values), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRValuesFails(c *C) {
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	err := s.testPolicyPCRValues(c, values)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyPCR values assertion' task in root branch: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyPCR: TPM_RC_VALUE \+ TPM_RC_P \+ TPM_RC_1 \(value is out of range or is not correct for the context\)`)
	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policyExecuteSuite) testPolicyPCRDigest(c *C, pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPCRDigest(pcrDigest, pcrs)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policyExecuteSuite) TestPolicyPCRDigest(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}}
	_, values, err := s.TPM.PCRRead(pcrs)
	c.Assert(err, IsNil)

	pcrs, pcrDigest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, values)
	c.Check(err, IsNil)

	c.Check(s.testPolicyPCRDigest(c, pcrDigest, pcrs), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRDigestDifferentDigestAndSelectionSHA1(c *C) {
	s.RequirePCRBank(c, tpm2.HashAlgorithmSHA1)

	pcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}},
	}
	_, values, err := s.TPM.PCRRead(pcrs)
	c.Assert(err, IsNil)

	pcrs, pcrDigest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, values)
	c.Check(err, IsNil)

	c.Check(s.testPolicyPCRDigest(c, pcrDigest, pcrs), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRDigestDifferentDigestAndSelectionSHA384(c *C) {
	s.RequirePCRBank(c, tpm2.HashAlgorithmSHA384)

	pcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}},
		{Hash: tpm2.HashAlgorithmSHA384, Select: []int{4}},
	}
	_, values, err := s.TPM.PCRRead(pcrs)
	c.Assert(err, IsNil)

	pcrs, pcrDigest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, values)
	c.Check(err, IsNil)

	c.Check(s.testPolicyPCRDigest(c, pcrDigest, pcrs), IsNil)
}

func (s *policyExecuteSuite) TestPolicyPCRDigestFails(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}}

	err := s.testPolicyPCRDigest(c, make([]byte, 32), pcrs)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyPCR assertion' task in root branch: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyPCR: TPM_RC_VALUE \+ TPM_RC_P \+ TPM_RC_1 \(value is out of range or is not correct for the context\)`)

	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool
	usage         *PolicySessionUsage
}

func (s *policyExecuteSuite) testPolicyDuplicationSelect(c *C, data *testExecutePolicyDuplicationSelectData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, &PolicyExecuteParams{Usage: data.usage})
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandDuplicate)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	nameHash, set := result.NameHash()
	c.Check(set, internal_testutil.IsTrue)
	var expectedNameHash tpm2.Digest
	if data.object != nil {
		expectedNameHash, err = ComputeNameHash(tpm2.HashAlgorithmSHA256, data.object.Name(), data.newParent.Name())
		c.Assert(err, IsNil)
	} else {
		c.Assert(data.usage, NotNil)
		expectedNameHash, err = data.usage.NameHash(tpm2.HashAlgorithmSHA256)
		c.Assert(err, IsNil)
	}
	c.Check(nameHash, DeepEquals, expectedNameHash)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyDuplicationSelect(c *C) {
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

func (s *policyExecuteSuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
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

func (s *policyExecuteSuite) TestPolicyDuplicationSelectNoIncludeObjectName(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		newParent:     newParent,
		includeObject: false,
		usage:         NewPolicySessionUsage(tpm2.CommandDuplicate, []NamedHandle{tpm2.NewResourceContext(0x80000000, object), tpm2.NewResourceContext(0x80000001, newParent)}, tpm2.Data{}, tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull}),
	})
}

func (s *policyExecuteSuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
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

func (s *policyExecuteSuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPassword()
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyPassword)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) testPolicyNvWritten(c *C, writtenSet bool) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(writtenSet)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, Equals, writtenSet)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, false)
}

func (s *policyExecuteSuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, true)
}

type testExecutePolicyORData struct {
	policy    *Policy
	pHashList tpm2.DigestList
}

func (s *policyExecuteSuite) testPolicyOR(c *C, data *testExecutePolicyORData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyOR(data.pHashList...)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = data.policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyOR(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testExecutePolicyORData{
		policy:    policy,
		pHashList: tpm2.DigestList{digest1, digest2},
	})
}

func (s *policyExecuteSuite) TestPolicyORDifferentDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testExecutePolicyORData{
		policy:    policy,
		pHashList: tpm2.DigestList{digest2, digest1},
	})
}

func (s *policyExecuteSuite) TestPolicyBranchesNVAutoSelected(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandNVRead)
		})
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandPolicyNV)
		})
	})
	digest, nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq)
		})
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpEq)
		})
	})
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, nil), NewTPMHelper(s.TPM, nil), nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "{1}")

	digest, err = s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuite) TestPolicyBranchesNVAutoSelectedFail(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandNVRead)
		})
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandPolicyNV)
		})
	})
	digest, nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq)
		})
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyNV(nvPub, []byte{0}, 10, tpm2.OpEq)
		})
	})

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, nil), NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type policyExecuteSuitePCR struct {
	testutil.TPMTest
}

func (s *policyExecuteSuitePCR) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV | testutil.TPMFeaturePCR
}

var _ = Suite(&policyExecuteSuitePCR{})

func (s *policyExecuteSuitePCR) TestPolicyBranchesAutoSelected(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyPCRValues(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}})
		})

		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyPCRValues(pcrValues)
		})
	})

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "{1}")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyExecuteSuitePCR) TestPolicyBranchesAutoSelectFail(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyPCRValues(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}})
		})

		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyPCRValues(pcrValues)
		})
	})

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}
