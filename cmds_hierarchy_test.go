// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
)

type hierarchySuite struct {
	testutil.TPMTest
	objectMixin
}

func (s *hierarchySuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy | testutil.TPMFeatureLockoutHierarchy | testutil.TPMFeaturePlatformHierarchy | testutil.TPMFeatureClear | testutil.TPMFeatureNV
}

func (s *hierarchySuite) SetUpTest(c *C) {
	s.TPMTest.SetUpTest(c)
	s.AddFixtureCleanup(s.objectMixin.setupTest(s.TPM))
}

var _ = Suite(&hierarchySuite{})

type testCreatePrimaryParams struct {
	hierarchy         ResourceContext
	sensitive         *SensitiveCreate
	template          *Public
	outsideInfo       Data
	creationPCR       PCRSelectionList
	parentAuthSession SessionContext
}

func (s *hierarchySuite) testCreatePrimary(c *C, params *testCreatePrimaryParams) ResourceContext {
	sessionHandle := authSessionHandle(params.parentAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.parentAuthSession.State().NeedsPassword

	objectContext, outPublic, creationData, creationHash, creationTicket, err := s.TPM.CreatePrimary(params.hierarchy, params.sensitive, params.template, params.outsideInfo, params.creationPCR, params.parentAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(params.hierarchy.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(params.hierarchy.AuthValue()))
		}
	}
	c.Check(cmd.RspHandle, Equals, objectContext.Handle())
	if params.parentAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.parentAuthSession.Handle(), Equals, HandleUnassigned)
	}

	c.Check(objectContext.Handle().Type(), Equals, HandleTypeTransient)

	var sample ObjectContext
	c.Assert(objectContext, Implements, &sample)
	c.Check(objectContext.(ObjectContext).Public(), testutil.TPMValueDeepEquals, outPublic)

	s.checkPublicAgainstTemplate(c, outPublic, params.template)
	s.checkCreationData(c, creationData, creationHash, params.template, params.outsideInfo, params.creationPCR, params.hierarchy)
	s.checkCreationTicket(c, creationTicket, params.hierarchy.Handle())

	return objectContext
}

func (s *hierarchySuite) TestCreatePrimaryRSAPrimaryStorage(c *C) {
	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
	})
}

func (s *hierarchySuite) TestCreatePrimaryECCPrimaryStorage(c *C) {
	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewECCStorageKeyTemplate(
			objectutil.WithECCUnique(&ECCPoint{
				X: make([]byte, 32),
				Y: make([]byte, 32),
			}),
		),
	})
}

func (s *hierarchySuite) TestCreatePrimaryEK(c *C) {
	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.EndorsementHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithAuthPolicy(internal_testutil.DecodeHexString(c, "837197674484B3F81A90CC8D46A5D724FD52D76E06520B64F2A1DA1B331469AA")),
			objectutil.WithUserAuthMode(objectutil.RequirePolicy),
			objectutil.WithAdminAuthMode(objectutil.RequirePolicy),
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
	})
}

func (s *hierarchySuite) TestCreatePrimaryRSAWithUserAuth(c *C) {
	srk := s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		sensitive: &SensitiveCreate{
			UserAuth: []byte("1234"),
		},
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
	})

	// The returned object should already have the auth value set
	c.Check(srk.AuthValue(), DeepEquals, []byte("1234"))

	// Make sure we can use the auth value for user role.
	s.ForgetCommands()
	_, _, _, _, _, err := s.TPM.Create(srk, nil, objectutil.NewRSAKeyTemplate(objectutil.UsageSign), nil, nil, nil)
	c.Check(err, IsNil)
	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth("1234"))
}

func (s *hierarchySuite) TestCreatePrimaryRSAPrimaryStorageWithPWSession(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("password"))

	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
	})
}

func (s *hierarchySuite) TestCreatePrimaryRSAPrimaryStorageWithHMACSession(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("password"))

	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
		parentAuthSession: s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestCreatePrimaryRSAPrimaryStorageWithOutsideInfo(c *C) {
	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
		outsideInfo: []byte("foo"),
	})
}

func (s *hierarchySuite) TestCreatePrimaryRSAPrimaryStorageWithCreationPCR(c *C) {
	s.testCreatePrimary(c, &testCreatePrimaryParams{
		hierarchy: s.TPM.OwnerHandleContext(),
		template: objectutil.NewRSAStorageKeyTemplate(
			objectutil.WithRSAUnique(make([]byte, 256)),
		),
		creationPCR: tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}},
	})
}

func (s *hierarchySuite) TestCreatePrimaryInvalidTemplate(c *C) {
	template := Public{
		Type:    ObjectTypeECC,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}

	_, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Check(IsTPMParameterError(err, ErrorSymmetric, CommandCreatePrimary, 2), internal_testutil.IsTrue)
}

func (s *hierarchySuite) TestCreatePrimaryWithNilHierarchy(c *C) {
	template := objectutil.NewRSAStorageKeyTemplate(
		objectutil.WithRSAUnique(make([]byte, 256)),
	)
	_, _, _, _, _, err := s.TPM.CreatePrimary(nil, nil, template, nil, nil, nil)
	c.Check(IsTPMHandleError(err, ErrorValue, CommandCreatePrimary, 1), internal_testutil.IsTrue)
}

type testHierarchyControlParams struct {
	authContext            ResourceContext
	enable                 Handle
	state                  bool
	authContextAuthSession SessionContext
}

func (s *hierarchySuite) testHierarchyControl(c *C, params *testHierarchyControlParams) {
	sessionHandle := authSessionHandle(params.authContextAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.authContextAuthSession.State().NeedsPassword

	c.Check(s.TPM.HierarchyControl(params.authContext, params.enable, params.state, params.authContextAuthSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(params.authContext.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(params.authContext.AuthValue()))
		}
	}
	if params.authContextAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.authContextAuthSession.Handle(), Equals, HandleUnassigned)
	}

	val, err := s.TPM.GetCapabilityTPMProperty(PropertyStartupClear)
	c.Check(err, IsNil)

	var mask StartupClearAttributes
	switch params.enable {
	case HandleOwner:
		mask = AttrShEnable
	case HandleEndorsement:
		mask = AttrEhEnable
	}

	var expected StartupClearAttributes
	if params.state {
		expected = mask
	}
	c.Check(StartupClearAttributes(val)&mask, Equals, expected)
}

func (s *hierarchySuite) TestHierarchyControlDisableOwner(c *C) {
	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.OwnerHandleContext(),
		enable:      HandleOwner,
		state:       false,
	})
}

func (s *hierarchySuite) TestHierarchyControlDisableEndorsement(c *C) {
	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.EndorsementHandleContext(),
		enable:      HandleEndorsement,
		state:       false,
	})
}

func (s *hierarchySuite) TestHierarchyControlEnableOwner(c *C) {
	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.OwnerHandleContext(),
		enable:      HandleOwner,
		state:       false,
	})
	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.PlatformHandleContext(),
		enable:      HandleOwner,
		state:       true,
	})
}

func (s *hierarchySuite) TestHierarchyControlDisableOwnerPWAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("password"))

	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.OwnerHandleContext(),
		enable:      HandleOwner,
		state:       false,
	})
	c.Assert(s.CommandLog(), internal_testutil.LenEquals, 2)
	c.Assert(s.CommandLog()[0].CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(s.CommandLog()[0].CmdAuthArea[0].HMAC, DeepEquals, Auth("password"))
}

func (s *hierarchySuite) TestHierarchyControlDisableOwnerHMACAuth(c *C) {
	s.HierarchyChangeAuth(c, tpm2.HandleOwner, []byte("password"))

	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext:            s.TPM.OwnerHandleContext(),
		enable:                 HandleOwner,
		state:                  false,
		authContextAuthSession: s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestHierarchyControlReenableOwnerWrongAuth(c *C) {
	s.testHierarchyControl(c, &testHierarchyControlParams{
		authContext: s.TPM.OwnerHandleContext(),
		enable:      HandleOwner,
		state:       false,
	})
	err := s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), HandleOwner, true, nil)
	c.Check(err, ErrorMatches, `TPM returned an error for handle 1 whilst executing command TPM_CC_HierarchyControl: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)`)
	c.Check(IsTPMHandleError(err, ErrorHierarchy, CommandHierarchyControl, 1), internal_testutil.IsTrue)
}

type testSetPrimaryPolicyParams struct {
	authContext            ResourceContext
	authPolicy             Digest
	hashAlg                HashAlgorithmId
	authContextAuthSession SessionContext
}

func (s *hierarchySuite) testSetPrimaryPolicy(c *C, params *testSetPrimaryPolicyParams) {
	sessionHandle := authSessionHandle(params.authContextAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.authContextAuthSession.State().NeedsPassword

	c.Check(s.TPM.SetPrimaryPolicy(params.authContext, params.authPolicy, params.hashAlg, params.authContextAuthSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(params.authContext.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(params.authContext.AuthValue()))
		}
	}
	if params.authContextAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.authContextAuthSession.Handle(), Equals, HandleUnassigned)
	}

	digest, err := s.TPM.GetCapabilityAuthPolicy(params.authContext.Handle())
	c.Assert(err, IsNil)
	c.Check(digest.Digest(), DeepEquals, params.authPolicy)
	c.Check(digest.HashAlg, Equals, params.hashAlg)
}

func (s *hierarchySuite) TestSetPrimaryPolicyOwner(c *C) {
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext: s.TPM.OwnerHandleContext(),
		authPolicy:  internal_testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
		hashAlg:     HashAlgorithmSHA256,
	})
}

func (s *hierarchySuite) TestSetPrimaryPolicyEndorsement(c *C) {
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext: s.TPM.EndorsementHandleContext(),
		authPolicy:  internal_testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
		hashAlg:     HashAlgorithmSHA256,
	})
}

func (s *hierarchySuite) TestSetPrimaryPolicyOwnerDifferentPolicy(c *C) {
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext: s.TPM.OwnerHandleContext(),
		authPolicy:  internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
		hashAlg:     HashAlgorithmSHA256,
	})
}

func (s *hierarchySuite) TestSetPrimaryPolicyOwnerDifferentAlg(c *C) {
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext: s.TPM.OwnerHandleContext(),
		authPolicy:  internal_testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
		hashAlg:     HashAlgorithmSHA1,
	})
}

func (s *hierarchySuite) TestSetPrimaryPolicyOwnerWithAuthSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("12345678"))
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext:            s.TPM.OwnerHandleContext(),
		authPolicy:             internal_testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
		hashAlg:                HashAlgorithmSHA256,
		authContextAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestSetPrimaryPolicyOwnerWithPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("12345678"))
	s.testSetPrimaryPolicy(c, &testSetPrimaryPolicyParams{
		authContext: s.TPM.OwnerHandleContext(),
		authPolicy:  internal_testutil.DecodeHexString(c, "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5"),
		hashAlg:     HashAlgorithmSHA256,
	})
}

func (s *hierarchySuite) testClear(c *C, auth ResourceContext, authSession SessionContext) {
	sessionHandle := authSessionHandle(authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || authSession.State().NeedsPassword

	origAuthValue := auth.AuthValue()

	// Persist an owner object (should be cleared)
	srk := s.CreateStoragePrimaryKeyRSA(c)
	srkHandle := Handle(0x81000001)
	s.EvictControl(c, HandleOwner, srk, srkHandle)
	srkTransientHandle := srk.Handle()

	// Change endorsement hierarchy auth (should be cleared)
	s.HierarchyChangeAuth(c, tpm2.HandleEndorsement, []byte("1234"))

	// Change platform hierarchy auth (shouldn't be cleared)
	s.HierarchyChangeAuth(c, tpm2.HandlePlatform, []byte("1234"))
	if auth.Handle() == HandlePlatform {
		origAuthValue = []byte("1234")
	}

	c.Check(s.TPM.Clear(auth, authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(origAuthValue) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(origAuthValue))
		}
	}
	if authSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(authSession.Handle(), Equals, HandleUnassigned)
	}

	c.Check(s.TPM.DoesHandleExist(srkHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesHandleExist(srkTransientHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.EndorsementHandleContext().AuthValue(), internal_testutil.LenEquals, 0)
	c.Check(s.TPM.PlatformHandleContext().AuthValue(), DeepEquals, []byte("1234"))
	c.Check(s.TPM.LockoutHandleContext().AuthValue(), internal_testutil.LenEquals, 0)

	val, err := s.TPM.GetCapabilityTPMProperty(PropertyPermanent)
	c.Assert(err, IsNil)
	c.Check(PermanentAttributes(val)&(AttrOwnerAuthSet|AttrEndorsementAuthSet|AttrLockoutAuthSet), Equals, PermanentAttributes(0))
}

func (s *hierarchySuite) TestClear(c *C) {
	s.testClear(c, s.TPM.LockoutHandleContext(), nil)
}

func (s *hierarchySuite) TestClearPlatform(c *C) {
	s.testClear(c, s.TPM.PlatformHandleContext(), nil)
}

func (s *hierarchySuite) TestClearPWAuth(c *C) {
	s.HierarchyChangeAuth(c, HandleLockout, []byte("password"))
	s.testClear(c, s.TPM.LockoutHandleContext(), nil)
}

func (s *hierarchySuite) TestClearUnboundSession(c *C) {
	s.HierarchyChangeAuth(c, HandleLockout, []byte("password"))
	s.testClear(c, s.TPM.LockoutHandleContext(), s.StartAuthSession(c, nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256))
}

func (s *hierarchySuite) TestClearBoundSession(c *C) {
	s.HierarchyChangeAuth(c, HandleLockout, []byte("password"))
	s.testClear(c, s.TPM.LockoutHandleContext(), s.StartAuthSession(c, nil, s.TPM.LockoutHandleContext(), tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256))
}

type testClearControlParams struct {
	auth        ResourceContext
	disable     bool
	authSession SessionContext
}

func (s *hierarchySuite) testClearControl(c *C, params *testClearControlParams) {
	sessionHandle := authSessionHandle(params.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.authSession.State().NeedsPassword

	c.Check(s.TPM.ClearControl(params.auth, params.disable, params.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(params.auth.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(params.auth.AuthValue()))
		}
	}
	if params.authSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.authSession.Handle(), Equals, HandleUnassigned)
	}

	val, err := s.TPM.GetCapabilityTPMProperty(PropertyPermanent)
	c.Check(err, IsNil)

	var mask PermanentAttributes
	if params.disable {
		mask = AttrDisableClear
	}
	c.Check(PermanentAttributes(val)&mask, Equals, mask)
}

func (s *hierarchySuite) TestClearControlDisable(c *C) {
	s.testClearControl(c, &testClearControlParams{
		auth:    s.TPM.LockoutHandleContext(),
		disable: true,
	})
}

func (s *hierarchySuite) TestClearControlDisablePlatformAuth(c *C) {
	s.testClearControl(c, &testClearControlParams{
		auth:    s.TPM.PlatformHandleContext(),
		disable: true,
	})
}

func (s *hierarchySuite) TestClearControlEnablePlatformAuth(c *C) {
	s.testClearControl(c, &testClearControlParams{
		auth:    s.TPM.LockoutHandleContext(),
		disable: true,
	})
	s.testClearControl(c, &testClearControlParams{
		auth:    s.TPM.PlatformHandleContext(),
		disable: false,
	})
}

func (s *hierarchySuite) TestClearControlDisablePWAuth(c *C) {
	s.HierarchyChangeAuth(c, HandleLockout, []byte("password"))
	s.testClearControl(c, &testClearControlParams{
		auth:    s.TPM.LockoutHandleContext(),
		disable: true,
	})
}

func (s *hierarchySuite) TestClearControlDisableHMACAuth(c *C) {
	s.HierarchyChangeAuth(c, HandleLockout, []byte("password"))
	s.testClearControl(c, &testClearControlParams{
		auth:        s.TPM.LockoutHandleContext(),
		disable:     true,
		authSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

type testHierarchyChangeAuthParams struct {
	authContext            ResourceContext
	newAuth                Auth
	authContextAuthSession SessionContext
}

func (s *hierarchySuite) testHierarchyChangeAuth(c *C, params *testHierarchyChangeAuthParams) {
	sessionHandle := authSessionHandle(params.authContextAuthSession)
	sessionHMACIsPW := sessionHandle == HandlePW || params.authContextAuthSession.State().NeedsPassword

	origAuthValue := params.authContext.AuthValue()

	c.Check(s.TPM.HierarchyChangeAuth(params.authContext, params.newAuth, params.authContextAuthSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(origAuthValue) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(origAuthValue))
		}
	}
	if params.authContextAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(params.authContextAuthSession.Handle(), Equals, HandleUnassigned)
	}

	c.Check(params.authContext.AuthValue(), DeepEquals, []byte(params.newAuth))

	_, _, _, _, _, err := s.TPM.CreatePrimary(params.authContext, nil, objectutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwner(c *C) {
	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext: s.TPM.OwnerHandleContext(),
		newAuth:     []byte("1234"),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthEndorsement(c *C) {
	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext: s.TPM.EndorsementHandleContext(),
		newAuth:     []byte("1234"),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerDifferentNewAuth(c *C) {
	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext: s.TPM.OwnerHandleContext(),
		newAuth:     []byte("5678"),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext: s.TPM.OwnerHandleContext(),
		newAuth:     []byte("1234"),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerUnboundSession(c *C) {
	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext:            s.TPM.OwnerHandleContext(),
		newAuth:                []byte("1234"),
		authContextAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerUnboundSessionWithPW(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext:            s.TPM.OwnerHandleContext(),
		newAuth:                []byte("1234"),
		authContextAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerBoundSession(c *C) {
	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext:            s.TPM.OwnerHandleContext(),
		newAuth:                []byte("1234"),
		authContextAuthSession: s.StartAuthSession(c, nil, s.TPM.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerBoundSessionWithPW(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext:            s.TPM.OwnerHandleContext(),
		newAuth:                []byte("1234"),
		authContextAuthSession: s.StartAuthSession(c, nil, s.TPM.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}

func (s *hierarchySuite) TestHierarchyChangeAuthOwnerUnboundSessionWithSessionKey(c *C) {
	// This test highlights a historical bug where we didn't preserve the value of sessionParam.IncludeAuthValue
	// (which should be true) before computing the response HMAC. It wasn't caught by
	// TestHierarchyChangeAuthOwnerUnboundSession because the lack of session key combined with
	// a former implementation of sessionParam.ProcessResponseAuth bailing out early with success
	// before checking the response HMAC.

	tpmKey := s.CreateStoragePrimaryKeyRSA(c)

	s.testHierarchyChangeAuth(c, &testHierarchyChangeAuthParams{
		authContext:            s.TPM.OwnerHandleContext(),
		newAuth:                []byte("1234"),
		authContextAuthSession: s.StartAuthSession(c, tpmKey, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
	})
}
