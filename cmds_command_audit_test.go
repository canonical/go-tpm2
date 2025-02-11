// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/testutil"
)

type commandCodeAuditSuiteBase struct {
	testutil.TPMTest
}

type commandCodeAuditSuiteOwner struct {
	commandCodeAuditSuiteBase
}

func (s *commandCodeAuditSuiteOwner) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy | testutil.TPMFeatureNV
}

type commandCodeAuditSuitePlatform struct {
	commandCodeAuditSuiteBase
}

func (s *commandCodeAuditSuitePlatform) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureEndorsementHierarchy | testutil.TPMFeaturePlatformHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&commandCodeAuditSuiteOwner{})
var _ = Suite(&commandCodeAuditSuitePlatform{})

type testSetCommandCodeAuditStatusData struct {
	auth        ResourceContext
	alg         HashAlgorithmId
	setList     CommandCodeList
	clearList   CommandCodeList
	authSession SessionContext

	expectedCommands CommandCodeList
}

func (s *commandCodeAuditSuiteBase) testSetCommandCodeAuditStatus(c *C, data *testSetCommandCodeAuditStatusData) {
	sessionHandle := authSessionHandle(data.authSession)
	sessionHMACIsPW := sessionHandle == HandlePW || data.authSession.State().NeedsPassword

	c.Check(s.TPM.SetCommandCodeAuditStatus(data.auth, data.alg, nil, nil, data.authSession), IsNil)
	c.Check(s.TPM.SetCommandCodeAuditStatus(data.auth, HashAlgorithmNull, data.setList, nil, data.authSession), IsNil)
	c.Check(s.TPM.SetCommandCodeAuditStatus(data.auth, data.alg, nil, data.clearList, data.authSession), IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.auth.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.auth.AuthValue()))
		}
	}

	commands, err := s.TPM.GetCapabilityAuditCommands(CommandFirst, CapabilityMaxProperties)
	c.Assert(err, IsNil)
	c.Check(commands, DeepEquals, data.expectedCommands)

	auditInfo, _, err := s.TPM.GetCommandAuditDigest(s.TPM.EndorsementHandleContext(), nil, nil, nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(auditInfo.Attested.CommandAudit.DigestAlg, Equals, AlgorithmId(data.alg))
}

func (s *commandCodeAuditSuiteOwner) TestSetCommandCodeAuditStatus1(c *C) {
	s.testSetCommandCodeAuditStatus(c, &testSetCommandCodeAuditStatusData{
		auth:             s.TPM.OwnerHandleContext(),
		alg:              HashAlgorithmSHA256,
		setList:          CommandCodeList{CommandClockSet, CommandStirRandom, CommandGetRandom},
		clearList:        CommandCodeList{CommandGetRandom},
		expectedCommands: CommandCodeList{CommandClockSet, CommandSetCommandCodeAuditStatus, CommandStirRandom}})
}

func (s *commandCodeAuditSuiteOwner) TestSetCommandCodeAuditStatus2(c *C) {
	s.testSetCommandCodeAuditStatus(c, &testSetCommandCodeAuditStatusData{
		auth:             s.TPM.OwnerHandleContext(),
		alg:              HashAlgorithmSHA1,
		setList:          CommandCodeList{CommandClockSet, CommandStirRandom, CommandGetRandom},
		expectedCommands: CommandCodeList{CommandClockSet, CommandSetCommandCodeAuditStatus, CommandStirRandom, CommandGetRandom}})
}

func (s *commandCodeAuditSuiteOwner) TestSetCommandCodeAuditStatusAuthSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testSetCommandCodeAuditStatus(c, &testSetCommandCodeAuditStatusData{
		auth:             s.TPM.OwnerHandleContext(),
		alg:              HashAlgorithmSHA256,
		setList:          CommandCodeList{CommandClockSet, CommandStirRandom, CommandGetRandom},
		clearList:        CommandCodeList{CommandGetRandom},
		authSession:      s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256).WithAttrs(AttrContinueSession),
		expectedCommands: CommandCodeList{CommandClockSet, CommandSetCommandCodeAuditStatus, CommandStirRandom}})
}

func (s *commandCodeAuditSuiteOwner) TestSetCommandCodeAuditStatusPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandleOwner, []byte("password"))

	s.testSetCommandCodeAuditStatus(c, &testSetCommandCodeAuditStatusData{
		auth:             s.TPM.OwnerHandleContext(),
		alg:              HashAlgorithmSHA256,
		setList:          CommandCodeList{CommandClockSet, CommandStirRandom, CommandGetRandom},
		clearList:        CommandCodeList{CommandGetRandom},
		expectedCommands: CommandCodeList{CommandClockSet, CommandSetCommandCodeAuditStatus, CommandStirRandom}})
}

func (s *commandCodeAuditSuitePlatform) TestSetCommandCodeAuditStatus(c *C) {
	s.testSetCommandCodeAuditStatus(c, &testSetCommandCodeAuditStatusData{
		auth:             s.TPM.PlatformHandleContext(),
		alg:              HashAlgorithmSHA256,
		setList:          CommandCodeList{CommandClockSet, CommandStirRandom, CommandGetRandom},
		clearList:        CommandCodeList{CommandGetRandom},
		expectedCommands: CommandCodeList{CommandClockSet, CommandSetCommandCodeAuditStatus, CommandStirRandom}})
}
