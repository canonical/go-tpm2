// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"io/ioutil"
	"net"
	"os"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	. "github.com/canonical/go-tpm2/testutil"
)

type baseTestSuite struct{}

var _ = Suite(&baseTestSuite{})

type mockBaseTestCleanupSuite struct {
	BaseTest
	log []string

	fixtureCb func(*C)
}

func (s *mockBaseTestCleanupSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	s.AddFixtureCleanup(func(c *C) { s.log = append(s.log, "fixture1") })
	s.AddFixtureCleanup(func(c *C) { s.log = append(s.log, "fixture2") })
	if s.fixtureCb != nil {
		s.fixtureCb(c)
	}
}

func (s *mockBaseTestCleanupSuite) Test(c *C) {}

func (s *baseTestSuite) TestCleanup(c *C) {
	suite := new(mockBaseTestCleanupSuite)
	suite.SetUpTest(c)
	suite.AddCleanup(func() { suite.log = append(suite.log, "foo1") })
	suite.AddCleanup(func() { suite.log = append(suite.log, "bar1") })
	suite.TearDownTest(c)
	suite.SetUpTest(c)
	suite.AddCleanup(func() { suite.log = append(suite.log, "bar2") })
	suite.AddCleanup(func() { suite.log = append(suite.log, "foo2") })
	suite.TearDownTest(c)
	c.Check(suite.log, DeepEquals, []string{"bar1", "foo1", "fixture2", "fixture1", "foo2", "bar2", "fixture2", "fixture1"})
}

func (s *baseTestSuite) TestFixtureCleanupError(c *C) {
	suite := new(mockBaseTestCleanupSuite)
	suite.fixtureCb = func(c *C) {
		suite.AddFixtureCleanup(func(c *C) { c.Error("error") })
	}

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Passed(), IsFalse)
	c.Check(result.Failed, Equals, 1)
	c.Check(result.Missed, Equals, 1)
}

type tpmTestSuite struct {
	BaseTest
}

var _ = Suite(&tpmTestSuite{})

func (s *tpmTestSuite) TestTestLifecycleDefault(c *C) {
	suite := new(TPMTest)
	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Check(suite.TCTI, NotNil)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), InSlice(ErrorIs), []error{os.ErrClosed, net.ErrClosed})
}

func (s *tpmTestSuite) TestTestLifecycleProvidedTCTI(c *C) {
	suite := new(TPMTest)

	tcti := NewTCTI(c, 0)
	suite.TCTI = tcti

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Check(suite.TCTI, Equals, tcti)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, Equals, tcti)
	c.Check(tpm.Close(), InSlice(ErrorIs), []error{os.ErrClosed, net.ErrClosed})
}

func (s *tpmTestSuite) TestTestLifecycleProvidedTPM(c *C) {
	suite := new(TPMTest)

	tpm, tcti := NewTPMContext(c, 0)
	suite.TPM = tpm
	suite.TCTI = tcti

	suite.SetUpTest(c)
	c.Check(suite.TPM, Equals, tpm)
	c.Check(suite.TCTI, Equals, tcti)

	suite.TearDownTest(c)
	c.Check(suite.TPM, Equals, tpm)
	c.Check(suite.TCTI, Equals, tcti)
	c.Check(tpm.Close(), IsNil)
}

type mockTPMTestSuite struct {
	TPMTest

	cb func(*C)
}

func (s *mockTPMTestSuite) Test(c *C) {
	if s.cb != nil {
		s.cb(c)
	}
}

func (s *tpmTestSuite) TestSkipNoTPM(c *C) {
	suite := new(mockTPMTestSuite)

	origBackend := TPMBackend
	TPMBackend = TPMBackendNone
	defer func() { TPMBackend = origBackend }()

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Skipped, Equals, 1)
}

func (s *tpmTestSuite) TestInvalidSetUp(c *C) {
	suite := new(mockTPMTestSuite)

	tpm, _ := NewTPMContext(c, 0)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})
	suite.TPM = tpm

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Missed, Equals, 1)
}

func (s *tpmTestSuite) TestLastCommandWithNoCommands(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.LastCommand(c)
	}

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Failed, Equals, 1)
}

type tpmTestSuiteProper struct {
	TPMTest
}

func (s *tpmTestSuiteProper) SetUpSuite(c *C) {
	s.TPMFeatures = TPMFeatureOwnerHierarchy | TPMFeaturePlatformHierarchy | TPMFeatureClear | TPMFeatureClearControl | TPMFeatureNV
}

var _ = Suite(&tpmTestSuiteProper{})

func (s *tpmTestSuiteProper) TestCommandLog(c *C) {
	c.Check(s.TPM.SelfTest(true), IsNil)
	outData, testResult, err := s.TPM.GetTestResult()
	c.Check(err, IsNil)

	c.Assert(s.CommandLog(), HasLen, 2)

	c.Check(s.CommandLog()[0].GetCommandCode(c), Equals, tpm2.CommandSelfTest)
	cHandles, cAuthArea, cpBytes := s.CommandLog()[0].UnmarshalCommand(c)
	c.Check(cHandles, HasLen, 0)
	c.Check(cAuthArea, HasLen, 0)

	var fullTest bool
	_, err = mu.UnmarshalFromBytes(cpBytes, &fullTest)
	c.Check(err, IsNil)
	c.Check(fullTest, IsTrue)

	rc, rHandle, rpBytes, rAuthArea := s.CommandLog()[0].UnmarshalResponse(c)
	c.Check(rc, Equals, tpm2.Success)
	c.Check(rHandle, Equals, tpm2.HandleUnassigned)
	c.Check(rpBytes, HasLen, 0)
	c.Check(rAuthArea, HasLen, 0)

	c.Check(s.CommandLog()[1].GetCommandCode(c), Equals, tpm2.CommandGetTestResult)
	cHandles, cAuthArea, cpBytes = s.CommandLog()[1].UnmarshalCommand(c)
	c.Check(cHandles, HasLen, 0)
	c.Check(cAuthArea, HasLen, 0)
	c.Check(cpBytes, HasLen, 0)

	rc, rHandle, rpBytes, rAuthArea = s.CommandLog()[1].UnmarshalResponse(c)
	c.Check(rc, Equals, tpm2.Success)
	c.Check(rHandle, Equals, tpm2.HandleUnassigned)
	c.Check(rAuthArea, HasLen, 0)

	var outData2 tpm2.MaxBuffer
	var testResult2 tpm2.ResponseCode
	_, err = mu.UnmarshalFromBytes(rpBytes, &outData2, &testResult2)
	c.Check(err, IsNil)
	c.Check(outData2, DeepEquals, outData)
	c.Check(testResult2, Equals, testResult)
}

func (s *tpmTestSuiteProper) TestLastCommand(c *C) {
	c.Check(s.TPM.SelfTest(true), IsNil)
	_, _, err := s.TPM.GetTestResult()
	c.Check(err, IsNil)

	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandGetTestResult)
}

func (s *tpmTestSuiteProper) TestForgetCommands(c *C) {
	c.Check(s.TPM.SelfTest(true), IsNil)
	_, _, err := s.TPM.GetTestResult()
	c.Check(err, IsNil)

	s.ForgetCommands()
	c.Check(s.CommandLog(), HasLen, 0)
}

func (s *tpmTestSuiteProper) TestNextAvailableHandle(c *C) {
	handles, err := s.TPM.GetCapabilityHandles(tpm2.HandleTypePCR.BaseHandle(), tpm2.CapabilityMaxProperties)
	c.Check(err, IsNil)

	c.Check(s.NextAvailableHandle(c, tpm2.HandleTypePCR.BaseHandle()), Equals, handles[len(handles)-1]+1)
}

func (s *tpmTestSuiteProper) TestNextAvailableHandle2(c *C) {
	// This handle is not assigned in any version of the spec
	c.Check(s.NextAvailableHandle(c, 0x4000000e), Equals, tpm2.Handle(0x4000000e))
}

func (s *tpmTestSuiteProper) TestClearTPMUsingPlatformHierarchy(c *C) {
	name := s.CreateStoragePrimaryKeyRSA(c)
	c.Check(s.TPM.ClearControl(s.TPM.PlatformHandleContext(), true, nil), IsNil)

	s.ForgetCommands()
	s.ClearTPMUsingPlatformHierarchy(c)
	c.Check(s.CommandLog(), HasLen, 0)

	c.Check(s.CreateStoragePrimaryKeyRSA(c), Not(DeepEquals), name)

	props, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Assert(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	c.Check(tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear, Equals, tpm2.PermanentAttributes(0))
}

type tpmSimulatorTestSuite struct {
	BaseTest
}

var _ = Suite(&tpmSimulatorTestSuite{})

func (s *tpmSimulatorTestSuite) TestTestLifecycleDefault(c *C) {
	suite := new(TPMSimulatorTest)

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Assert(suite.TPMTest.TCTI, NotNil)
	c.Check(suite.TCTI, Equals, suite.TPMTest.TCTI.Unwrap())

	suite.ResetTPMSimulator(c) // Increment reset count so we can detect the clea
	c.Check(suite.TPM.ClearControl(suite.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(suite.TPM.HierarchyControl(suite.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(suite.TPMTest.TCTI, IsNil)
	c.Check(tpm.Close(), ErrorIs, net.ErrClosed)

	tpm, _ = NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})

	currentTime, err := tpm.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, uint32(0))
}

func (s *tpmSimulatorTestSuite) TestTestLifecycleProvidedTCTI(c *C) {
	suite := new(TPMSimulatorTest)

	tcti := NewSimulatorTCTI(c)
	suite.TPMTest.TCTI = tcti
	suite.TCTI = tcti.Unwrap().(*tpm2.TctiMssim)

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Check(suite.TPMTest.TCTI, Equals, tcti)
	c.Check(suite.TCTI, Equals, tcti.Unwrap().(*tpm2.TctiMssim))

	suite.ResetTPMSimulator(c) // Increment reset count so we can detect the clea
	c.Check(suite.TPM.ClearControl(suite.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(suite.TPM.HierarchyControl(suite.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TPMTest.TCTI, Equals, tcti)
	c.Check(suite.TCTI, Equals, tcti.Unwrap().(*tpm2.TctiMssim))
	c.Check(tpm.Close(), ErrorIs, net.ErrClosed)

	tpm, _ = NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})

	currentTime, err := tpm.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, uint32(0))
}

type mockTPMSimulatorTestSuite struct {
	TPMSimulatorTest
}

func (s *mockTPMSimulatorTestSuite) Test(c *C) {}

func (s *tpmSimulatorTestSuite) TestSkipNoTPM(c *C) {
	suite := new(mockTPMSimulatorTestSuite)

	origBackend := TPMBackend
	TPMBackend = TPMBackendNone
	defer func() { TPMBackend = origBackend }()

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Skipped, Equals, 1)
}

func (s *tpmSimulatorTestSuite) TestInvalidSetUp1(c *C) {
	suite := new(mockTPMSimulatorTestSuite)

	tcti := NewSimulatorTCTI(c)
	s.AddCleanup(func() {
		c.Check(tcti.Close(), IsNil)
	})
	suite.TCTI = tcti.Unwrap().(*tpm2.TctiMssim)

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Missed, Equals, 1)
}

func (s *tpmSimulatorTestSuite) TestInvalidSetUp2(c *C) {
	suite := new(mockTPMSimulatorTestSuite)

	tpm, _ := NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})
	suite.TPM = tpm

	result := Run(suite, &RunConf{Output: ioutil.Discard})
	c.Check(result.Missed, Equals, 1)
}

type tpmSimulatorTestSuiteProper struct {
	TPMSimulatorTest
}

var _ = Suite(&tpmSimulatorTestSuiteProper{})

func (s *tpmSimulatorTestSuiteProper) TestResetTPMSimulator(c *C) {
	origCurrentTime, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	s.ResetTPMSimulator(c)

	currentTime, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, origCurrentTime.ClockInfo.ResetCount+1)
}

func (s *tpmSimulatorTestSuiteProper) TestResetAndClearTPMSimulatorUsingPlatformHierarchy(c *C) {
	s.ResetTPMSimulator(c) // Increment reset count so we can detect the clea
	c.Check(s.TPM.ClearControl(s.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	s.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)

	currentTime, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, uint32(0))
}
