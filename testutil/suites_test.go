// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mssim"
	"github.com/canonical/go-tpm2/mu"
	. "github.com/canonical/go-tpm2/testutil"
)

type baseTestSuite struct{}

var _ = Suite(&baseTestSuite{})

type mockBaseTestCleanupSuite struct {
	BaseTest
	log []string

	setupCb func(*C)
	testCb  func(*C)
}

func (s *mockBaseTestCleanupSuite) SetUpTest(c *C) {
	s.setupCb(c)
}

func (s *mockBaseTestCleanupSuite) Test1(c *C) {
	s.testCb(c)
}

func (s *mockBaseTestCleanupSuite) Test2(c *C) {
	s.testCb(c)
}

func (s *baseTestSuite) TestCleanup(c *C) {
	suite := new(mockBaseTestCleanupSuite)
	suite.setupCb = func(c *C) {
		suite.InitCleanup(c)
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture1") })
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture2") })
		suite.BaseTest.SetUpTest(c)
	}
	suite.testCb = func(c *C) {
		suite.AddCleanup(func() { suite.log = append(suite.log, c.TestName()+".test1") })
		suite.AddCleanup(func() { suite.log = append(suite.log, c.TestName()+".test2") })
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 2 passed")
	c.Check(suite.log, DeepEquals, []string{
		"mockBaseTestCleanupSuite.Test1.test2",
		"mockBaseTestCleanupSuite.Test1.test1",
		"mockBaseTestCleanupSuite.Test1.fixture2",
		"mockBaseTestCleanupSuite.Test1.fixture1",
		"mockBaseTestCleanupSuite.Test2.test2",
		"mockBaseTestCleanupSuite.Test2.test1",
		"mockBaseTestCleanupSuite.Test2.fixture2",
		"mockBaseTestCleanupSuite.Test2.fixture1"})
}

func (s *baseTestSuite) TestSkipTests(c *C) {
	// Cleanup handlers should run if a test is skipped.
	suite := new(mockBaseTestCleanupSuite)
	suite.setupCb = func(c *C) {
		suite.BaseTest.SetUpTest(c)
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture1") })
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture2") })
	}
	suite.testCb = func(c *C) {
		suite.AddCleanup(func() { suite.log = append(suite.log, c.TestName()+".test1") })
		c.Skip("test skipped")
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 2 skipped")
	c.Check(suite.log, DeepEquals, []string{
		"mockBaseTestCleanupSuite.Test1.test1",
		"mockBaseTestCleanupSuite.Test1.fixture2",
		"mockBaseTestCleanupSuite.Test1.fixture1",
		"mockBaseTestCleanupSuite.Test2.test1",
		"mockBaseTestCleanupSuite.Test2.fixture2",
		"mockBaseTestCleanupSuite.Test2.fixture1"})
}

func (s *baseTestSuite) TestSkipTestsFromFixture(c *C) {
	suite := new(mockBaseTestCleanupSuite)
	suite.setupCb = func(c *C) {
		suite.BaseTest.SetUpTest(c)
		c.Skip("test skipped")
	}
	suite.testCb = func(c *C) {}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 2 skipped")
	c.Check(suite.log, DeepEquals, []string(nil))
}

func (s *baseTestSuite) TestFixtureCleanupError(c *C) {
	// Functions registered in SetUpTest with AddFixtureCleanup should be able to make the
	// fixture panic if they fail.
	suite := new(mockBaseTestCleanupSuite)
	suite.setupCb = func(c *C) {
		suite.BaseTest.SetUpTest(c)
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture1") })
		suite.AddFixtureCleanup(func(c *C) { c.Error("error") })
	}
	suite.testCb = func(c *C) {
		suite.AddCleanup(func() { suite.log = append(suite.log, c.TestName()+".test1") })
		c.Skip("test skipped")
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OOPS: 0 passed, 1 FAILED, 2 MISSED")
	c.Check(suite.log, DeepEquals, []string{"mockBaseTestCleanupSuite.Test1.test1", "mockBaseTestCleanupSuite.Test1.fixture1"})
}

func (s *baseTestSuite) TestSkipTestFromFixtureAfterAddCleanup(c *C) {
	// If a test is skipped in SetUpTest, TearDownTest isn't called and no
	// cleanup handlers run. Make sure this results in a failure if a test is
	// skipped after calling AddFixtureCleanup.
	suite := new(mockBaseTestCleanupSuite)
	suite.setupCb = func(c *C) {
		suite.BaseTest.SetUpTest(c)
		suite.AddFixtureCleanup(func(c *C) { suite.log = append(suite.log, c.TestName()+".fixture1") })
		c.Skip("test skipped")
	}
	suite.testCb = func(c *C) {}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OOPS: 0 passed, 1 skipped, 2 FAILED, 1 MISSED")
	c.Check(suite.log, DeepEquals, []string(nil))
}

type tpmTestSuite struct {
	BaseTest
}

func (s *tpmTestSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	if TPMBackend == TPMBackendNone {
		c.Skip("no tpm available")
	}
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
	c.Check(tpm.Close(), internal_testutil.IsOneOf(ErrorMatches), []string{
		`.*use of closed network connection$`,
		`.*file already closed$`,
		`.*transport already closed$`})
}

func (s *tpmTestSuite) TestTestLifecycleProvidedTransport(c *C) {
	suite := new(TPMTest)

	transport := OpenTransport(c, NewDevice(c, 0))
	suite.TCTI = transport

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Check(suite.TCTI, Equals, transport)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), internal_testutil.IsOneOf(ErrorMatches), []string{
		`.*use of closed network connection$`,
		`.*file already closed$`,
		`.*transport already closed$`})
}

func (s *tpmTestSuite) TestTestLifecycleProvidedTPM(c *C) {
	suite := new(TPMTest)

	tpm, transport := NewTPMContext(c, 0)
	suite.TPM = tpm
	suite.TCTI = transport

	suite.SetUpTest(c)
	c.Check(suite.TPM, Equals, tpm)
	c.Check(suite.TCTI, Equals, transport)

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), internal_testutil.IsOneOf(ErrorMatches), []string{
		`.*use of closed network connection$`,
		`.*file already closed$`,
		`.*transport already closed$`})
}

func (s *tpmTestSuite) TestLifecycleNoCloseTPM(c *C) {
	suite := new(TPMTest)

	suite.SetUpTest(c)
	tpm := suite.TPM
	suite.TPM = nil
	suite.TCTI = nil

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
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

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
}

func (s *tpmTestSuite) TestInvalidSetUp(c *C) {
	suite := new(mockTPMTestSuite)

	tpm, _ := NewTPMContext(c, 0)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})
	suite.TPM = tpm

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OOPS: 0 passed, 1 FAILED, 1 MISSED")
}

func (s *tpmTestSuite) TestLastCommandWithNoCommands(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.LastCommand(c)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OOPS: 0 passed, 1 FAILED")
}

func (s *tpmTestSuite) TestRequireAlgorithm(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireAlgorithm(c, tpm2.AlgorithmRSA)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 1 passed")
}

func (s *tpmTestSuite) TestRequireMissingAlgorithm(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireAlgorithm(c, tpm2.AlgorithmError)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
}

func (s *tpmTestSuite) TestRequireRSAKeySize(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireRSAKeySize(c, 2048)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 1 passed")
}

func (s *tpmTestSuite) TestRequireMissingRSAKeySize(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireRSAKeySize(c, 2047)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
}

func (s *tpmTestSuite) TestRequireECCCurve(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireECCCurve(c, tpm2.ECCCurveNIST_P256)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 1 passed")
}

func (s *tpmTestSuite) TestRequireMissingECCCurve(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireECCCurve(c, tpm2.ECCCurve(0))
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
}

func (s *tpmTestSuite) TestRequireSymmetricAlgorithm(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmAES, 128)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 1 passed")
}

func (s *tpmTestSuite) TestRequireMissingSymmetricAlgorithm(c *C) {
	suite := new(mockTPMTestSuite)
	suite.cb = func(c *C) {
		suite.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmId(tpm2.AlgorithmError), 128)
	}

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
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

	c.Assert(s.CommandLog(), internal_testutil.LenEquals, 2)

	cmd := s.CommandLog()[0]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandSelfTest)
	c.Check(cmd.CmdHandles, internal_testutil.LenEquals, 0)
	c.Check(cmd.CmdAuthArea, internal_testutil.LenEquals, 0)

	var fullTest bool
	_, err = mu.UnmarshalFromBytes(cmd.CpBytes, &fullTest)
	c.Check(err, IsNil)
	c.Check(fullTest, internal_testutil.IsTrue)

	c.Check(cmd.RspCode, Equals, tpm2.ResponseSuccess)
	c.Check(cmd.RspHandle, Equals, tpm2.HandleUnassigned)
	c.Check(cmd.RpBytes, internal_testutil.LenEquals, 0)
	c.Check(cmd.RspAuthArea, internal_testutil.LenEquals, 0)

	cmd = s.CommandLog()[1]
	c.Check(cmd.CmdCode, Equals, tpm2.CommandGetTestResult)
	c.Check(cmd.CmdHandles, internal_testutil.LenEquals, 0)
	c.Check(cmd.CmdAuthArea, internal_testutil.LenEquals, 0)
	c.Check(cmd.CpBytes, internal_testutil.LenEquals, 0)

	c.Check(cmd.RspCode, Equals, tpm2.ResponseSuccess)
	c.Check(cmd.RspHandle, Equals, tpm2.HandleUnassigned)
	c.Check(cmd.RspAuthArea, internal_testutil.LenEquals, 0)

	var outData2 tpm2.MaxBuffer
	var testResult2 tpm2.ResponseCode
	_, err = mu.UnmarshalFromBytes(cmd.RpBytes, &outData2, &testResult2)
	c.Check(err, IsNil)
	c.Check(outData2, DeepEquals, outData)
	c.Check(testResult2, Equals, testResult)
}

func (s *tpmTestSuiteProper) TestLastCommand(c *C) {
	c.Check(s.TPM.SelfTest(true), IsNil)
	_, _, err := s.TPM.GetTestResult()
	c.Check(err, IsNil)

	c.Check(s.LastCommand(c).CmdCode, Equals, tpm2.CommandGetTestResult)
}

func (s *tpmTestSuiteProper) TestForgetCommands(c *C) {
	c.Check(s.TPM.SelfTest(true), IsNil)
	_, _, err := s.TPM.GetTestResult()
	c.Check(err, IsNil)

	s.ForgetCommands()
	c.Check(s.CommandLog(), internal_testutil.LenEquals, 0)
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
	c.Check(s.CommandLog(), internal_testutil.LenEquals, 0)

	c.Check(s.CreateStoragePrimaryKeyRSA(c), Not(DeepEquals), name)

	props, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Assert(err, IsNil)
	c.Assert(props, internal_testutil.LenEquals, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	c.Check(tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear, Equals, tpm2.PermanentAttributes(0))
}

type tpmSimulatorTestSuite struct {
	BaseTest
}

func (s *tpmSimulatorTestSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	if TPMBackend != TPMBackendMssim {
		c.Skip("no tpm available")
	}
}

var _ = Suite(&tpmSimulatorTestSuite{})

func (s *tpmSimulatorTestSuite) TestTestLifecycleDefault(c *C) {
	suite := new(TPMSimulatorTest)

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Assert(suite.TCTI, NotNil)
	c.Check(suite.TCTI.Unwrap(), internal_testutil.ConvertibleTo, &mssim.Transport{})

	suite.ResetTPMSimulator(c) // Increment reset count so we can detect the clea
	c.Check(suite.TPM.ClearControl(suite.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(suite.TPM.HierarchyControl(suite.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), ErrorMatches, `.*transport already closed$`)

	tpm, _ = NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})

	currentTime, err := tpm.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, uint32(0))
}

func (s *tpmSimulatorTestSuite) TestTestLifecycleProvidedTransport(c *C) {
	suite := new(TPMSimulatorTest)

	transport := OpenTransport(c, NewSimulatorDevice())
	suite.TCTI = transport

	suite.SetUpTest(c)
	c.Check(suite.TPM, NotNil)
	c.Check(suite.TCTI, Equals, transport)

	suite.ResetTPMSimulator(c) // Increment reset count so we can detect the clea
	c.Check(suite.TPM.ClearControl(suite.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(suite.TPM.HierarchyControl(suite.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	tpm := suite.TPM

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), ErrorMatches, `.*transport already closed$`)

	tpm, _ = NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})

	currentTime, err := tpm.ReadClock()
	c.Assert(err, IsNil)
	c.Check(currentTime.ClockInfo.ResetCount, Equals, uint32(0))
}

func (s *tpmSimulatorTestSuite) TestTestLifecycleNoResetAndClear(c *C) {
	suite := new(TPMSimulatorTest)

	suite.SetUpTest(c)
	tpm := suite.TPM
	suite.TPM = nil

	suite.TearDownTest(c)
	c.Check(suite.TPM, IsNil)
	c.Check(suite.TCTI, IsNil)
	c.Check(tpm.Close(), IsNil)
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

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OK: 0 passed, 1 skipped")
}

func (s *tpmSimulatorTestSuite) TestInvalidSetUp(c *C) {
	suite := new(mockTPMSimulatorTestSuite)

	tpm, _ := NewTPMSimulatorContext(c)
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})
	suite.TPM = tpm

	result := Run(suite, &RunConf{Output: io.Discard})
	c.Check(result.String(), Equals, "OOPS: 0 passed, 2 FAILED, 1 MISSED")
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
