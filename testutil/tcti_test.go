// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	. "github.com/canonical/go-tpm2/testutil"
)

type ignoreCloseTcti struct {
	tcti   tpm2.TCTI
	closed bool
}

func (t *ignoreCloseTcti) Read(data []byte) (int, error) {
	if t.closed {
		return 0, errors.New("already closed")
	}
	return t.tcti.Read(data)
}

func (t *ignoreCloseTcti) Write(data []byte) (int, error) {
	if t.closed {
		return 0, errors.New("already closed")
	}
	return t.tcti.Write(data)
}

func (t *ignoreCloseTcti) Close() error {
	if t.closed {
		return errors.New("already closed")
	}
	t.closed = true
	return nil
}

func (t *ignoreCloseTcti) SetLocality(locality uint8) error {
	return t.tcti.SetLocality(locality)
}

func (t *ignoreCloseTcti) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return t.tcti.MakeSticky(handle, sticky)
}

func (t *ignoreCloseTcti) Unwrap() tpm2.TCTI {
	return t.tcti
}

type tctiSuite struct {
	TPMSimulatorTest
}

func (s *tctiSuite) SetUpTest(c *C) {
	// Skip TPMSimulatorTest.SetUpTest and TPMTest.SetUpTest
	s.BaseTest.SetUpTest(c)
	c.Assert(s.TCTI, IsNil)
	c.Assert(s.TPM, IsNil)
}

func (s *tctiSuite) initTPMContext(c *C, permittedFeatures TPMFeatureFlags) {
	restore := MockWrapMssimTCTI(func(tcti tpm2.TCTI, _ TPMFeatureFlags) (*TCTI, error) {
		return WrapTCTI(&ignoreCloseTcti{tcti: tcti}, permittedFeatures)
	})
	defer restore()

	s.TPM, s.TCTI = NewTPMSimulatorContext(c)

	s.AddCleanup(func() {
		// The test has to call Close()
		c.Check(s.TCTI.Unwrap().(*ignoreCloseTcti).closed, IsTrue)

		tpm, _ := tpm2.NewTPMContext(s.Mssim(c))
		s.TPM = tpm

		s.ResetAndClearTPMSimulatorUsingPlatformHierarchy(c)
		c.Check(s.TCTI.Unwrap().(TCTIWrapper).Unwrap().Close(), IsNil)

		s.TPM = nil
		s.TCTI = nil
	})
}

func (s *tctiSuite) rawTpm(c *C) *tpm2.TPMContext {
	c.Assert(s.TCTI, NotNil)
	tpm, _ := tpm2.NewTPMContext(s.Mssim(c))
	return tpm
}

var _ = Suite(&tctiSuite{})

func (s *tctiSuite) deferCloseTpm(c *C) {
	s.AddCleanup(func() {
		c.Check(s.TPM.Close(), IsNil)
	})
}

func (s *tctiSuite) TestCommandLog(c *C) {
	s.initTPMContext(c, 0)
	s.deferCloseTpm(c)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	public := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmNull,
					KeyBits:   &tpm2.SymKeyBitsU{},
					Mode:      &tpm2.SymModeU{}},
				Scheme: tpm2.RSAScheme{
					Scheme:  tpm2.RSASchemeNull,
					Details: &tpm2.AsymSchemeU{}},
				KeyBits:  2048,
				Exponent: uint32(key.PublicKey.E)}},
		Unique: &tpm2.PublicIDU{RSA: key.PublicKey.N.Bytes()}}
	object, err := s.TPM.LoadExternal(nil, &public, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(s.CommandLog(), HasLen, 2)

	cmd := s.CommandLog()[0].GetCommandCode(c)
	c.Check(cmd, Equals, tpm2.CommandLoadExternal)
	cmdHandles, cmdAuthArea, cpBytes := s.CommandLog()[0].UnmarshalCommand(c)
	c.Check(cmdHandles, HasLen, 0)
	c.Check(cmdAuthArea, HasLen, 0)

	var inSensitiveBytes []byte
	var inPublicBytes []byte
	var hierarchy tpm2.Handle
	_, err = mu.UnmarshalFromBytes(cpBytes, &inSensitiveBytes, &inPublicBytes, &hierarchy)
	c.Check(err, IsNil)
	var inPublic *tpm2.Public
	_, err = mu.UnmarshalFromBytes(inPublicBytes, &inPublic)
	c.Assert(err, IsNil)
	c.Check(inSensitiveBytes, HasLen, 0)
	c.Check(inPublic, DeepEquals, &public)
	c.Check(hierarchy, Equals, tpm2.HandleOwner)

	rc, rHandle, rpBytes, rspAuthArea := s.CommandLog()[0].UnmarshalResponse(c)
	c.Check(rHandle, Equals, object.Handle())
	c.Check(rc, Equals, tpm2.Success)
	c.Check(rspAuthArea, HasLen, 0)

	var name tpm2.Name
	_, err = mu.UnmarshalFromBytes(rpBytes, &name)
	c.Check(err, IsNil)
	c.Check(name, DeepEquals, object.Name())

	cmd = s.CommandLog()[1].GetCommandCode(c)
	c.Check(cmd, Equals, tpm2.CommandGetCapability)
	cmdHandles, cmdAuthArea, cpBytes = s.CommandLog()[1].UnmarshalCommand(c)
	c.Check(cmdHandles, HasLen, 0)
	c.Check(cmdAuthArea, HasLen, 0)

	var capability tpm2.Capability
	var property uint32
	var propertyCount uint32
	_, err = mu.UnmarshalFromBytes(cpBytes, &capability, &property, &propertyCount)
	c.Check(err, IsNil)
	c.Check(capability, Equals, tpm2.CapabilityHandles)
	c.Check(property, Equals, uint32(object.Handle()))
	c.Check(propertyCount, Equals, uint32(1))

	rc, rHandle, rpBytes, rspAuthArea = s.CommandLog()[1].UnmarshalResponse(c)
	c.Check(rc, Equals, tpm2.Success)
	c.Check(rHandle, Equals, tpm2.HandleUnassigned)
	c.Check(rspAuthArea, HasLen, 0)

	var moreData bool
	var capabilityData tpm2.CapabilityData
	_, err = mu.UnmarshalFromBytes(rpBytes, &moreData, &capabilityData)
	c.Check(err, IsNil)
	c.Check(moreData, Equals, false)
	c.Check(capabilityData, DeepEquals, tpm2.CapabilityData{
		Capability: tpm2.CapabilityHandles,
		Data: &tpm2.CapabilitiesU{
			Handles: tpm2.HandleList{object.Handle()}}})
}

type testHierarchyAllowedData struct {
	hierarchy         tpm2.Handle
	permittedFeatures TPMFeatureFlags
}

func (s *tctiSuite) testHierarchyAllowed(c *C, data *testHierarchyAllowedData) {
	s.initTPMContext(c, data.permittedFeatures)
	s.deferCloseTpm(c)

	_, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.GetPermanentContext(data.hierarchy), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestOwnerHierarchyAllowed(c *C) {
	s.testHierarchyAllowed(c, &testHierarchyAllowedData{hierarchy: tpm2.HandleOwner, permittedFeatures: TPMFeatureOwnerHierarchy})
}

func (s *tctiSuite) TestEndorsementHierarchyAllowed(c *C) {
	s.testHierarchyAllowed(c, &testHierarchyAllowedData{hierarchy: tpm2.HandleEndorsement, permittedFeatures: TPMFeatureEndorsementHierarchy})
}

func (s *tctiSuite) TestPlatformHierarchyAllowed(c *C) {
	s.testHierarchyAllowed(c, &testHierarchyAllowedData{hierarchy: tpm2.HandlePlatform, permittedFeatures: TPMFeaturePlatformHierarchy})
}

type testHierarchyDisallowedData struct {
	hierarchy tpm2.Handle

	err string
}

func (s *tctiSuite) testHierarchyDisallowed(c *C, data *testHierarchyDisallowedData) {
	s.initTPMContext(c, 0)
	s.deferCloseTpm(c)

	_, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.GetPermanentContext(data.hierarchy), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, ErrorMatches, data.err)
}

func (s *tctiSuite) TestOwnerHierarchyDisallowed(c *C) {
	s.testHierarchyDisallowed(c, &testHierarchyDisallowedData{
		hierarchy: tpm2.HandleOwner,
		err:       `cannot complete write operation on TCTI: command TPM_CC_CreatePrimary is trying to use a non-requested feature \(missing: 0x00000001\)`})
}

func (s *tctiSuite) TestEndorsementHierarchyDisallowed(c *C) {
	s.testHierarchyDisallowed(c, &testHierarchyDisallowedData{
		hierarchy: tpm2.HandleEndorsement,
		err:       `cannot complete write operation on TCTI: command TPM_CC_CreatePrimary is trying to use a non-requested feature \(missing: 0x00000002\)`})
}

func (s *tctiSuite) TestPlatformHierarchyDisallowed(c *C) {
	s.testHierarchyDisallowed(c, &testHierarchyDisallowedData{
		hierarchy: tpm2.HandlePlatform,
		err:       `cannot complete write operation on TCTI: command TPM_CC_CreatePrimary is trying to use a non-requested feature \(missing: 0x00000008\)`})
}

func (s *tctiSuite) TestLockoutHierarchyAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestLockoutHierarchyDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureNV)
	s.deferCloseTpm(c)

	err := s.TPM.DictionaryAttackLockReset(s.TPM.LockoutHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_DictionaryAttackLockReset is trying to use a non-requested feature \(missing: 0x00000804\)`)
}

func (s *tctiSuite) TestPCRAllowed(c *C) {
	s.initTPMContext(c, TPMFeaturePCR|TPMFeatureNV)
	s.deferCloseTpm(c)

	_, _, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(err, IsNil)
	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestPCRDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureNV)
	s.deferCloseTpm(c)

	_, _, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(err, IsNil)
	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(0), []byte("foo"), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_PCR_Event is trying to use a non-requested feature \(missing: 0x00000010\)`)
}

func (s *tctiSuite) TestHierarchyControlAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureStClearChange|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
}

func (s *tctiSuite) TestHierarchyControlDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	err := s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_HierarchyControl is trying to use a non-requested feature \(missing: 0x00000020\)`)
}

func (s *tctiSuite) TestHierarchyControlAllowedWithPlatform(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureSetCommandCodeAuditStatus)
	s.deferCloseTpm(c)

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil), IsNil)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.SetCommandCodeAuditStatus(s.TPM.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_SetCommandCodeAuditStatus is trying to use a non-requested feature \(missing: 0x00000040\)`)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusAllowedWithEndorsementAndOwner(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureEndorsementHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil), IsNil)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusAllowedWithEndorsementAndPlatform(c *C) {
	s.initTPMContext(c, TPMFeatureEndorsementHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.PlatformHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil), IsNil)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusWithEndorsementAndOwnerRequiresNV(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureEndorsementHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.SetCommandCodeAuditStatus(s.TPM.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_SetCommandCodeAuditStatus is trying to use a non-requested feature \(missing: 0x00001000\)`)
}

func (s *tctiSuite) TestClearAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureClear)
	s.deferCloseTpm(c)

	c.Check(s.TPM.Clear(s.TPM.LockoutHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestClearDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.Clear(s.TPM.LockoutHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Clear is trying to use a non-requested feature \(missing: 0x00000080\)`)
}

func (s *tctiSuite) TestClearControlAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureClearControl)
	s.deferCloseTpm(c)

	c.Check(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)
}

func (s *tctiSuite) TestClearControlDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_ClearControl is trying to use a non-requested feature \(missing: 0x00000100\)`)
}

func (s *tctiSuite) TestClearControlAllowedWithPlatform(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil), IsNil)
}

func (s *tctiSuite) TestClearControlWithPlatformRequiresNV(c *C) {
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeaturePlatformHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.ClearControl(s.TPM.LockoutHandleContext(), true, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_ClearControl is trying to use a non-requested feature \(missing: 0x00001000\)`)
}

func (s *tctiSuite) TestFeatureShutdownAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureShutdown)
	s.deferCloseTpm(c)

	c.Check(s.TPM.Shutdown(tpm2.StartupState), IsNil)
}

func (s *tctiSuite) TestFeatureShutdownDisallowed(c *C) {
	s.initTPMContext(c, 0)
	s.deferCloseTpm(c)

	err := s.TPM.Shutdown(tpm2.StartupState)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Shutdown is trying to use a non-requested feature \(missing: 0x00000200\)`)
}

func (s *tctiSuite) TestNVGlobalWriteLockAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNVGlobalWriteLock)
	s.deferCloseTpm(c)

	c.Check(s.TPM.NVGlobalWriteLock(s.TPM.OwnerHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestNVGlobalWriteLockDisllowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	err := s.TPM.NVGlobalWriteLock(s.TPM.OwnerHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_NV_GlobalWriteLock is trying to use a non-requested feature \(missing: 0x00000400\)`)
}

func (s *tctiSuite) TestDAProtectedCapabilityAllowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureDAProtectedCapability|TPMFeatureNV)
	s.deferCloseTpm(c)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(s.TPM.NVWrite(index, index, []byte("foo"), 0, nil), IsNil)
}

func (s *tctiSuite) TestDAProtectedCapabilityDisallowed(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	err = s.TPM.NVWrite(index, index, []byte("foo"), 0, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_NV_Write is trying to use a non-requested feature \(missing: 0x00000800\)`)
}

func (s *tctiSuite) TestRestorePlatformHierarchyAuth(c *C) {
	// Test that changes to the platform hierarchy authorization value are undone.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.PlatformHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	c.Check(s.rawTpm(c).HierarchyChangeAuth(s.rawTpm(c).PlatformHandleContext(), nil, nil), IsNil)
}

func (s *tctiSuite) TestRestorePlatformHierarchyAuthAfterDisablePlatform(c *C) {
	// Test that Close() succeeds if we can't restore the platform hierarchy
	// authorization value because the platform hierarchy was disabled.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.PlatformHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)
}

type testRestoreHierarchyControlData struct {
	permittedFeatures TPMFeatureFlags
	auth              tpm2.Handle
	enable            tpm2.Handle
	attr              tpm2.StartupClearAttributes
}

func (s *tctiSuite) testRestoreHierarchyControl(c *C, data *testRestoreHierarchyControlData) {
	s.initTPMContext(c, data.permittedFeatures|TPMFeaturePlatformHierarchy|TPMFeatureNV)

	c.Check(s.TPM.HierarchyControl(s.TPM.GetPermanentContext(data.auth), data.enable, false, nil), IsNil)

	// Note that restoring this hierarchy requires the use of the platform hierarchy. Change its auth
	// value to make sure this isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.PlatformHandleContext(), []byte("foo"), nil), IsNil)

	props, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyStartupClear)
	enabled := tpm2.StartupClearAttributes(props[0].Value)&data.attr > 0
	c.Check(enabled, IsFalse)

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyStartupClear)
	enabled = tpm2.StartupClearAttributes(props[0].Value)&data.attr > 0
	c.Check(enabled, IsTrue)
}

func (s *tctiSuite) TestRestoreHierarchyControlOwner(c *C) {
	// Test that the owner hierarchy is reenabled if the test disables it.
	s.testRestoreHierarchyControl(c, &testRestoreHierarchyControlData{
		permittedFeatures: TPMFeatureOwnerHierarchy,
		auth:              tpm2.HandleOwner,
		enable:            tpm2.HandleOwner,
		attr:              tpm2.AttrShEnable})
}

func (s *tctiSuite) TestRestoreHierarchyControlEndorsement(c *C) {
	// Test that the endorsement hierarchy is reenabled if the test disables it.
	s.testRestoreHierarchyControl(c, &testRestoreHierarchyControlData{
		permittedFeatures: TPMFeatureEndorsementHierarchy,
		auth:              tpm2.HandleEndorsement,
		enable:            tpm2.HandleEndorsement,
		attr:              tpm2.AttrEhEnable})
}

func (s *tctiSuite) TestRestoreHierarchyControlPlatformNV(c *C) {
	// Test that the platformNV hierarchy is reenabled if the test disables it.
	s.testRestoreHierarchyControl(c, &testRestoreHierarchyControlData{
		auth:   tpm2.HandlePlatform,
		enable: tpm2.HandlePlatformNV,
		attr:   tpm2.AttrPhEnableNV})
}

func (s *tctiSuite) testRestoreHierarchyAuth(c *C, handle tpm2.Handle) {
	s.initTPMContext(c, TPMFeatureFlags(math.MaxUint32))

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.GetPermanentContext(handle), []byte("foo"), nil), IsNil)

	if handle != tpm2.HandleLockout {
		// Note that restoring this auth value requires that the hierarchy is enabled. Disable it
		// to make sure this isn't a problem.
		c.Check(s.TPM.HierarchyControl(s.TPM.GetPermanentContext(handle), handle, false, nil), IsNil)
	}

	c.Check(s.TPM.Close(), IsNil)

	c.Check(s.rawTpm(c).HierarchyChangeAuth(s.rawTpm(c).GetPermanentContext(handle), nil, nil), IsNil)
}

func (s *tctiSuite) TestRestoreOwnerHierarchyAuth(c *C) {
	// Test that the owner hierarchy auth value is retored.
	s.testRestoreHierarchyAuth(c, tpm2.HandleOwner)
}

func (s *tctiSuite) TestRestoreEndorsementHierarchyAuth(c *C) {
	// Test that the endorsement hierarchy auth value is retored.
	s.testRestoreHierarchyAuth(c, tpm2.HandleEndorsement)
}

func (s *tctiSuite) TestRestoreLockoutHierarchyAuth(c *C) {
	// Test that the lockout hierarchy auth value is retored.
	s.testRestoreHierarchyAuth(c, tpm2.HandleLockout)
}

func (s *tctiSuite) TestManualRestoreHierarchyAuthChangeWithCommandEncrypt(c *C) {
	// Test that Close() succeeds if the hierarchy auth is manually restored
	// after initially changing it with command encryption.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	sym := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}
	session, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, &sym, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), session.WithAttrs(tpm2.AttrCommandEncrypt)), IsNil)
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), nil, nil), IsNil)
}

func (s *tctiSuite) TestNoManualRestoreHierarchyAuthChangeWithCommandEncryption(c *C) {
	// Test that Close() fails if the hierarchy auth is not manually restored
	// after changing it with command encryption.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)

	sym := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}
	session, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, &sym, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), session.WithAttrs(tpm2.AttrCommandEncrypt)), IsNil)
	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot clear auth value for TPM_RH_OWNER: TPM returned an error for session 1 whilst executing command TPM_CC_HierarchyChangeAuth: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)\n`)
}

func (s *tctiSuite) TestRestoreHierarchyAuthFailsIfPlatformIsDisabled(c *C) {
	// Test that Close() fails if the owner hierarchy auth cannot be restored
	// because both it and the platform hierarchy have been disabled.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot clear auth value for TPM_RH_OWNER: TPM returned an error for handle 1 whilst executing command TPM_CC_HierarchyChangeAuth: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestRestoreHierarchyAuthFailsIfHierarchyIsDisabled(c *C) {
	// Test that Close() fails if the owner hierarchy auth cannot be restored
	// because it has been disabled and use of the platform hierarchy is not
	// permitted in order to reenable it.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot clear auth value for TPM_RH_OWNER: TPM returned an error for handle 1 whilst executing command TPM_CC_HierarchyChangeAuth: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestRestoreDisableClear(c *C) {
	// Test that disableClear is restored correctly if the test can
	// use the platform hierarchy.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)

	c.Check(s.TPM.ClearControl(s.TPM.PlatformHandleContext(), true, nil), IsNil)

	props, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	disabled := tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0
	c.Check(disabled, IsTrue)

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	disabled = tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0
	c.Check(disabled, IsFalse)
}

func (s *tctiSuite) TestRestoreDisableClearFailsIfPlatformIsDisabled(c *C) {
	// Test that Close() fails if it cannot restore disableClear because the
	// platform hierarchy was disabled and TPMFeatureClearControl isn't defined.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(s.TPM.ClearControl(s.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot restore disableClear: TPM returned an error for handle 1 whilst executing command TPM_CC_ClearControl: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestRestoreDisableClearIgnoresErrorWhenPermitted(c *C) {
	// Test that Close() succeeds if it cannot restore disableClear but
	// TPMFeatureClearControl is defined.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureClearControl|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.ClearControl(s.TPM.PlatformHandleContext(), true, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)
}

func (s *tctiSuite) TestRestoreDACounter(c *C) {
	// Test that we can access a DA protected resource and that the DA counter
	// is reset if we don't have TPMFeatureDAProtectedCapability but we do have
	// TPMFeatureLockoutHierarchy.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureLockoutHierarchy|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), []byte("foo"), &nvPublic, nil)
	c.Assert(err, IsNil)

	index.SetAuthValue(nil)
	err = s.TPM.NVWrite(index, index, []byte("bar"), 0, nil)
	c.Check(err, ErrorMatches, `TPM returned an error for session 1 whilst executing command TPM_CC_NV_Write: TPM_RC_AUTH_FAIL \(the authorization HMAC check failed and DA counter incremented\)`)

	props, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyLockoutCounter, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Value, Equals, uint32(1))

	// Check that changing the lockout hierarchy auth value isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityTPMProperties(tpm2.PropertyLockoutCounter, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Value, Equals, uint32(0))
}

func (s *tctiSuite) TestRestoreDAParams(c *C) {
	// Test that DA parameters are restored properly.
	s.initTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureNV)

	origProps, err := s.TPM.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	c.Check(err, IsNil)
	c.Assert(origProps, HasLen, 3)

	c.Check(s.TPM.DictionaryAttackParameters(s.TPM.LockoutHandleContext(), math.MaxUint32, math.MaxUint32, math.MaxUint32, nil), IsNil)

	// Check that changing the lockout hierarchy auth value isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.LockoutHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err := s.rawTpm(c).GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	c.Check(err, IsNil)
	c.Check(props, DeepEquals, origProps)
}

func (s *tctiSuite) TestCreateAndFlushPrimaryObject(c *C) {
	// Test that transient objects created with CreatePrimary are flushed from the TPM.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushObject(c *C) {
	// Test that transient objects loaded in to the TPM are flushed.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestCreateAndFlushHMACObject(c *C) {
	// Test that HMAC sequence objects are flushed from the TPM.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrNoDA,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: &tpm2.SchemeKeyedHashU{
						HMAC: &tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}}}}}}
	key, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	seq, err := s.TPM.HMACStart(key, nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, seq.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushRestoredObject(c *C) {
	// Test that restored transient objects are flushed from the TPM.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)

	object2, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(object2.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object2.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(object2.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushExternalObject(c *C) {
	// Test that external objects are flushed from the TPM.
	s.initTPMContext(c, 0)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	public := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
				Exponent:  uint32(key.PublicKey.E)}},
		Unique: &tpm2.PublicIDU{RSA: key.PublicKey.N.Bytes()}}
	object, err := s.TPM.LoadExternal(nil, &public, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestCreateAndFlushHashObject(c *C) {
	// Test that has sequence objects are flushed from the TPM.
	s.initTPMContext(c, 0)

	seq, err := s.TPM.HashSequenceStart(nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, seq.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestStartAndFlushSession(c *C) {
	// Test that sessions are flushed from the TPM.
	s.initTPMContext(c, 0)

	session, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, session.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushRestoredSession(c *C) {
	s.initTPMContext(c, 0)

	session, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(session)
	c.Assert(err, IsNil)

	session2, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, session2.Handle())

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestEvictPersistentObjects(c *C) {
	// Test that persistent objects are evicted from the TPM.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureNV)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	persistent, err := s.TPM.EvictControl(s.TPM.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(persistent.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, persistent.Handle())

	// Check that changing the owner hierarchy auth value and then disabling the hierarchy
	// isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(persistent.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestEvictPersistentObjectError(c *C) {
	// Test that a failure to evict a persistent object results in an error.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	// Disable the owner and platform hierarchies.
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot evict 0x81000001: TPM returned an error for handle 1 whilst executing command TPM_CC_EvictControl: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestUndefineNVIndex(c *C) {
	// Test that NV indexes are undefined.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	_, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	props, err := s.TPM.GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0], Equals, nvPublic.Index)

	// Check that changing the owner hierarchy auth value and then disabling the hierarchy
	// isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err = s.rawTpm(c).GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestUndefineNVIndexError(c *C) {
	// Test that a failure to undefine a NV index results in an error.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	_, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	// Disable the owner and platform hierarchies.
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot undefine 0x01800000: TPM returned an error for handle 1 whilst executing command TPM_CC_NV_UndefineSpace: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestUndefinePolicyDeleteNVIndex(c *C) {
	// Test that Close() fails with an error if a test doesn't undefine a
	// TPMA_NV_POLICY_DELETE index.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(tpm2.CommandNVUndefineSpaceSpecial)

	nvPublic := tpm2.NVPublic{
		Index:      0x01800000,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA | tpm2.AttrNVPolicyDelete | tpm2.AttrNVPlatformCreate),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	index, err := s.TPM.NVDefineSpace(s.TPM.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)
	s.AddCleanup(func() {
		// We test that the fixture can't undefine this index, but we should actually undefine it
		// after completing the test.
		session, err := s.rawTpm(c).StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
		c.Assert(err, IsNil)
		c.Check(s.rawTpm(c).PolicyAuthValue(session), IsNil)
		c.Check(s.rawTpm(c).PolicyCommandCode(session, tpm2.CommandNVUndefineSpaceSpecial), IsNil)
		c.Check(s.rawTpm(c).NVUndefineSpaceSpecial(index, s.rawTpm(c).PlatformHandleContext(), session, nil), IsNil)
	})

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- the test needs to undefine index 0x01800000 which has the TPMA_NV_POLICY_DELETE attribute set\n`)
}

func (s *tctiSuite) TestNVUndefineSpaceSpecial(c *C) {
	// Test that a NV index being undefined by the test is handled correctly.
	s.initTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(tpm2.CommandNVUndefineSpaceSpecial)

	nvPublic := tpm2.NVPublic{
		Index:      0x01800000,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA | tpm2.AttrNVPolicyDelete | tpm2.AttrNVPlatformCreate),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	index, err := s.TPM.NVDefineSpace(s.TPM.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Assert(err, IsNil)

	session, err := s.TPM.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)
	c.Check(s.TPM.PolicyCommandCode(session, tpm2.CommandNVUndefineSpaceSpecial), IsNil)

	c.Check(s.TPM.NVUndefineSpaceSpecial(index, s.TPM.PlatformHandleContext(), session, nil), IsNil)
}

func (s *tctiSuite) TestEvictControl(c *C) {
	// Test that a persistent object being evicted by the test is handled correctly.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	persistent, err := s.TPM.EvictControl(s.TPM.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), persistent, persistent.Handle(), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestNVUndefineSpace(c *C) {
	// Test that a NV index being undefined by the test is handled correctly.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index, err := s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(s.TPM.NVUndefineSpace(s.TPM.OwnerHandleContext(), index, nil), IsNil)
}

func (s *tctiSuite) TestClear(c *C) {
	// Test that TPM_CC_Clear works correctly and that the test cleans
	// up the platform hierarchy at the end of the test.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureLockoutHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureClear|TPMFeatureNV)

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt | tpm2.AttrNoDA,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}

	oObject, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)
	_, err = s.TPM.EvictControl(s.TPM.OwnerHandleContext(), oObject, 0x81000001, nil)
	c.Check(err, IsNil)

	pObject, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.PlatformHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)
	pPersist, err := s.TPM.EvictControl(s.TPM.PlatformHandleContext(), pObject, 0x81800000, nil)
	c.Assert(err, IsNil)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}

	_, err = s.TPM.NVDefineSpace(s.TPM.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	nvPublic.Index = 0x01400000
	nvPublic.Attrs |= tpm2.AttrNVPlatformCreate
	_, err = s.TPM.NVDefineSpace(s.TPM.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.PlatformHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(s.TPM.Clear(s.TPM.LockoutHandleContext(), nil), IsNil)

	c.Check(s.TPM.Close(), IsNil)

	// Verify that platform objects have gone
	props, err := s.rawTpm(c).GetCapabilityHandles(pPersist.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)

	props, err = s.rawTpm(c).GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

type testRestoreCommandCodeAuditStatusData struct {
	handle           tpm2.Handle
	disableHierarchy bool
	permission       TPMFeatureFlags
}

func (s *tctiSuite) testRestoreCommandCodeAuditStatus(c *C, data *testRestoreCommandCodeAuditStatusData) {
	s.initTPMContext(c, TPMFeatureEndorsementHierarchy|TPMFeatureNV|data.permission)

	restoreCommands, err := s.TPM.GetCapabilityAuditCommands(tpm2.CommandFirst, tpm2.CapabilityMaxProperties)
	c.Assert(err, IsNil)
	auditInfo, _, err := s.TPM.GetCommandAuditDigest(s.TPM.EndorsementHandleContext(), nil, nil, nil, nil, nil)
	c.Assert(err, IsNil)
	restoreAlg := auditInfo.Attested.CommandAudit.DigestAlg

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.GetPermanentContext(data.handle), tpm2.HashAlgorithmSHA1, nil, nil, nil), IsNil)
	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.GetPermanentContext(data.handle), tpm2.HashAlgorithmNull, tpm2.CommandCodeList{tpm2.CommandStirRandom}, restoreCommands, nil), IsNil)

	commands, err := s.TPM.GetCapabilityAuditCommands(tpm2.CommandFirst, tpm2.CapabilityMaxProperties)
	c.Assert(err, IsNil)
	c.Check(commands, DeepEquals, tpm2.CommandCodeList{tpm2.CommandSetCommandCodeAuditStatus, tpm2.CommandStirRandom})
	auditInfo, _, err = s.TPM.GetCommandAuditDigest(s.TPM.EndorsementHandleContext(), nil, nil, nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(auditInfo.Attested.CommandAudit.DigestAlg, Equals, tpm2.AlgorithmSHA1)

	// Check that changing the endorsement hierarchy auth value and then disabling the hierarchy
	// isn't a problem.
	c.Check(s.TPM.HierarchyChangeAuth(s.TPM.EndorsementHandleContext(), []byte("foo"), nil), IsNil)
	if data.disableHierarchy {
		c.Check(s.TPM.HierarchyControl(s.TPM.EndorsementHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
	}

	c.Check(s.TPM.Close(), IsNil)

	commands, err = s.rawTpm(c).GetCapabilityAuditCommands(tpm2.CommandFirst, tpm2.CapabilityMaxProperties)
	c.Assert(err, IsNil)
	c.Check(commands, DeepEquals, restoreCommands)
	auditInfo, _, err = s.rawTpm(c).GetCommandAuditDigest(s.rawTpm(c).EndorsementHandleContext(), nil, nil, nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(auditInfo.Attested.CommandAudit.DigestAlg, Equals, restoreAlg)
}

func (s *tctiSuite) TestRestoreCommandCodeAuditStatusOwner(c *C) {
	// Test that changes made with TPM2_SetCommandCodeAuditStatus are reverted when use of the owner
	// hierarchy is permitted.
	s.testRestoreCommandCodeAuditStatus(c, &testRestoreCommandCodeAuditStatusData{
		handle:     tpm2.HandleOwner,
		permission: TPMFeatureOwnerHierarchy})
}

func (s *tctiSuite) TestRestoreCommandCodeAuditStatusPlatform(c *C) {
	// Test that changes made with TPM2_SetCommandCodeAuditStatus are reverted when use of the platform
	// hierarchy is permitted.
	s.testRestoreCommandCodeAuditStatus(c, &testRestoreCommandCodeAuditStatusData{
		handle:           tpm2.HandlePlatform,
		disableHierarchy: true,
		permission:       TPMFeaturePlatformHierarchy})
}

func (s *tctiSuite) TestRestoreCommandCodeAuditStatusFailsIfPlatformIsDisabled(c *C) {
	// Test that Close() returns an error if changes made with TPM2_SetCommandCodeAuditStatus can't
	// be reverted because the endorsement hierarchy has been disabled and can't be re-enabled.
	s.initTPMContext(c, TPMFeatureEndorsementHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.PlatformHandleContext(), tpm2.HashAlgorithmSHA1, nil, nil, nil), IsNil)

	// Disable the endorsement and platform hierarchies.
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(s.TPM.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot restore command code audit alg: TPM returned an error for handle 1 whilst executing command TPM_CC_SetCommandCodeAuditStatus: TPM_RC_HIERARCHY \(hierarchy is not enabled or is not correct for the use\)\n`)
}

func (s *tctiSuite) TestRestoreCommandCodeAuditStatusIgnoresErrorWhenPermitted(c *C) {
	// Test that Close() succeeds if changes made with TPM2_SetCommandCodeAuditStatus can't
	// be reverted because the endorsement hierarchy has been disabled and can't be re-enabled,
	// but TPMFeatureSetCommandCodeAuditStatus is defined.
	s.initTPMContext(c, TPMFeatureEndorsementHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureSetCommandCodeAuditStatus|TPMFeatureNV)
	s.deferCloseTpm(c)

	c.Check(s.TPM.SetCommandCodeAuditStatus(s.TPM.PlatformHandleContext(), tpm2.HashAlgorithmSHA1, nil, nil, nil), IsNil)

	// Disable the endorsement and platform hierarchies.
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandleEndorsement, false, nil), IsNil)
	c.Check(s.TPM.HierarchyControl(s.TPM.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)
}

func (s *tctiSuite) testUseCreatedPrimaryNoDA(c *C, extraFeatures TPMFeatureFlags) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|extraFeatures)
	s.deferCloseTpm(c)

	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	_, _, _, _, _, err = s.TPM.Create(object, nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseCreatedPrimaryNoDAPermitDA(c *C) {
	s.testUseCreatedPrimaryNoDA(c, TPMFeatureDAProtectedCapability)
}

func (s *tctiSuite) TestUseCreatedPrimaryNoDAForbidDA(c *C) {
	s.testUseCreatedPrimaryNoDA(c, 0)
}

func (s *tctiSuite) TestUseCreatedPrimaryDAPermitted(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureDAProtectedCapability)
	s.deferCloseTpm(c)

	template := StorageKeyRSATemplate()
	template.Attrs &^= tpm2.AttrNoDA
	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, template, nil, nil, nil)
	c.Assert(err, IsNil)

	_, _, _, _, _, err = s.TPM.Create(object, nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseCreatedPrimaryDAForbidden(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	template := StorageKeyRSATemplate()
	template.Attrs &^= tpm2.AttrNoDA
	object, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, template, nil, nil, nil)
	c.Assert(err, IsNil)

	_, _, _, _, _, err = s.TPM.Create(object, nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Create is trying to use a non-requested feature \(missing: 0x00000800\)`)
}

func (s *tctiSuite) testUseLoadedObjectNoDA(c *C, extraFeatures TPMFeatureFlags) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|extraFeatures)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrNoDA | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseLoadedObjectNoDAPermitDA(c *C) {
	s.testUseLoadedObjectNoDA(c, TPMFeatureDAProtectedCapability)
}

func (s *tctiSuite) TestUseLoadedObjectNoDAForbidDA(c *C) {
	s.testUseLoadedObjectNoDA(c, 0)
}

func (s *tctiSuite) TestUseLoadedObjectDAPermitted(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureDAProtectedCapability)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseLoadedObjectDAForbidden(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(object, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Unseal is trying to use a non-requested feature \(missing: 0x00000800\)`)
}

func (s *tctiSuite) testUseHMACObject(c *C, extraFeatures TPMFeatureFlags) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|extraFeatures)
	s.deferCloseTpm(c)

	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrNoDA,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: &tpm2.SchemeKeyedHashU{
						HMAC: &tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}}}}}}
	key, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	seq, err := s.TPM.HMACStart(key, nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	c.Check(s.TPM.SequenceUpdate(seq, []byte("foo"), nil), IsNil)
}

func (s *tctiSuite) TestUseHMACObjectDAForbidden(c *C) {
	s.testUseHMACObject(c, 0)
}

func (s *tctiSuite) TestUseHMACObjectDAPermitted(c *C) {
	s.testUseHMACObject(c, TPMFeatureDAProtectedCapability)
}

func (s *tctiSuite) testUseHashObject(c *C, extraFeatures TPMFeatureFlags) {
	s.initTPMContext(c, extraFeatures)
	s.deferCloseTpm(c)

	seq, err := s.TPM.HashSequenceStart(nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	c.Check(s.TPM.SequenceUpdate(seq, []byte("foo"), nil), IsNil)
}

func (s *tctiSuite) TestUseHashObjectDAForbidden(c *C) {
	s.testUseHashObject(c, 0)
}

func (s *tctiSuite) TestUseHashObjectDAPermitted(c *C) {
	s.testUseHashObject(c, TPMFeatureDAProtectedCapability)
}

func (s *tctiSuite) testUseContextLoadedObjectNoDA(c *C, extraFeatures TPMFeatureFlags) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|extraFeatures)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrNoDA | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)

	o, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(o.(tpm2.ResourceContext), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseContextLoadedObjectNoDAPermitDA(c *C) {
	s.testUseContextLoadedObjectNoDA(c, TPMFeatureDAProtectedCapability)
}

func (s *tctiSuite) TestUseContextLoadedObjectNoDAForbidDA(c *C) {
	s.testUseContextLoadedObjectNoDA(c, 0)
}

func (s *tctiSuite) TestUseContextLoadedObjectDAPermitted(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureDAProtectedCapability)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)

	o, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(o.(tpm2.ResourceContext), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestUseContextLoadedObjectDAForbidden(c *C) {
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template := tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := s.TPM.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	context, err := s.TPM.ContextSave(object)
	c.Assert(err, IsNil)

	o, err := s.TPM.ContextLoad(context)
	c.Assert(err, IsNil)

	_, err = s.TPM.Unseal(o.(tpm2.ResourceContext), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Unseal is trying to use a non-requested feature \(missing: 0x00000800\)`)
}

func (s *tctiSuite) TestUseExistingObject(c *C) {
	// Test that we can use a persistent object that we didn't create
	// because TPM2_ReadPublic saves the public area.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	primary, _, _, _, _, err := s.rawTpm(c).CreatePrimary(s.rawTpm(c).OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	persist, err := s.rawTpm(c).EvictControl(s.rawTpm(c).OwnerHandleContext(), primary, 0x81000001, nil)
	c.Assert(err, IsNil)

	rc, err := s.TPM.CreateResourceContextFromTPM(persist.Handle())
	c.Check(err, IsNil)

	_, _, _, _, _, err = s.TPM.Create(rc, nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestDontEvictExistingObject(c *C) {
	// Test that Close() doesn't evict an object that we didn't create,
	// but which the fixture is aware of (via TPM2_ReadPublic).
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	primary, _, _, _, _, err := s.rawTpm(c).CreatePrimary(s.rawTpm(c).OwnerHandleContext(), nil, StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	persist, err := s.rawTpm(c).EvictControl(s.rawTpm(c).OwnerHandleContext(), primary, 0x81000001, nil)
	c.Assert(err, IsNil)

	_, err = s.TPM.CreateResourceContextFromTPM(persist.Handle())
	c.Check(err, IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err := s.rawTpm(c).GetCapabilityHandles(persist.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, persist.Handle())
}

func (s *tctiSuite) TestUseExistingIndex(c *C) {
	// Test that we can use a NV index that we didn't create
	// because TPM2_NV_ReadPublic saves the public area.
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index, err := s.rawTpm(c).NVDefineSpace(s.rawTpm(c).OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)
	c.Check(s.rawTpm(c).NVWrite(index, index, []byte("foo"), 0, nil), IsNil)

	rc, err := s.TPM.CreateResourceContextFromTPM(nvPublic.Index)
	c.Check(err, IsNil)

	_, err = s.TPM.NVRead(rc, rc, 8, 0, nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestDontEvictExistingIndex(c *C) {
	// Test that Close() doesn't evict a NV index that we didn't create,
	// but which the fixture is aware of (via TPM2_NV_ReadPublic).
	s.initTPMContext(c, TPMFeatureOwnerHierarchy)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index, err := s.rawTpm(c).NVDefineSpace(s.rawTpm(c).OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)
	c.Check(s.rawTpm(c).NVWrite(index, index, []byte("foo"), 0, nil), IsNil)

	_, err = s.TPM.CreateResourceContextFromTPM(nvPublic.Index)
	c.Check(err, IsNil)

	c.Check(s.TPM.Close(), IsNil)

	props, err := s.rawTpm(c).GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, nvPublic.Index)
}
