// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type mockTcti struct {
	tcti   tpm2.TCTI
	closed bool
}

func (t *mockTcti) Read(data []byte) (int, error) {
	return t.tcti.Read(data)
}

func (t *mockTcti) Write(data []byte) (int, error) {
	return t.tcti.Write(data)
}

func (t *mockTcti) Close() error {
	if t.closed {
		return errors.New("already closed")
	}
	t.closed = true
	return nil
}

func (t *mockTcti) SetLocality(locality uint8) error {
	return t.tcti.SetLocality(locality)
}

func (t *mockTcti) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return t.tcti.MakeSticky(handle, sticky)
}

type tctiSuite struct {
	BaseTest
}

var _ = Suite(&tctiSuite{})

func (s *tctiSuite) newTPMContext(c *C, permittedFeatures TPMFeatureFlags) (*tpm2.TPMContext, *tpm2.TPMContext) {
	restore := MockWrapMssimTCTI(func(tcti tpm2.TCTI, _ TPMFeatureFlags) (*TCTI, error) {
		return WrapTCTI(&mockTcti{tcti: tcti}, permittedFeatures)
	})
	defer restore()

	tpm, tcti := NewTPMSimulatorContext(c)

	rawTcti := tcti.Unwrap().(*mockTcti).tcti.(*tpm2.TctiMssim)
	rawTpm, _ := tpm2.NewTPMContext(rawTcti)

	s.AddCleanup(func() {
		c.Check(rawTpm.Shutdown(tpm2.StartupClear), IsNil)
		c.Check(rawTcti.Reset(), IsNil)
		c.Check(rawTpm.Startup(tpm2.StartupClear), IsNil)
		c.Check(rawTpm.ClearControl(rawTpm.PlatformHandleContext(), false, nil), IsNil)
		c.Check(rawTpm.Clear(rawTpm.PlatformHandleContext(), nil), IsNil)
		c.Check(rawTpm.Close(), IsNil)
	})

	return tpm, rawTpm
}

func (s *tctiSuite) deferCloseTpm(c *C, tpm *tpm2.TPMContext) {
	s.AddCleanup(func() {
		c.Check(tpm.Close(), IsNil)
	})
}

type testHierarchyAllowedData struct {
	hierarchy         tpm2.Handle
	permittedFeatures TPMFeatureFlags
}

func (s *tctiSuite) testHierarchyAllowed(c *C, data *testHierarchyAllowedData) {
	tpm, _ := s.newTPMContext(c, data.permittedFeatures)
	s.deferCloseTpm(c, tpm)

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
	_, _, _, _, _, err := tpm.CreatePrimary(tpm.GetPermanentContext(data.hierarchy), nil, &template, nil, nil, nil)
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
	err       string
}

func (s *tctiSuite) testHierarchyDisallowed(c *C, data *testHierarchyDisallowedData) {
	tpm, _ := s.newTPMContext(c, 0)
	s.deferCloseTpm(c, tpm)

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
	_, _, _, _, _, err := tpm.CreatePrimary(tpm.GetPermanentContext(data.hierarchy), nil, &template, nil, nil, nil)
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
	tpm, _ := s.newTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestLockoutHierarchyDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_DictionaryAttackLockReset is trying to use a non-requested feature \(missing: 0x00000804\)`)
}

func (s *tctiSuite) TestPCRAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeaturePCR|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	_, _, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(err, IsNil)
	_, err = tpm.PCREvent(tpm.PCRHandleContext(0), []byte("foo"), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestPCRDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	_, _, err := tpm.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Check(err, IsNil)
	_, err = tpm.PCREvent(tpm.PCRHandleContext(0), []byte("foo"), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_PCR_Event is trying to use a non-requested feature \(missing: 0x00000010\)`)
}

func (s *tctiSuite) TestStClearChangeAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureStClearChange|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.HierarchyControl(tpm.OwnerHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
}

func (s *tctiSuite) TestStClearChangeDisllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	err := tpm.HierarchyControl(tpm.OwnerHandleContext(), tpm2.HandleOwner, false, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_HierarchyControl is trying to use a non-requested feature \(missing: 0x00000020\)`)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureSetCommandCodeAuditStatus)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.SetCommandCodeAuditStatus(tpm.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil), IsNil)
}

func (s *tctiSuite) TestSetCommandCodeAuditStatusDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c, tpm)

	err := tpm.SetCommandCodeAuditStatus(tpm.OwnerHandleContext(), tpm2.HashAlgorithmSHA256, nil, nil, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_SetCommandCodeAuditStatus is trying to use a non-requested feature \(missing: 0x00000040\)`)
}

func (s *tctiSuite) TestClearAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureClear)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.Clear(tpm.LockoutHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestClearDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureLockoutHierarchy)
	s.deferCloseTpm(c, tpm)

	err := tpm.Clear(tpm.LockoutHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Clear is trying to use a non-requested feature \(missing: 0x00000080\)`)
}

func (s *tctiSuite) TestClearControlAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureClearControl)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.ClearControl(tpm.LockoutHandleContext(), true, nil), IsNil)
}

func (s *tctiSuite) TestClearControlDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureLockoutHierarchy)
	s.deferCloseTpm(c, tpm)

	err := tpm.ClearControl(tpm.LockoutHandleContext(), true, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_ClearControl is trying to use a non-requested feature \(missing: 0x00000100\)`)
}

func (s *tctiSuite) TestFeatureShutdownAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureShutdown)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.Shutdown(tpm2.StartupState), IsNil)
}

func (s *tctiSuite) TestFeatureShutdownDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, 0)
	s.deferCloseTpm(c, tpm)

	err := tpm.Shutdown(tpm2.StartupState)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_Shutdown is trying to use a non-requested feature \(missing: 0x00000200\)`)
}

func (s *tctiSuite) TestNVGlobalWriteLockAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNVGlobalWriteLock)
	s.deferCloseTpm(c, tpm)

	c.Check(tpm.NVGlobalWriteLock(tpm.OwnerHandleContext(), nil), IsNil)
}

func (s *tctiSuite) TestNVGlobalWriteLockDisllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy)
	s.deferCloseTpm(c, tpm)

	err := tpm.NVGlobalWriteLock(tpm.OwnerHandleContext(), nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_NV_GlobalWriteLock is trying to use a non-requested feature \(missing: 0x00000400\)`)
}

func (s *tctiSuite) TestDAProtectedCapabilityAllowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureDAProtectedCapability|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(tpm.NVWrite(index, index, []byte("foo"), 0, nil), IsNil)
}

func (s *tctiSuite) TestDAProtectedCapabilityDisallowed(c *C) {
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	err = tpm.NVWrite(index, index, []byte("foo"), 0, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_NV_Write is trying to use a non-requested feature \(missing: 0x00000800\)`)
}

func (s *tctiSuite) TestDisablePlatformHierarchyAllowed(c *C) {
	// Test that the platform hierarchy can be disabled if TPMFeatureStClearChange
	// is specified.
	tpm, rawTpm := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureClearControl|TPMFeatureNV)

	// Set disableClear - this can't be undone, but we shouldn't see an error
	// because of TPMFeatureClearControl
	c.Check(tpm.ClearControl(tpm.PlatformHandleContext(), true, nil), IsNil)

	// Change the platform hierarchy auth - this can't be undone, but we shouldn't
	// see an error because of TPMFeatureStClearChange (it's undone on a
	// TPM_CC_Startup(CLEAR)).
	c.Check(tpm.HierarchyChangeAuth(tpm.PlatformHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	props, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyStartupClear)
	enabled := tpm2.StartupClearAttributes(props[0].Value)&tpm2.AttrPhEnable > 0
	c.Check(enabled, IsFalse)

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyStartupClear)
	enabled = tpm2.StartupClearAttributes(props[0].Value)&tpm2.AttrPhEnable > 0
	c.Check(enabled, IsFalse)
}

func (s *tctiSuite) TestDisablePlatformHierarchyDisallowed(c *C) {
	// Test that disabling the platform hierarchy isn't allowed without
	// TPMFeatureStClearChange.
	tpm, _ := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	err := tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandlePlatform, false, nil)
	c.Check(err, ErrorMatches, `cannot complete write operation on TCTI: command TPM_CC_HierarchyControl is trying to use a non-requested feature \(missing: 0x00000020\)`)
}

type testRestoreHierarchyControlData struct {
	permittedFeatures TPMFeatureFlags
	auth              tpm2.Handle
	enable            tpm2.Handle
	attr              tpm2.StartupClearAttributes
}

func (s *tctiSuite) testRestoreHierarchyControl(c *C, data *testRestoreHierarchyControlData) {
	tpm, rawTpm := s.newTPMContext(c, data.permittedFeatures|TPMFeaturePlatformHierarchy|TPMFeatureNV)

	c.Check(tpm.HierarchyControl(tpm.GetPermanentContext(data.auth), data.enable, false, nil), IsNil)

	props, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyStartupClear)
	enabled := tpm2.StartupClearAttributes(props[0].Value)&data.attr > 0
	c.Check(enabled, IsFalse)

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityTPMProperties(tpm2.PropertyStartupClear, 1)
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

type testRestoreHierarhcyAuthData struct {
	handle tpm2.Handle
}

func (s *tctiSuite) testRestoreHierarchyAuth(c *C, handle tpm2.Handle) {
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureFlags(math.MaxUint32))

	c.Check(tpm.HierarchyChangeAuth(tpm.GetPermanentContext(handle), []byte("foo"), nil), IsNil)

	c.Check(tpm.Close(), IsNil)

	c.Check(rawTpm.HierarchyChangeAuth(rawTpm.GetPermanentContext(handle), nil, nil), IsNil)
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
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	sym := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, &sym, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	c.Check(tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), []byte("foo"), session.WithAttrs(tpm2.AttrCommandEncrypt)), IsNil)
	c.Check(tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), nil, nil), IsNil)
}

func (s *tctiSuite) TestNoManualRestoreHierarchyAuthChangeWithCommandEncryption(c *C) {
	// Test that Close() fails if the hierarchy auth is not manually restored
	// after changing it with command encryption.
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)

	sym := tpm2.SymDef{
		Algorithm: tpm2.SymAlgorithmAES,
		KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
		Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}
	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, &sym, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	c.Check(tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), []byte("foo"), session.WithAttrs(tpm2.AttrCommandEncrypt)), IsNil)
	c.Check(tpm.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot clear auth value for TPM_RH_OWNER: TPM returned an error for session 1 whilst executing command TPM_CC_HierarchyChangeAuth: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)\n`)
}

func (s *tctiSuite) TestRestoreDisableClear(c *C) {
	// Test that disableClear is restored correctly if the test can
	// use the platform hierarchy.
	tpm, rawTpm := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)

	c.Check(tpm.ClearControl(tpm.PlatformHandleContext(), true, nil), IsNil)

	props, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	disabled := tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0
	c.Check(disabled, IsTrue)

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Property, Equals, tpm2.PropertyPermanent)
	disabled = tpm2.PermanentAttributes(props[0].Value)&tpm2.AttrDisableClear > 0
	c.Check(disabled, IsFalse)
}

func (s *tctiSuite) TestRestoreDisableClearFailsIfPlatformIsDisabled(c *C) {
	// Test that Close() fails if it cannot restore disableClear because the
	// platform hierarchy was disabled and TPMFeatureClearControl isn't defined.
	tpm, _ := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	c.Check(tpm.ClearControl(tpm.PlatformHandleContext(), true, nil), IsNil)
	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(tpm.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot restore disableClear because the platform hierarchy was disabled\n`)
}

func (s *tctiSuite) TestRestoreDACounter(c *C) {
	// Test that we can access a DA protected resource and that the DA counter
	// is reset if we don't have TPMFeatureDAProtectedCapability but we do have
	// TPMFeatureLockoutHierarchy.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureLockoutHierarchy|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), []byte("foo"), &nvPublic, nil)
	c.Assert(err, IsNil)

	index.SetAuthValue(nil)
	err = tpm.NVWrite(index, index, []byte("bar"), 0, nil)
	c.Check(err, ErrorMatches, `TPM returned an error for session 1 whilst executing command TPM_CC_NV_Write: TPM_RC_AUTH_FAIL \(the authorization HMAC check failed and DA counter incremented\)`)

	props, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyLockoutCounter, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Value, Equals, uint32(1))

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityTPMProperties(tpm2.PropertyLockoutCounter, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0].Value, Equals, uint32(0))
}

func (s *tctiSuite) TestRestoreDAParams(c *C) {
	// Test that DA parameters are restored properly.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureLockoutHierarchy|TPMFeatureNV)

	origProps, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	c.Check(err, IsNil)
	c.Assert(origProps, HasLen, 3)

	c.Check(tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), math.MaxUint32, math.MaxUint32, math.MaxUint32, nil), IsNil)

	c.Check(tpm.Close(), IsNil)

	props, err := rawTpm.GetCapabilityTPMProperties(tpm2.PropertyMaxAuthFail, 3)
	c.Check(err, IsNil)
	c.Check(props, DeepEquals, origProps)
}

func (s *tctiSuite) TestCreateAndFlushPrimaryObject(c *C) {
	// Test that transient objects created with CreatePrimary are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy)

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
	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushObject(c *C) {
	// Test that transient objects loaded in to the TPM are flushed.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy)

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
	primary, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	template = tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrNoDA,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}
	priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := tpm.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestCreateAndFlushHMACObject(c *C) {
	// Test that HMAC sequence objects are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy)

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
	key, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	seq, err := tpm.HMACStart(key, nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, seq.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushRestoredObject(c *C) {
	// Test that restored transient objects are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy)

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
	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	context, err := tpm.ContextSave(object)
	c.Assert(err, IsNil)

	object2, err := tpm.ContextLoad(context)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(object2.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object2.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(object2.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushExternalObject(c *C) {
	// Test that external objects are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, 0)

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
	object, err := tpm.LoadExternal(nil, &public, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, object.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(object.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestCreateAndFlushHashObject(c *C) {
	// Test that has sequence objects are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, 0)

	seq, err := tpm.HashSequenceStart(nil, tpm2.HashAlgorithmSHA256, nil)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, seq.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(seq.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestStartAndFlushSession(c *C) {
	// Test that sessions are flushed from the TPM.
	tpm, rawTpm := s.newTPMContext(c, 0)

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, session.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestLoadAndFlushRestoredSession(c *C) {
	tpm, rawTpm := s.newTPMContext(c, 0)

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypeHMAC, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	context, err := tpm.ContextSave(session)
	c.Assert(err, IsNil)

	session2, err := tpm.ContextLoad(context)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, session2.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(tpm2.HandleTypeLoadedSession.BaseHandle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestEvictPersistentObjects(c *C) {
	// Test that persistent objects are evicted from the TPM.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)

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
	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	persistent, err := tpm.EvictControl(tpm.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(persistent.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 1)
	c.Check(props[0], Equals, persistent.Handle())

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(persistent.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestEvictPersistentObjectError(c *C) {
	// Test that a failure to evict a persistent object results in an error.
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

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
	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	_, err = tpm.EvictControl(tpm.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	// Disable the owner and platform hierarchies.
	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(tpm.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot create ResourceContext for persistent object: a resource at handle 0x81000001 is not available on the TPM\n`)
}

func (s *tctiSuite) TestUndefineNVIndex(c *C) {
	// Test that NV indexes are undefined.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	_, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	props, err := rawTpm.GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Assert(props, HasLen, 1)
	c.Check(props[0], Equals, nvPublic.Index)

	c.Check(tpm.Close(), IsNil)

	props, err = rawTpm.GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}

func (s *tctiSuite) TestUndefineNVIndexError(c *C) {
	// Test that a failure to undefine a NV index results in an error.
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureStClearChange|TPMFeatureNV)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	_, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	// Disable the owner and platform hierarchies.
	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandleOwner, false, nil), IsNil)
	c.Check(tpm.HierarchyControl(tpm.PlatformHandleContext(), tpm2.HandlePlatform, false, nil), IsNil)

	c.Check(tpm.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- cannot create ResourceContext for NV index: a resource at handle 0x01800000 is not available on the TPM\n`)
}

func (s *tctiSuite) TestUndefinePolicyDeleteNVIndex(c *C) {
	// Test that Close() fails with an error if a test doesn't undefine a
	// TPMA_NV_POLICY_DELETE index.
	tpm, _ := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(tpm2.CommandNVUndefineSpaceSpecial)

	nvPublic := tpm2.NVPublic{
		Index:      0x01800000,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA | tpm2.AttrNVPolicyDelete | tpm2.AttrNVPlatformCreate),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	_, err := tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(tpm.Close(), ErrorMatches, `cannot complete close operation on TCTI: cannot cleanup TPM state because of the following errors:\n`+
		`- the test needs to undefine index 0x01800000 which has the TPMA_NV_POLICY_DELETE attribute set\n`)
}

func (s *tctiSuite) TestNVUndefineSpaceSpecial(c *C) {
	// Test that a NV index being undefined by the test is handled correctly.
	tpm, _ := s.newTPMContext(c, TPMFeaturePlatformHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	trial, _ := tpm2.ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyAuthValue()
	trial.PolicyCommandCode(tpm2.CommandNVUndefineSpaceSpecial)

	nvPublic := tpm2.NVPublic{
		Index:      0x01800000,
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA | tpm2.AttrNVPolicyDelete | tpm2.AttrNVPlatformCreate),
		AuthPolicy: trial.GetDigest(),
		Size:       8}
	index, err := tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Assert(err, IsNil)

	session, err := tpm.StartAuthSession(nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	c.Check(tpm.PolicyAuthValue(session), IsNil)
	c.Check(tpm.PolicyCommandCode(session, tpm2.CommandNVUndefineSpaceSpecial), IsNil)

	c.Check(tpm.NVUndefineSpaceSpecial(index, tpm.PlatformHandleContext(), session, nil), IsNil)
}

func (s *tctiSuite) TestEvictControl(c *C) {
	// Test that a persistent object being evicted by the test is handled correctly.
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

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
	object, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	persistent, err := tpm.EvictControl(tpm.OwnerHandleContext(), object, 0x81000001, nil)
	c.Assert(err, IsNil)

	_, err = tpm.EvictControl(tpm.OwnerHandleContext(), persistent, persistent.Handle(), nil)
	c.Check(err, IsNil)
}

func (s *tctiSuite) TestNVUndefineSpace(c *C) {
	// Test that a NV index being undefined by the test is handled correctly.
	tpm, _ := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureNV)
	s.deferCloseTpm(c, tpm)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index, err := tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(tpm.NVUndefineSpace(tpm.OwnerHandleContext(), index, nil), IsNil)
}

func (s *tctiSuite) TestClear(c *C) {
	// Test that TPM_CC_Clear works correctly and that the test cleans
	// up the platform hierarchy at the end of the test.
	tpm, rawTpm := s.newTPMContext(c, TPMFeatureOwnerHierarchy|TPMFeatureLockoutHierarchy|TPMFeaturePlatformHierarchy|TPMFeatureClear|TPMFeatureNV)

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

	oObject, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)
	_, err = tpm.EvictControl(tpm.OwnerHandleContext(), oObject, 0x81000001, nil)
	c.Check(err, IsNil)

	pObject, _, _, _, _, err := tpm.CreatePrimary(tpm.PlatformHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)
	pPersist, err := tpm.EvictControl(tpm.PlatformHandleContext(), pObject, 0x81800000, nil)
	c.Assert(err, IsNil)

	nvPublic := tpm2.NVPublic{
		Index:   0x01800000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVOwnerWrite | tpm2.AttrNVNoDA),
		Size:    8}

	_, err = tpm.NVDefineSpace(tpm.OwnerHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	nvPublic.Index = 0x01400000
	nvPublic.Attrs |= tpm2.AttrNVPlatformCreate
	_, err = tpm.NVDefineSpace(tpm.PlatformHandleContext(), nil, &nvPublic, nil)
	c.Check(err, IsNil)

	c.Check(tpm.HierarchyChangeAuth(tpm.OwnerHandleContext(), []byte("foo"), nil), IsNil)
	c.Check(tpm.HierarchyChangeAuth(tpm.PlatformHandleContext(), []byte("foo"), nil), IsNil)

	c.Check(tpm.Clear(tpm.LockoutHandleContext(), nil), IsNil)

	c.Check(tpm.Close(), IsNil)

	// Verify that platform objects have gone
	props, err := rawTpm.GetCapabilityHandles(pPersist.Handle(), 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)

	props, err = rawTpm.GetCapabilityHandles(nvPublic.Index, 1)
	c.Check(err, IsNil)
	c.Check(props, HasLen, 0)
}
