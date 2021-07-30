// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"fmt"
	"io"
	"math"
	"reflect"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type capsIncludeChecker struct {
	*CheckerInfo
}

var capsInclude Checker = &capsIncludeChecker{
	&CheckerInfo{Name: "capsInclude", Params: []string{"obtained", "expected"}}}

func (checker *capsIncludeChecker) Check(params []interface{}, names []string) (result bool, error string) {
	obtained := reflect.ValueOf(params[0])
	expected := reflect.ValueOf(params[1])

	for expected.Len() > 0 {
		e := expected.Index(0)
		expected = expected.Slice(1, expected.Len())

		found := false

		for obtained.Len() > 0 {
			o := obtained.Index(0)
			obtained = obtained.Slice(1, obtained.Len())

			if reflect.DeepEqual(o.Interface(), e.Interface()) {
				found = true
				break
			}
		}

		if !found {
			return false, fmt.Sprintf("didn't find expected cap %v", e.Interface())
		}
	}

	return true, ""
}

type capabilitiesSuite struct {
	testutil.TPMTest
}

var _ = Suite(&capabilitiesSuite{})

type testGetCapabilityAlgsData struct {
	first         AlgorithmId
	propertyCount uint32
	expected      AlgorithmPropertyList
}

func (s *capabilitiesSuite) testGetCapabilityAlgs(c *C, data *testGetCapabilityAlgsData) {
	algs, err := s.TPM.GetCapabilityAlgs(data.first, data.propertyCount)
	c.Assert(err, IsNil)
	c.Check(algs, capsInclude, data.expected)
}

func (s *capabilitiesSuite) TestGetCapabilityAlgs1(c *C) {
	s.testGetCapabilityAlgs(c, &testGetCapabilityAlgsData{
		first:         AlgorithmRSA,
		propertyCount: math.MaxUint32,
		expected: AlgorithmPropertyList{
			{Alg: AlgorithmRSA, Properties: AttrAsymmetric | AttrObject},
			{Alg: AlgorithmSHA1, Properties: AttrHash},
			{Alg: AlgorithmHMAC, Properties: AttrHash | AttrSigning},
			{Alg: AlgorithmAES, Properties: AttrSymmetric},
			{Alg: AlgorithmMGF1, Properties: AttrHash | AttrMethod},
			{Alg: AlgorithmKeyedHash, Properties: AttrHash | AttrEncrypting | AttrSigning | AttrObject},
			{Alg: AlgorithmXOR, Properties: AttrHash | AttrSymmetric},
			{Alg: AlgorithmSHA256, Properties: AttrHash},
			{Alg: AlgorithmRSASSA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmRSAES, Properties: AttrAsymmetric | AttrEncrypting},
			{Alg: AlgorithmRSAPSS, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmOAEP, Properties: AttrAsymmetric | AttrEncrypting},
			{Alg: AlgorithmECDSA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECDH, Properties: AttrAsymmetric | AttrMethod},
			{Alg: AlgorithmECDAA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECSCHNORR, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECC, Properties: AttrAsymmetric | AttrObject},
			{Alg: AlgorithmSymCipher, Properties: AttrObject}}})
}

func (s *capabilitiesSuite) TestGetCapabilityAlgs2(c *C) {
	s.testGetCapabilityAlgs(c, &testGetCapabilityAlgsData{
		first:         AlgorithmSHA256,
		propertyCount: math.MaxUint32,
		expected: AlgorithmPropertyList{
			{Alg: AlgorithmSHA256, Properties: AttrHash},
			{Alg: AlgorithmRSASSA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmRSAES, Properties: AttrAsymmetric | AttrEncrypting},
			{Alg: AlgorithmRSAPSS, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmOAEP, Properties: AttrAsymmetric | AttrEncrypting},
			{Alg: AlgorithmECDSA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECDH, Properties: AttrAsymmetric | AttrMethod},
			{Alg: AlgorithmECDAA, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECSCHNORR, Properties: AttrAsymmetric | AttrSigning},
			{Alg: AlgorithmECC, Properties: AttrAsymmetric | AttrObject},
			{Alg: AlgorithmSymCipher, Properties: AttrObject}}})
}

func (s *capabilitiesSuite) TestGetCapabilityAlgs3(c *C) {
	s.testGetCapabilityAlgs(c, &testGetCapabilityAlgsData{
		first:         AlgorithmRSA,
		propertyCount: 1,
		expected:      AlgorithmPropertyList{{Alg: AlgorithmRSA, Properties: AttrAsymmetric | AttrObject}}})
}

func makeCommandAttributes(code CommandCode, attrs CommandAttributes, handles int) CommandAttributes {
	return CommandAttributes(code) | CommandAttributes((handles&0x7)<<25) | attrs
}

type testGetCapabilityCommandsData struct {
	first         CommandCode
	propertyCount uint32
	expected      CommandAttributesList
}

func (s *capabilitiesSuite) testGetCapabilityCommands(c *C, data *testGetCapabilityCommandsData) {
	commands, err := s.TPM.GetCapabilityCommands(data.first, data.propertyCount)
	c.Assert(err, IsNil)
	c.Check(commands, capsInclude, data.expected)
}

func (s *capabilitiesSuite) TestGetCapabilityCommands1(c *C) {
	s.testGetCapabilityCommands(c, &testGetCapabilityCommandsData{
		first:         CommandFirst,
		propertyCount: math.MaxUint32,
		expected: CommandAttributesList{
			makeCommandAttributes(CommandNVUndefineSpaceSpecial, AttrNV, 2),
			makeCommandAttributes(CommandEvictControl, AttrNV, 2),
			makeCommandAttributes(CommandHierarchyControl, AttrNV|AttrExtensive, 1),
			makeCommandAttributes(CommandNVUndefineSpace, AttrNV, 2),
			makeCommandAttributes(CommandClear, AttrNV|AttrExtensive, 1),
			makeCommandAttributes(CommandClearControl, AttrNV, 1),
			makeCommandAttributes(CommandClockSet, AttrNV, 1),
			makeCommandAttributes(CommandHierarchyChangeAuth, AttrNV, 1),
			makeCommandAttributes(CommandNVDefineSpace, AttrNV, 1),
			makeCommandAttributes(CommandPCRAllocate, AttrNV, 1),
			makeCommandAttributes(CommandSetPrimaryPolicy, AttrNV, 1),
			makeCommandAttributes(CommandClockRateAdjust, 0, 1),
			makeCommandAttributes(CommandCreatePrimary, AttrRHandle, 1),
			makeCommandAttributes(CommandNVIncrement, AttrNV, 2),
			makeCommandAttributes(CommandNVSetBits, AttrNV, 2),
			makeCommandAttributes(CommandNVExtend, AttrNV, 2),
			makeCommandAttributes(CommandNVWrite, AttrNV, 2),
			makeCommandAttributes(CommandNVWriteLock, AttrNV, 2),
			makeCommandAttributes(CommandDictionaryAttackLockReset, AttrNV, 1),
			makeCommandAttributes(CommandDictionaryAttackParameters, AttrNV, 1),
			makeCommandAttributes(CommandNVChangeAuth, AttrNV, 1),
			makeCommandAttributes(CommandPCREvent, AttrNV, 1),
			makeCommandAttributes(CommandPCRReset, AttrNV, 1),
			makeCommandAttributes(CommandSequenceComplete, AttrFlushed, 1),
			makeCommandAttributes(CommandIncrementalSelfTest, AttrNV, 0),
			makeCommandAttributes(CommandSelfTest, AttrNV, 0),
			makeCommandAttributes(CommandStartup, AttrNV, 0),
			makeCommandAttributes(CommandShutdown, AttrNV, 0),
			makeCommandAttributes(CommandStirRandom, AttrNV, 0),
			makeCommandAttributes(CommandActivateCredential, 0, 2),
			makeCommandAttributes(CommandCertify, 0, 2),
			makeCommandAttributes(CommandPolicyNV, 0, 3),
			makeCommandAttributes(CommandCertifyCreation, 0, 2),
			makeCommandAttributes(CommandDuplicate, 0, 2),
			makeCommandAttributes(CommandGetTime, 0, 2),
			makeCommandAttributes(CommandGetSessionAuditDigest, 0, 3),
			makeCommandAttributes(CommandNVRead, 0, 2),
			makeCommandAttributes(CommandNVReadLock, AttrNV, 2),
			makeCommandAttributes(CommandObjectChangeAuth, 0, 2),
			makeCommandAttributes(CommandPolicySecret, 0, 2),
			makeCommandAttributes(CommandCreate, 0, 1),
			makeCommandAttributes(CommandECDHZGen, 0, 1),
			makeCommandAttributes(CommandHMAC, 0, 1),
			makeCommandAttributes(CommandImport, 0, 1),
			makeCommandAttributes(CommandLoad, AttrRHandle, 1),
			makeCommandAttributes(CommandQuote, 0, 1),
			makeCommandAttributes(CommandRSADecrypt, 0, 1),
			makeCommandAttributes(CommandHMACStart, AttrRHandle, 1),
			makeCommandAttributes(CommandSequenceUpdate, 0, 1),
			makeCommandAttributes(CommandSign, 0, 1),
			makeCommandAttributes(CommandUnseal, 0, 1),
			makeCommandAttributes(CommandPolicySigned, 0, 2),
			makeCommandAttributes(CommandContextLoad, AttrRHandle, 0),
			makeCommandAttributes(CommandContextSave, 0, 1),
			makeCommandAttributes(CommandECDHKeyGen, 0, 1),
			makeCommandAttributes(CommandFlushContext, 0, 0),
			makeCommandAttributes(CommandLoadExternal, AttrRHandle, 0),
			makeCommandAttributes(CommandMakeCredential, 0, 1),
			makeCommandAttributes(CommandNVReadPublic, 0, 1),
			makeCommandAttributes(CommandPolicyAuthorize, 0, 1),
			makeCommandAttributes(CommandPolicyAuthValue, 0, 1),
			makeCommandAttributes(CommandPolicyCommandCode, 0, 1),
			makeCommandAttributes(CommandPolicyCounterTimer, 0, 1),
			makeCommandAttributes(CommandPolicyCpHash, 0, 1),
			makeCommandAttributes(CommandPolicyLocality, 0, 1),
			makeCommandAttributes(CommandPolicyNameHash, 0, 1),
			makeCommandAttributes(CommandPolicyOR, 0, 1),
			makeCommandAttributes(CommandPolicyTicket, 0, 1),
			makeCommandAttributes(CommandReadPublic, 0, 1),
			makeCommandAttributes(CommandRSAEncrypt, 0, 1),
			makeCommandAttributes(CommandStartAuthSession, AttrRHandle, 2),
			makeCommandAttributes(CommandVerifySignature, 0, 1),
			makeCommandAttributes(CommandECCParameters, 0, 0),
			makeCommandAttributes(CommandGetCapability, 0, 0),
			makeCommandAttributes(CommandGetRandom, 0, 0),
			makeCommandAttributes(CommandGetTestResult, 0, 0),
			makeCommandAttributes(CommandHash, 0, 0),
			makeCommandAttributes(CommandPCRRead, 0, 0),
			makeCommandAttributes(CommandPolicyPCR, 0, 1),
			makeCommandAttributes(CommandPolicyRestart, 0, 1),
			makeCommandAttributes(CommandReadClock, 0, 0),
			makeCommandAttributes(CommandPCRExtend, AttrNV, 1),
			makeCommandAttributes(CommandNVCertify, 0, 3),
			makeCommandAttributes(CommandEventSequenceComplete, AttrNV|AttrFlushed, 2),
			makeCommandAttributes(CommandHashSequenceStart, AttrRHandle, 0),
			makeCommandAttributes(CommandPolicyDuplicationSelect, 0, 1),
			makeCommandAttributes(CommandPolicyGetDigest, 0, 1),
			makeCommandAttributes(CommandTestParms, 0, 0),
			makeCommandAttributes(CommandCommit, 0, 1),
			makeCommandAttributes(CommandPolicyPassword, 0, 1),
			makeCommandAttributes(CommandPolicyNvWritten, 0, 1),
			makeCommandAttributes(CommandPolicyTemplate, 0, 1),
			makeCommandAttributes(CommandCreateLoaded, AttrRHandle, 1),
			makeCommandAttributes(CommandPolicyAuthorizeNV, 0, 3)}})
}

func (s *capabilitiesSuite) TestGetCapabilityCommands2(c *C) {
	s.testGetCapabilityCommands(c, &testGetCapabilityCommandsData{
		first:         CommandPolicyGetDigest,
		propertyCount: math.MaxUint32,
		expected: CommandAttributesList{
			makeCommandAttributes(CommandPolicyGetDigest, 0, 1),
			makeCommandAttributes(CommandTestParms, 0, 0),
			makeCommandAttributes(CommandCommit, 0, 1),
			makeCommandAttributes(CommandPolicyPassword, 0, 1),
			makeCommandAttributes(CommandPolicyNvWritten, 0, 1),
			makeCommandAttributes(CommandPolicyTemplate, 0, 1),
			makeCommandAttributes(CommandCreateLoaded, AttrRHandle, 1),
			makeCommandAttributes(CommandPolicyAuthorizeNV, 0, 3)}})
}

func (s *capabilitiesSuite) TestGetCapabilityCommands3(c *C) {
	s.testGetCapabilityCommands(c, &testGetCapabilityCommandsData{
		first:         CommandFirst,
		propertyCount: 1,
		expected:      CommandAttributesList{makeCommandAttributes(CommandNVUndefineSpaceSpecial, AttrNV, 2)}})
}

type testGetCapabilityHandlesData struct {
	firstHandle   Handle
	propertyCount uint32
	expected      HandleList
}

func (s *capabilitiesSuite) testGetCapabilityHandles(c *C, data *testGetCapabilityHandlesData) {
	handles, err := s.TPM.GetCapabilityHandles(data.firstHandle, data.propertyCount)
	c.Check(err, IsNil)
	c.Check(handles, capsInclude, data.expected)
}

func (s *capabilitiesSuite) TestGetCapabilityHandles1(c *C) {
	s.testGetCapabilityHandles(c, &testGetCapabilityHandlesData{
		firstHandle:   HandleTypePermanent.BaseHandle(),
		propertyCount: math.MaxUint32,
		expected: HandleList{
			HandleOwner,
			HandleNull,
			HandlePW,
			HandleLockout,
			HandleEndorsement,
			HandlePlatform,
			HandlePlatformNV}})
}

func (s *capabilitiesSuite) TestGetCapabilityHandles2(c *C) {
	s.testGetCapabilityHandles(c, &testGetCapabilityHandlesData{
		firstHandle:   HandleTypePCR.BaseHandle(),
		propertyCount: math.MaxUint32,
		expected:      HandleList{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}})
}

func (s *capabilitiesSuite) TestGetCapabilityHandles3(c *C) {
	s.testGetCapabilityHandles(c, &testGetCapabilityHandlesData{
		firstHandle:   HandleTypePermanent.BaseHandle(),
		propertyCount: 1,
		expected:      HandleList{HandleOwner}})
}

func (s *capabilitiesSuite) TestGetCapabilityPCRs(c *C) {
	expected := PCRSelectionList{
		{Hash: HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
		{Hash: HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}}}

	pcrs, err := s.TPM.GetCapabilityPCRs()
	c.Check(err, IsNil)
	c.Check(pcrs, capsInclude, expected)
}

type propsValidChecker struct {
	*CheckerInfo
}

var propsValid Checker = &propsValidChecker{
	&CheckerInfo{Name: "propsValid", Params: []string{"obtained", "first", "propertyCount"}}}

func (checker *propsValidChecker) Check(params []interface{}, names []string) (result bool, error string) {
	props := params[0].(TaggedTPMPropertyList)
	first := params[1].(Property)
	propertyCount := params[2].(uint32)

	max := Property(first + 0x100 - (first & 0xff))

	if len(props) > int(propertyCount) {
		return false, "more properties than expected"
	}
	for _, p := range props {
		if p.Property < first {
			return false, fmt.Sprintf("unexpected property %v (before first property)", p.Property)
		}
		if p.Property >= max {
			return false, fmt.Sprintf("unexpected property %v (wrong group)", p.Property)
		}

		valid := false
		switch p.Property {
		case PropertyFamilyIndicator:
			valid = p.Value == 0x322E3000
		case PropertyLevel:
			valid = p.Value == 0
		case PropertyHRTransientMin:
			valid = p.Value >= 3
		case PropertyHRLoadedMin:
			valid = p.Value >= 3
		case PropertyActiveSessionsMax:
			valid = p.Value >= 64
		case PropertyPCRCount:
			valid = p.Value >= 24
		case PropertyPCRSelectMin:
			valid = p.Value >= 3
		case PropertyNVIndexMax:
			valid = p.Value >= 1600
		case PropertyPSLevel:
			valid = p.Value == 0
		case PropertyNVBufferMax:
			valid = p.Value >= 512
		case PropertyContextHash:
			valid = p.Value == uint32(AlgorithmSHA1) || p.Value == uint32(AlgorithmSHA256) || p.Value == uint32(AlgorithmSHA384) || p.Value == uint32(AlgorithmSHA512)
		case PropertyMaxDigest:
			valid = p.Value >= 20 && p.Value <= 64
		default:
			valid = true
		}

		if !valid {
			return false, fmt.Sprintf("unexpected value for property %v (%d)", p.Property, p.Value)
		}
	}
	return true, ""
}

type testGetCapabilityTPMPropertiesData struct {
	first         Property
	propertyCount uint32
}

func (s *capabilitiesSuite) testGetCapabilityTPMProperties(c *C, data *testGetCapabilityTPMPropertiesData) {
	props, err := s.TPM.GetCapabilityTPMProperties(data.first, data.propertyCount)
	c.Check(err, IsNil)
	c.Check(props, propsValid, data.first, data.propertyCount)
}

func (s *capabilitiesSuite) TestGetCapabilityTPMProperties1(c *C) {
	s.testGetCapabilityTPMProperties(c, &testGetCapabilityTPMPropertiesData{
		first:         PropertyFixed,
		propertyCount: math.MaxUint32})
}

func (s *capabilitiesSuite) TestGetCapabilityTPMProperties2(c *C) {
	s.testGetCapabilityTPMProperties(c, &testGetCapabilityTPMPropertiesData{
		first:         PropertyVar,
		propertyCount: math.MaxUint32})
}

func (s *capabilitiesSuite) TestGetCapabilityTPMProperties3(c *C) {
	s.testGetCapabilityTPMProperties(c, &testGetCapabilityTPMPropertiesData{
		first:         PropertyFixed,
		propertyCount: 1})
}

func (s *capabilitiesSuite) TestGetManufacturer(c *C) {
	id, err := s.TPM.GetManufacturer()
	c.Check(err, IsNil)
	c.Check(id, testutil.InSlice(Equals), []TPMManufacturer{TPMManufacturerIBM, TPMManufacturerMSFT})
}

func (s *capabilitiesSuite) testTestParms(c *C, params *PublicParams) {
	c.Check(s.TPM.TestParms(params), IsNil)
}

func (s *capabilitiesSuite) TestTestParms1(c *C) {
	s.testTestParms(c, &PublicParams{
		Type: ObjectTypeRSA,
		Parameters: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}})
}

func (s *capabilitiesSuite) TestTestParms2(c *C) {
	s.testTestParms(c, &PublicParams{
		Type: ObjectTypeECC,
		Parameters: &PublicParamsU{
			ECCDetail: &ECCParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme: ECCScheme{
					Scheme:  ECCSchemeECDSA,
					Details: &AsymSchemeU{ECDSA: &SigSchemeECDSA{HashAlg: HashAlgorithmSHA256}}},
				CurveID: ECCCurveNIST_P256,
				KDF:     KDFScheme{Scheme: KDFAlgorithmNull}}}})
}

func (s *capabilitiesSuite) TestTestParms3(c *C) {
	s.testTestParms(c, &PublicParams{
		Type: ObjectTypeSymCipher,
		Parameters: &PublicParamsU{
			SymDetail: &SymCipherParams{
				Sym: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 256},
					Mode:      &SymModeU{Sym: SymModeCFB}}}}})
}

func (s *capabilitiesSuite) TestTestParmsErrValue(c *C) {
	err := s.TPM.TestParms(&PublicParams{
		Type: ObjectTypeRSA,
		Parameters: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2047,
				Exponent: 0}}})
	c.Check(IsTPMParameterError(err, ErrorValue, CommandTestParms, 1), testutil.IsTrue)
}

func (s *capabilitiesSuite) TestIsTPM2(c *C) {
	isTpm2, err := s.TPM.IsTPM2()
	c.Check(err, IsNil)
	c.Check(isTpm2, testutil.IsTrue)
}

type testGetCapabilityPCRPropertiesData struct {
	first         PropertyPCR
	propertyCount uint32
	expected      TaggedPCRPropertyList
}

func (s *capabilitiesSuite) testGetCapabilityPCRProperties(c *C, data *testGetCapabilityPCRPropertiesData) {
	props, err := s.TPM.GetCapabilityPCRProperties(data.first, data.propertyCount)
	c.Check(err, IsNil)
	c.Check(props, capsInclude, data.expected)
}

func (s *capabilitiesSuite) TestGetCapabilityPCRProperties1(c *C) {
	s.testGetCapabilityPCRProperties(c, &testGetCapabilityPCRPropertiesData{
		first:         PropertyPCRSave,
		propertyCount: math.MaxUint32,
		expected: TaggedPCRPropertyList{
			{Tag: PropertyPCRSave, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},
			{Tag: PropertyPCRExtendL0, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 23}},
			{Tag: PropertyPCRResetL0, Select: []int{16, 23}},
			{Tag: PropertyPCRExtendL1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 20, 23}},
			{Tag: PropertyPCRResetL1, Select: []int{16, 23}},
			{Tag: PropertyPCRExtendL2, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23}},
			{Tag: PropertyPCRResetL2, Select: []int{16, 20, 21, 22, 23}},
			{Tag: PropertyPCRExtendL3, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 23}},
			// The simulator doesn't align with the PC Client Platform TPM Profile spec here
			//{Tag: PropertyPCRResetL3, Select: []int{16, 20, 21, 22, 23}},
			{Tag: PropertyPCRExtendL4, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23}},
			{Tag: PropertyPCRResetL4, Select: []int{17, 18, 19, 20, 21, 22}},
			// The simulator doesn't align with the PC Client Platform TPM Profile spec here
			//{Tag: PropertyPCRNoIncrement, Select: []int{16, 21, 22, 23}},
			{Tag: PropertyPCRDRTMReset, Select: []int{17, 18, 19, 20, 21, 22}}}})
}

func (s *capabilitiesSuite) TestGetCapabilityPCRProperties2(c *C) {
	s.testGetCapabilityPCRProperties(c, &testGetCapabilityPCRPropertiesData{
		first:         PropertyPCRExtendL4,
		propertyCount: math.MaxUint32,
		expected: TaggedPCRPropertyList{
			{Tag: PropertyPCRExtendL4, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 23}},
			{Tag: PropertyPCRResetL4, Select: []int{17, 18, 19, 20, 21, 22}},
			// The simulator doesn't align with the PC Client Platform TPM Profile spec here
			//{Tag: PropertyPCRNoIncrement, Select: []int{16, 21, 22, 23}},
			{Tag: PropertyPCRDRTMReset, Select: []int{17, 18, 19, 20, 21, 22}}}})
}

func (s *capabilitiesSuite) TestGetCapabilityPCRProperties3(c *C) {
	s.testGetCapabilityPCRProperties(c, &testGetCapabilityPCRPropertiesData{
		first:         PropertyPCRSave,
		propertyCount: 1,
		expected: TaggedPCRPropertyList{
			{Tag: PropertyPCRSave, Select: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}}}})
}

// We don't have a TPM1.2 simulator, so create a mock TCTI that just returns
// a TPM_BAD_ORDINAL error
type mockTPM12Tcti struct{}

func (t *mockTPM12Tcti) Read(data []byte) (int, error) {
	// tag = TPM_TAG_RSP_COMMAND (0xc4)
	// paramSize = 10
	// returnCode = TPM_BAD_ORDINAL (10)
	b, _ := mu.MarshalToBytes(uint16(0xc4), uint32(10), uint32(10))
	return copy(data, b), io.EOF
}

func (t *mockTPM12Tcti) Write(data []byte) (int, error) {
	return len(data), nil
}

func (t *mockTPM12Tcti) Close() error {
	return nil
}

func (t *mockTPM12Tcti) SetLocality(locality uint8) error {
	return nil
}

func (t *mockTPM12Tcti) MakeSticky(handle Handle, sticky bool) error {
	return nil
}

type capabilitiesMockTPM12Suite struct {
	testutil.BaseTest
	tpm *TPMContext
}

func (s *capabilitiesMockTPM12Suite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	tpm, _ := NewTPMContext(&mockTPM12Tcti{})
	s.tpm = tpm
}

var _ = Suite(&capabilitiesMockTPM12Suite{})

func (s *capabilitiesMockTPM12Suite) TestIsTPM2(c *C) {
	isTpm2, err := s.tpm.IsTPM2()
	c.Check(err, IsNil)
	c.Check(isTpm2, testutil.IsFalse)
}
