// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

type attestationSuite struct {
	testutil.TPMTest
}

func (s *attestationSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy | testutil.TPMFeatureNV
}

func (s *attestationSuite) checkAttestCommon(c *C, attest *Attest, tag StructTag, sign ResourceContext, signHierarchy Handle, qualifyingData Data) {
	c.Assert(attest, NotNil)
	c.Check(attest.Magic, Equals, TPMGeneratedValue)
	c.Check(attest.Type, Equals, tag)

	if sign == nil {
		c.Assert(attest.QualifiedSigner.Type(), Equals, NameTypeHandle)
		c.Check(attest.QualifiedSigner.Handle(), Equals, HandleNull)
	} else {
		_, _, qn, err := s.TPM.ReadPublic(sign)
		c.Assert(err, IsNil)
		c.Check(attest.QualifiedSigner, DeepEquals, qn)
	}

	c.Check(attest.ExtraData, DeepEquals, qualifyingData)

	if sign != nil && signHierarchy == HandleEndorsement {
		time, err := s.TPM.ReadClock()
		c.Assert(err, IsNil)
		c.Check(attest.ClockInfo.ResetCount, Equals, time.ClockInfo.ResetCount)
		c.Check(attest.ClockInfo.RestartCount, Equals, time.ClockInfo.RestartCount)
		c.Check(attest.ClockInfo.Safe, Equals, time.ClockInfo.Safe)
	}
}

func (s *attestationSuite) checkAttestSignature(c *C, signature *Signature, sign ResourceContext, attest *Attest, scheme *SigScheme) {
	c.Assert(signature, NotNil)

	if sign == nil {
		c.Check(signature.SigAlg, Equals, SigSchemeAlgNull)
	} else {
		c.Check(signature.SigAlg, Equals, scheme.Scheme)
		c.Check(signature.HashAlg(), Equals, scheme.AnyDetails().HashAlg)

		pub, _, _, err := s.TPM.ReadPublic(sign)
		c.Assert(err, IsNil)

		ok, err := util.VerifyAttestationSignature(pub.Public(), attest, signature)
		c.Check(err, IsNil)
		c.Check(ok, internal_testutil.IsTrue)
	}
}

var _ = Suite(&attestationSuite{})

type testCertifyData struct {
	sign              ResourceContext
	qualifyingData    Data
	inScheme          *SigScheme
	objectAuthSession SessionContext
	signAuthSession   SessionContext

	signHierarchy Handle
	signScheme    *SigScheme
}

func (s *attestationSuite) testCertify(c *C, data *testCertifyData) {
	sessionHandles := []Handle{authSessionHandle(data.objectAuthSession), authSessionHandle(data.signAuthSession)}
	sessionHMACIsPW := []bool{
		sessionHandles[0] == HandlePW,
		data.sign != nil && (sessionHandles[1] == HandlePW || data.signAuthSession.State().NeedsPassword),
	}

	object := s.CreateStoragePrimaryKeyRSA(c)

	certifyInfo, signature, err := s.TPM.Certify(object, data.sign, data.qualifyingData, data.inScheme, data.objectAuthSession, data.signAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 2)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandles[0])
	if sessionHMACIsPW[0] {
		c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
	}
	c.Check(cmd.CmdAuthArea[1].SessionHandle, Equals, sessionHandles[1])
	if sessionHMACIsPW[1] {
		if len(data.sign.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[1].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[1].HMAC, DeepEquals, Auth(data.sign.AuthValue()))
		}
	}
	if data.objectAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandles[0]), internal_testutil.IsFalse)
		c.Check(data.objectAuthSession.Handle(), Equals, HandleUnassigned)
	}
	if data.signAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandles[1]), internal_testutil.IsFalse)
		c.Check(data.signAuthSession.Handle(), Equals, HandleUnassigned)
	}

	s.checkAttestCommon(c, certifyInfo, TagAttestCertify, data.sign, data.signHierarchy, data.qualifyingData)
	_, name, qn, err := s.TPM.ReadPublic(object)
	c.Assert(err, IsNil)
	c.Check(certifyInfo.Attested.Certify.Name, DeepEquals, name)
	c.Check(certifyInfo.Attested.Certify.QualifiedName, DeepEquals, qn)

	s.checkAttestSignature(c, signature, data.sign, certifyInfo, data.signScheme)
}

func (s *attestationSuite) TestCertifyNoSignature(c *C) {
	s.testCertify(c, &testCertifyData{})
}

func (s *attestationSuite) TestCertifyWithSignature(c *C) {
	s.testCertify(c, &testCertifyData{
		sign: s.CreatePrimary(c, HandleEndorsement, objectutil.NewRSAAttestationKeyTemplate(
			objectutil.WithoutDictionaryAttackProtection(),
		)),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyExtraData(c *C) {
	s.testCertify(c, &testCertifyData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestCertifyInScheme(c *C) {
	data := &testCertifyData{
		sign: s.CreatePrimary(c, HandleEndorsement, objectutil.NewRSAAttestationKeyTemplate(
			objectutil.WithoutDictionaryAttackProtection(),
			objectutil.WithRSAScheme(RSASchemeRSASSA, HashAlgorithmSHA1),
		)),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		signHierarchy: HandleEndorsement}
	data.signScheme = data.inScheme
	s.testCertify(c, data)
}

func (s *attestationSuite) TestCertifyObjectAuthSession(c *C) {
	s.testCertify(c, &testCertifyData{
		objectAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *attestationSuite) TestCertifySignAuthSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testCertify(c, &testCertifyData{
		sign:            sign,
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyWithSignPW(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testCertify(c, &testCertifyData{
		sign:          sign,
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

type testCertifyCreationData struct {
	sign            ResourceContext
	qualifyingData  Data
	inScheme        *SigScheme
	signAuthSession SessionContext

	signHierarchy Handle
	signScheme    *SigScheme
}

func (s *attestationSuite) testCertifyCreation(c *C, data *testCertifyCreationData) {
	sessionHandle := authSessionHandle(data.signAuthSession)
	sessionHMACIsPW := data.sign != nil && (sessionHandle == HandlePW || data.signAuthSession.State().NeedsPassword)

	object, _, _, creationHash, creationTicket, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	certifyInfo, signature, err := s.TPM.CertifyCreation(data.sign, object, data.qualifyingData, creationHash, data.inScheme, creationTicket, data.signAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.sign.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.sign.AuthValue()))
		}
	}
	if data.signAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(data.signAuthSession.Handle(), Equals, HandleUnassigned)
	}

	s.checkAttestCommon(c, certifyInfo, TagAttestCreation, data.sign, data.signHierarchy, data.qualifyingData)
	c.Check(certifyInfo.Attested.Creation.ObjectName, DeepEquals, object.Name())
	c.Check(certifyInfo.Attested.Creation.CreationHash, DeepEquals, creationHash)

	s.checkAttestSignature(c, signature, data.sign, certifyInfo, data.signScheme)
}

func (s *attestationSuite) TestCertifyCreationNoSignature(c *C) {
	s.testCertifyCreation(c, &testCertifyCreationData{})
}

func (s *attestationSuite) TestCertifyCreationWithSignature(c *C) {
	s.testCertifyCreation(c, &testCertifyCreationData{
		sign:          s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyCreationExtraData(c *C) {
	s.testCertifyCreation(c, &testCertifyCreationData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestCertifyCreationInScheme(c *C) {
	data := &testCertifyCreationData{
		sign: s.CreatePrimary(c, HandleEndorsement, testutil.NewRSAKeyTemplate(objectutil.UsageSign, nil)),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		signHierarchy: HandleEndorsement}
	data.signScheme = data.inScheme
	s.testCertifyCreation(c, data)
}

func (s *attestationSuite) TestCertifyCreationSignAuthSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testCertifyCreation(c, &testCertifyCreationData{
		sign:            sign,
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyCreationSignPWSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testCertifyCreation(c, &testCertifyCreationData{
		sign:          sign,
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyCreationInvalidTicket(c *C) {
	object, _, _, creationHash, creationTicket, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	creationTicket.Hierarchy = HandleEndorsement

	_, _, err = s.TPM.CertifyCreation(nil, object, nil, creationHash, nil, creationTicket, nil)
	c.Check(IsTPMParameterError(err, ErrorTicket, CommandCertifyCreation, 4), internal_testutil.IsTrue)
}

type testQuoteData struct {
	sign            ResourceContext
	qualifyingData  Data
	inScheme        *SigScheme
	pcrs            PCRSelectionList
	signAuthSession SessionContext

	signHierarchy Handle
	alg           HashAlgorithmId
	signScheme    *SigScheme
}

func (s *attestationSuite) testQuote(c *C, data *testQuoteData) {
	var pcrs PCRSelectionList
	mu.MustCopyValue(&pcrs, data.pcrs)
	v, err := s.TPM.GetCapabilityTPMProperty(PropertyPCRSelectMin)
	c.Assert(err, IsNil)
	for i := range pcrs {
		if pcrs[i].SizeOfSelect < uint8(v) {
			pcrs[i].SizeOfSelect = uint8(v)
		}
	}

	sessionHandle := authSessionHandle(data.signAuthSession)
	sessionHMACIsPW := data.sign != nil && (sessionHandle == HandlePW || data.signAuthSession.State().NeedsPassword)

	quoted, signature, err := s.TPM.Quote(data.sign, data.qualifyingData, data.inScheme, data.pcrs, data.signAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 1)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandle)
	if sessionHMACIsPW {
		if len(data.sign.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(data.sign.AuthValue()))
		}
	}
	if data.signAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandle), internal_testutil.IsFalse)
		c.Check(data.signAuthSession.Handle(), Equals, HandleUnassigned)
	}

	s.checkAttestCommon(c, quoted, TagAttestQuote, data.sign, data.signHierarchy, data.qualifyingData)
	_, pcrValues, err := s.TPM.PCRRead(data.pcrs)
	c.Assert(err, IsNil)
	digest, err := util.ComputePCRDigest(data.alg, data.pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(quoted.Attested.Quote.PCRSelect, DeepEquals, pcrs)
	c.Check(quoted.Attested.Quote.PCRDigest, DeepEquals, digest)

	s.checkAttestSignature(c, signature, data.sign, quoted, data.signScheme)
}

func (s *attestationSuite) TestQuote(c *C) {
	s.testQuote(c, &testQuoteData{
		sign:          s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteWithExtraData(c *C) {
	s.testQuote(c, &testQuoteData{
		sign:           s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		qualifyingData: []byte("bar"),
		pcrs:           PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy:  HandleEndorsement,
		alg:            HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteInScheme(c *C) {
	data := &testQuoteData{
		sign: s.CreatePrimary(c, HandleEndorsement, testutil.NewRSAKeyTemplate(objectutil.UsageSign, nil)),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA1}
	data.signScheme = data.inScheme
	s.testQuote(c, data)
}

func (s *attestationSuite) TestQuoteDifferentPCRsSHA1(c *C) {
	s.RequirePCRBank(c, HashAlgorithmSHA1)

	s.testQuote(c, &testQuoteData{
		sign:          s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0}}, {Hash: HashAlgorithmSHA256, Select: []int{1, 2}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteDifferentPCRsSHA384(c *C) {
	s.RequirePCRBank(c, HashAlgorithmSHA384)

	s.testQuote(c, &testQuoteData{
		sign:          s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA384, Select: []int{0}}, {Hash: HashAlgorithmSHA256, Select: []int{1, 2}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteSignAuthSession(c *C) {
	s.testQuote(c, &testQuoteData{
		sign:            s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		pcrs:            PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		alg:             HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteSignPWSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testQuote(c, &testQuoteData{
		sign:          sign,
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

type testGetTimeData struct {
	sign                    ResourceContext
	qualifyingData          Data
	inScheme                *SigScheme
	privacyAdminAuthSession SessionContext
	signAuthSession         SessionContext

	signHierarchy Handle
	signScheme    *SigScheme
}

func (s *attestationSuite) testGetTime(c *C, data *testGetTimeData) {
	sessionHandles := []Handle{authSessionHandle(data.privacyAdminAuthSession), authSessionHandle(data.signAuthSession)}
	sessionHMACIsPW := []bool{
		sessionHandles[0] == HandlePW || data.privacyAdminAuthSession.State().NeedsPassword,
		data.sign != nil && (sessionHandles[1] == HandlePW || data.signAuthSession.State().NeedsPassword),
	}

	timeInfo, signature, err := s.TPM.GetTime(s.TPM.EndorsementHandleContext(), data.sign, data.qualifyingData, data.inScheme, data.privacyAdminAuthSession, data.signAuthSession)
	c.Assert(err, IsNil)

	cmd := s.LastCommand(c)
	c.Assert(cmd.CmdAuthArea, internal_testutil.LenEquals, 2)
	c.Check(cmd.CmdAuthArea[0].SessionHandle, Equals, sessionHandles[0])
	if sessionHMACIsPW[0] {
		if len(s.TPM.EndorsementHandleContext().AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[0].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[0].HMAC, DeepEquals, Auth(s.TPM.EndorsementHandleContext().AuthValue()))
		}
	}
	c.Check(cmd.CmdAuthArea[1].SessionHandle, Equals, sessionHandles[1])
	if sessionHMACIsPW[1] {
		if len(data.sign.AuthValue()) == 0 {
			c.Check(cmd.CmdAuthArea[1].HMAC, internal_testutil.LenEquals, 0)
		} else {
			c.Check(cmd.CmdAuthArea[1].HMAC, DeepEquals, Auth(data.sign.AuthValue()))
		}
	}
	if data.privacyAdminAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandles[0]), internal_testutil.IsFalse)
		c.Check(data.privacyAdminAuthSession.Handle(), Equals, HandleUnassigned)
	}
	if data.signAuthSession != nil {
		c.Check(s.TPM.DoesHandleExist(sessionHandles[1]), internal_testutil.IsFalse)
		c.Check(data.signAuthSession.Handle(), Equals, HandleUnassigned)
	}

	s.checkAttestCommon(c, timeInfo, TagAttestTime, data.sign, data.signHierarchy, data.qualifyingData)
	time, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)
	c.Check(timeInfo.Attested.Time.Time.ClockInfo.ResetCount, Equals, time.ClockInfo.ResetCount)
	c.Check(timeInfo.Attested.Time.Time.ClockInfo.RestartCount, Equals, time.ClockInfo.RestartCount)
	c.Check(timeInfo.Attested.Time.Time.ClockInfo.Safe, Equals, time.ClockInfo.Safe)
	c.Check(timeInfo.Attested.Time.Time.ClockInfo.Clock, Equals, timeInfo.ClockInfo.Clock)
	c.Check(timeInfo.Attested.Time.Time.ClockInfo.Safe, Equals, timeInfo.ClockInfo.Safe)

	s.checkAttestSignature(c, signature, data.sign, timeInfo, data.signScheme)
}

func (s *attestationSuite) TestGetTimeNoSignature(c *C) {
	s.testGetTime(c, &testGetTimeData{})
}

func (s *attestationSuite) TestGetTimeWithSignature(c *C) {
	s.testGetTime(c, &testGetTimeData{
		sign:          s.CreatePrimary(c, HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil)),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestGetTimeExtraData(c *C) {
	s.testGetTime(c, &testGetTimeData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestGetTimeInScheme(c *C) {
	data := &testGetTimeData{
		sign: s.CreatePrimary(c, HandleEndorsement, testutil.NewRSAKeyTemplate(objectutil.UsageSign, nil)),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		signHierarchy: HandleEndorsement}
	data.signScheme = data.inScheme
	s.testGetTime(c, data)
}

func (s *attestationSuite) TestGetTimePrivacyAdminAuthSession(c *C) {
	s.HierarchyChangeAuth(c, HandleEndorsement, []byte("password"))
	s.testGetTime(c, &testGetTimeData{
		privacyAdminAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *attestationSuite) TestGetTimePrivacyAdminPWSession(c *C) {
	s.HierarchyChangeAuth(c, HandleEndorsement, []byte("password"))
	s.testGetTime(c, &testGetTimeData{})
}

func (s *attestationSuite) TestGetTimeSignAuthSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testGetTime(c, &testGetTimeData{
		sign:            sign,
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestGetTimeSignPWSession(c *C) {
	sign, _, _, _, _, err := s.TPM.CreatePrimary(s.TPM.EndorsementHandleContext(), &SensitiveCreate{UserAuth: []byte("password")}, objectutil.NewRSAAttestationKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
	), nil, nil, nil)
	c.Assert(err, IsNil)

	s.testGetTime(c, &testGetTimeData{
		sign:          sign,
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSAPSS,
			Details: &SigSchemeU{
				RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}}})
}
