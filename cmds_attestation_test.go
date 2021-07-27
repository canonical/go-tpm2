// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"math/big"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
)

type attestationSuite struct {
	testutil.TPMTest
}

func (s *attestationSuite) SetUpTest(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy | testutil.TPMFeatureDAProtectedCapability
	s.TPMTest.SetUpTest(c)
}

func (s *attestationSuite) checkAttestCommon(c *C, attest *Attest, tag StructTag, sign ResourceContext, signHierarchy Handle, qualifyingData Data) {
	c.Assert(attest, NotNil)
	c.Check(attest.Magic, Equals, TPMGeneratedValue)
	c.Check(attest.Type, Equals, tag)

	if sign == nil {
		c.Assert(attest.QualifiedSigner.IsHandle(), testutil.IsTrue)
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

func (s *attestationSuite) checkSignature(c *C, signature *Signature, digest []byte, key *Public) {
	// TODO: Share this with cmds_signature_test.go

	c.Assert(key.Type, testutil.InSlice(Equals), []ObjectTypeId{ObjectTypeRSA, ObjectTypeECC})

	pubKey := key.Public()

	switch key.Type {
	case ObjectTypeRSA:
		c.Assert(signature.SigAlg, testutil.InSlice(Equals), []SigSchemeId{SigSchemeAlgRSASSA, SigSchemeAlgRSAPSS})
		switch signature.SigAlg {
		case SigSchemeAlgRSASSA:
			sig := (*SignatureRSA)(signature.Signature.RSASSA)
			c.Assert(sig.Hash.Available(), testutil.IsTrue)
			c.Check(rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), sig.Hash.GetHash(), digest, sig.Sig), IsNil)
		case SigSchemeAlgRSAPSS:
			sig := (*SignatureRSA)(signature.Signature.RSAPSS)
			c.Assert(sig.Hash.Available(), testutil.IsTrue)
			c.Check(rsa.VerifyPSS(pubKey.(*rsa.PublicKey), sig.Hash.GetHash(), digest, sig.Sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}), IsNil)
		}
	case ObjectTypeECC:
		c.Assert(signature.SigAlg, Equals, SigSchemeAlgECDSA)
		sig := signature.Signature.ECDSA
		c.Check(ecdsa.Verify(pubKey.(*ecdsa.PublicKey), digest, new(big.Int).SetBytes(sig.SignatureR), new(big.Int).SetBytes(sig.SignatureS)), testutil.IsTrue)
	}

}

func (s *attestationSuite) checkAttestSignature(c *C, signature *Signature, sign ResourceContext, attest *Attest, scheme *SigScheme) {
	c.Assert(signature, NotNil)

	if sign == nil {
		c.Check(signature.SigAlg, Equals, SigSchemeAlgNull)
	} else {
		c.Check(signature.SigAlg, Equals, scheme.Scheme)
		c.Check(signature.Signature.Any().HashAlg, Equals, scheme.Details.Any().HashAlg)

		h := scheme.Details.Any().HashAlg.NewHash()
		mu.MarshalToWriter(h, attest)
		digest := h.Sum(nil)

		pub, _, _, err := s.TPM.ReadPublic(sign)
		c.Assert(err, IsNil)

		s.checkSignature(c, signature, digest, pub)
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

	object := s.CreateStoragePrimaryKeyRSA(c)

	certifyInfo, signature, err := s.TPM.Certify(object, data.sign, data.qualifyingData, data.inScheme, data.objectAuthSession, data.signAuthSession)
	c.Assert(err, IsNil)

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, HasLen, 2)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandles[0])
	c.Check(authArea[1].SessionHandle, Equals, sessionHandles[1])

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
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyExtraData(c *C) {
	s.testCertify(c, &testCertifyData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestCertifyInScheme(c *C) {
	data := &testCertifyData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, false, &RSAScheme{Scheme: RSASchemeNull}),
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
	s.testCertify(c, &testCertifyData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
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

	object, _, _, creationHash, creationTicket, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, testutil.StorageKeyRSATemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	certifyInfo, signature, err := s.TPM.CertifyCreation(data.sign, object, data.qualifyingData, creationHash, data.inScheme, creationTicket, data.signAuthSession)
	c.Assert(err, IsNil)

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, HasLen, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

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
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyCreationExtraData(c *C) {
	s.testCertifyCreation(c, &testCertifyCreationData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestCertifyCreationInScheme(c *C) {
	data := &testCertifyCreationData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, false, &RSAScheme{Scheme: RSASchemeNull}),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		signHierarchy: HandleEndorsement}
	data.signScheme = data.inScheme
	s.testCertifyCreation(c, data)
}

func (s *attestationSuite) TestCertifyCreationSignAuthSession(c *C) {
	s.testCertifyCreation(c, &testCertifyCreationData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestCertifyCreationInvalidTicket(c *C) {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	object, _, _, creationHash, creationTicket, err := s.TPM.CreatePrimary(s.TPM.OwnerHandleContext(), nil, &template, nil, nil, nil)
	c.Assert(err, IsNil)

	creationTicket.Hierarchy = HandleEndorsement

	_, _, err = s.TPM.CertifyCreation(nil, object, nil, creationHash, nil, creationTicket, nil)
	c.Check(IsTPMParameterError(err, ErrorTicket, CommandCertifyCreation, 4), testutil.IsTrue)
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
	sessionHandle := authSessionHandle(data.signAuthSession)

	quoted, signature, err := s.TPM.Quote(data.sign, data.qualifyingData, data.inScheme, data.pcrs, data.signAuthSession)
	c.Assert(err, IsNil)

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, HasLen, 1)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandle)

	s.checkAttestCommon(c, quoted, TagAttestQuote, data.sign, data.signHierarchy, data.qualifyingData)
	_, pcrValues, err := s.TPM.PCRRead(data.pcrs)
	c.Assert(err, IsNil)
	digest, err := ComputePCRDigest(data.alg, data.pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(quoted.Attested.Quote.PCRSelect, DeepEquals, data.pcrs)
	c.Check(quoted.Attested.Quote.PCRDigest, DeepEquals, digest)

	s.checkAttestSignature(c, signature, data.sign, quoted, data.signScheme)
}

func (s *attestationSuite) TestQuote(c *C) {
	s.testQuote(c, &testQuoteData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteWithExtraData(c *C) {
	s.testQuote(c, &testQuoteData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		qualifyingData: []byte("bar"),
		pcrs:           PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signHierarchy:  HandleEndorsement,
		alg:            HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteInScheme(c *C) {
	data := &testQuoteData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, false, &RSAScheme{Scheme: RSASchemeNull}),
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

func (s *attestationSuite) TestQuoteDifferentPCRs(c *C) {
	s.testQuote(c, &testQuoteData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		pcrs:          PCRSelectionList{{Hash: HashAlgorithmSHA1, Select: []int{0}}, {Hash: HashAlgorithmSHA256, Select: []int{1, 2}}},
		signHierarchy: HandleEndorsement,
		alg:           HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestQuoteSignAuthSession(c *C) {
	s.testQuote(c, &testQuoteData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		pcrs:            PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		alg:             HashAlgorithmSHA256,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
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

	timeInfo, signature, err := s.TPM.GetTime(s.TPM.EndorsementHandleContext(), data.sign, data.qualifyingData, data.inScheme, data.privacyAdminAuthSession, data.signAuthSession)
	c.Assert(err, IsNil)

	_, authArea, _ := s.LastCommand(c).UnmarshalCommand(c)
	c.Assert(authArea, HasLen, 2)
	c.Check(authArea[0].SessionHandle, Equals, sessionHandles[0])
	c.Check(authArea[1].SessionHandle, Equals, sessionHandles[1])

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
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signHierarchy: HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}

func (s *attestationSuite) TestGetTimeExtraData(c *C) {
	s.testGetTime(c, &testGetTimeData{
		qualifyingData: []byte("foo")})
}

func (s *attestationSuite) TestGetTimeInScheme(c *C) {
	data := &testGetTimeData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, false, &RSAScheme{Scheme: RSASchemeNull}),
		inScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA1}}},
		signHierarchy: HandleEndorsement}
	data.signScheme = data.inScheme
	s.testGetTime(c, data)
}

func (s *attestationSuite) TestGetTimePrivacyAdminAuthSession(c *C) {
	s.testGetTime(c, &testGetTimeData{
		privacyAdminAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)})
}

func (s *attestationSuite) TestGetTimeSignAuthSession(c *C) {
	s.testGetTime(c, &testGetTimeData{
		sign: s.CreateSigningPrimaryKeyRSA(c, HandleEndorsement, true, &RSAScheme{
			Scheme:  RSASchemeRSASSA,
			Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}),
		signAuthSession: s.StartAuthSession(c, nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256),
		signHierarchy:   HandleEndorsement,
		signScheme: &SigScheme{
			Scheme: SigSchemeAlgRSASSA,
			Details: &SigSchemeU{
				RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}}})
}
