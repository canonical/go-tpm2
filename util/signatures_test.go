// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/testutil"
	. "github.com/canonical/go-tpm2/util"
)

type signaturesSuite struct {
	testutil.TPMTest
}

func (s *signaturesSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy
}

var _ = Suite(&signaturesSuite{})

func (s *signaturesSuite) TestSelectSigSchemeRSANull(c *C) {
	in := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	scheme, err := SelectSigScheme(templates.NewRSAKeyWithDefaults(0), in)
	c.Check(err, IsNil)
	c.Check(scheme, Equals, in)
}

func (s *signaturesSuite) TestSelectSigSchemeRSASSA(c *C) {
	in := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: tpm2.HashAlgorithmSHA1}}}
	keyScheme := &tpm2.RSAScheme{
		Scheme: tpm2.RSASchemeRSASSA,
		Details: &tpm2.AsymSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	scheme, err := SelectSigScheme(templates.NewRSAKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, keyScheme, 2048), in)
	c.Check(err, IsNil)
	c.Check(scheme, Not(Equals), in)
	c.Check(scheme.Scheme, Equals, tpm2.SigSchemeAlgRSASSA)
	c.Check(scheme.Details.RSASSA, Equals, keyScheme.Details.RSASSA)
}

func (s *signaturesSuite) TestSelectSigSchemeRSAPSS(c *C) {
	in := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	keyScheme := &tpm2.RSAScheme{
		Scheme: tpm2.RSASchemeRSAPSS,
		Details: &tpm2.AsymSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: tpm2.HashAlgorithmSHA512}}}
	scheme, err := SelectSigScheme(templates.NewRSAKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, keyScheme, 2048), in)
	c.Check(err, IsNil)
	c.Check(scheme, Not(Equals), in)
	c.Check(scheme.Scheme, Equals, tpm2.SigSchemeAlgRSAPSS)
	c.Check(scheme.Details.RSAPSS, Equals, keyScheme.Details.RSAPSS)
}

func (s *signaturesSuite) TestSelectSigSchemeECCNull(c *C) {
	in := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	scheme, err := SelectSigScheme(templates.NewECCKeyWithDefaults(0), in)
	c.Check(err, IsNil)
	c.Check(scheme, Equals, in)
}

func (s *signaturesSuite) TestSelectSigSchemeECDSA(c *C) {
	in := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA512}}}
	keyScheme := &tpm2.ECCScheme{
		Scheme: tpm2.ECCSchemeECDSA,
		Details: &tpm2.AsymSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	scheme, err := SelectSigScheme(templates.NewECCKey(tpm2.HashAlgorithmSHA256, templates.KeyUsageSign, keyScheme, tpm2.ECCCurveNIST_P256), in)
	c.Check(err, IsNil)
	c.Check(scheme, Not(Equals), in)
	c.Check(scheme.Scheme, Equals, tpm2.SigSchemeAlgECDSA)
	c.Check(scheme.Details.ECDSA, Equals, keyScheme.Details.ECDSA)
}

func (s *signaturesSuite) TestSignRSASSA(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := Sign(key, scheme, digest)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgRSASSA)
	c.Check(sig.Signature.RSASSA.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

	rc, err := s.TPM.LoadExternal(nil, pubKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, err = s.TPM.VerifySignature(rc, digest, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignRSAPSS(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := Sign(key, scheme, digest)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgRSAPSS)
	c.Check(sig.Signature.RSAPSS.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

	rc, err := s.TPM.LoadExternal(nil, pubKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, err = s.TPM.VerifySignature(rc, digest, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := Sign(key, scheme, digest)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgECDSA)
	c.Check(sig.Signature.ECDSA.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

	rc, err := s.TPM.LoadExternal(nil, pubKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, err = s.TPM.VerifySignature(rc, digest, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignHMAC(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := &tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgHMAC,
		Details: &tpm2.SigSchemeU{
			HMAC: &tpm2.SchemeHMAC{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := Sign(key, scheme, digest)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgHMAC)
	c.Check(sig.Signature.HMAC.HashAlg, Equals, tpm2.HashAlgorithmSHA256)

	pub, sensitive := NewExternalHMACKey(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA256, nil, key)

	rc, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	_, err = s.TPM.VerifySignature(rc, digest, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestVerifyRSASSA(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), digest, sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *signaturesSuite) TestVerifyRSASSAInvalid(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSASSA,
		Details: &tpm2.SigSchemeU{
			RSASSA: &tpm2.SigSchemeRSASSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), make([]byte, 32), sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *signaturesSuite) TestVerifyRSAPSS(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), digest, sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *signaturesSuite) TestVerifyRSAPSSInvalid(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgRSAPSS,
		Details: &tpm2.SigSchemeU{
			RSAPSS: &tpm2.SigSchemeRSAPSS{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), make([]byte, 32), sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *signaturesSuite) TestVerifyECDSA(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewECCKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), digest, sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *signaturesSuite) TestVerifyECDSAInvalid(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewECCKeyTemplate(templates.KeyUsageSign, nil))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgECDSA,
		Details: &tpm2.SigSchemeU{
			ECDSA: &tpm2.SigSchemeECDSA{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(key, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(pub.Public(), make([]byte, 32), sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

func (s *signaturesSuite) TestVerifyHMAC(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	pub, sensitive := testutil.NewExternalHMACKey(nil, key)

	rc, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgHMAC,
		Details: &tpm2.SigSchemeU{
			HMAC: &tpm2.SchemeHMAC{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(rc, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(key, digest, sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)
}

func (s *signaturesSuite) TestVerifyHMACInvalid(c *C) {
	key := make([]byte, 32)
	rand.Read(key)

	pub, sensitive := testutil.NewExternalHMACKey(nil, key)

	rc, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	scheme := tpm2.SigScheme{
		Scheme: tpm2.SigSchemeAlgHMAC,
		Details: &tpm2.SigSchemeU{
			HMAC: &tpm2.SchemeHMAC{
				HashAlg: tpm2.HashAlgorithmSHA256}}}
	sig, err := s.TPM.Sign(rc, digest, &scheme, nil, nil)
	c.Assert(err, IsNil)

	ok, err := VerifySignature(key, make([]byte, 32), sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsFalse)
}

type testSignPolicyAuthorizationData struct {
	key          crypto.PrivateKey
	pub          *tpm2.Public
	scheme       *tpm2.SigScheme
	includeNonce bool
	expiration   int32
	cpHashA      tpm2.Digest
	policyRef    tpm2.Nonce
}

func (s *signaturesSuite) testSignPolicyAuthorization(c *C, data *testSignPolicyAuthorizationData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var nonceTPM tpm2.Nonce
	if data.includeNonce {
		nonceTPM = session.NonceTPM()
	}

	sig, err := SignPolicyAuthorization(data.key, data.scheme, nonceTPM, data.cpHashA, data.policyRef, data.expiration)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, data.scheme.Scheme)

	key, err := s.TPM.LoadExternal(nil, data.pub, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, _, err = s.TPM.PolicySigned(key, session, data.includeNonce, data.cpHashA, data.policyRef, data.expiration, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignPolicyAuthorizationRSASSA(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgECDSA,
			Details: &tpm2.SigSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationIncludeNonce(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		includeNonce: true})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithExpiration(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		includeNonce: true,
		expiration:   100})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithCpHash(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		cpHashA: h.Sum(nil)})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithPolicyRef(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		policyRef: []byte("policy")})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationAllRestrictions(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params2")

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		key: key,
		pub: NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		includeNonce: true,
		expiration:   100,
		cpHashA:      h.Sum(nil),
		policyRef:    []byte("policy2")})
}

type testSignPolicyAuthorizeData struct {
	key       crypto.PrivateKey
	pub       *tpm2.Public
	command   tpm2.CommandCode
	scheme    *tpm2.SigScheme
	policyRef tpm2.Nonce
}

func (s *signaturesSuite) testPolicyAuthorize(c *C, data *testSignPolicyAuthorizeData) {
	trial := ComputeAuthPolicy(tpm2.HashAlgorithmSHA256)
	trial.PolicyCommandCode(data.command)

	approvedPolicy := trial.GetDigest()

	digest, sig, err := PolicyAuthorize(data.key, data.scheme, approvedPolicy, data.policyRef)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, data.scheme.Scheme)

	key, err := s.TPM.LoadExternal(nil, data.pub, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	validation, err := s.TPM.VerifySignature(key, digest, sig)
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)
	c.Check(s.TPM.PolicyCommandCode(session, data.command), IsNil)
	c.Check(s.TPM.PolicyAuthorize(session, approvedPolicy, data.policyRef, key.Name(), validation), IsNil)
}

func (s *signaturesSuite) TestPolicyAuthorizeRSASSA(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testSignPolicyAuthorizeData{
		key:     key,
		pub:     NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		command: tpm2.CommandUnseal,
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}})
}

func (s *signaturesSuite) TestPolicyAuthorizeECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testSignPolicyAuthorizeData{
		key:     key,
		pub:     NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		command: tpm2.CommandUnseal,
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgECDSA,
			Details: &tpm2.SigSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}})
}

func (s *signaturesSuite) TestPolicyAuthorizeDifferentPolicy(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testSignPolicyAuthorizeData{
		key:     key,
		pub:     NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		command: tpm2.CommandObjectChangeAuth,
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}}})
}

func (s *signaturesSuite) TestPolicyAuthorizeWithPolicyRef(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testSignPolicyAuthorizeData{
		key:     key,
		pub:     NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey),
		command: tpm2.CommandUnseal,
		scheme: &tpm2.SigScheme{
			Scheme: tpm2.SigSchemeAlgRSASSA,
			Details: &tpm2.SigSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{
					HashAlg: tpm2.HashAlgorithmSHA256}}},
		policyRef: []byte("ref")})
}

func (s *signaturesSuite) TestVerifyAttestationSignature(c *C) {
	key := s.CreatePrimary(c, tpm2.HandleEndorsement, testutil.NewRestrictedRSASigningKeyTemplate(nil))

	quoted, sig, err := s.TPM.Quote(key, nil, nil, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}}, nil)
	c.Assert(err, IsNil)

	pub, _, _, err := s.TPM.ReadPublic(key)
	c.Assert(err, IsNil)

	ok, err := VerifyAttestationSignature(pub.Public(), quoted, sig)
	c.Check(err, IsNil)
	c.Check(ok, testutil.IsTrue)

}
