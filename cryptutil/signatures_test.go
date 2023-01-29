// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package cryptutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/cryptutil"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"
)

type signaturesSuite struct {
	testutil.TPMTest
}

func (s *signaturesSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureEndorsementHierarchy
}

var _ = Suite(&signaturesSuite{})

func (s *signaturesSuite) TestSignRSASSA(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	sig, err := Sign(key, digest, crypto.SHA256)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgRSASSA)
	c.Check(sig.Signature.RSASSA.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

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

	sig, err := Sign(key, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgRSAPSS)
	c.Check(sig.Signature.RSAPSS.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := util.NewExternalRSAPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

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

	sig, err := Sign(key, digest, crypto.SHA256)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgECDSA)
	c.Check(sig.Signature.ECDSA.Hash, Equals, tpm2.HashAlgorithmSHA256)

	pubKey := util.NewExternalECCPublicKeyWithDefaults(templates.KeyUsageSign, &key.PublicKey)

	rc, err := s.TPM.LoadExternal(nil, pubKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, err = s.TPM.VerifySignature(rc, digest, sig)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignHMAC(c *C) {
	key := make(HMACKey, 32)
	rand.Read(key)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	sig, err := Sign(key, digest, crypto.SHA256)
	c.Assert(err, IsNil)
	c.Check(sig.SigAlg, Equals, tpm2.SigSchemeAlgHMAC)
	c.Check(sig.Signature.HMAC.HashAlg, Equals, tpm2.HashAlgorithmSHA256)

	pub, sensitive := util.NewExternalHMACKey(tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA256, nil, key)

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
	c.Check(ok, internal_testutil.IsTrue)
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
	c.Check(ok, internal_testutil.IsFalse)
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
	c.Check(ok, internal_testutil.IsTrue)
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
	c.Check(ok, internal_testutil.IsFalse)
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
	c.Check(ok, internal_testutil.IsTrue)
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
	c.Check(ok, internal_testutil.IsFalse)
}

func (s *signaturesSuite) TestVerifyHMAC(c *C) {
	key := make(HMACKey, 32)
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
	c.Check(ok, internal_testutil.IsTrue)
}

func (s *signaturesSuite) TestVerifyHMACInvalid(c *C) {
	key := make(HMACKey, 32)
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
	c.Check(ok, internal_testutil.IsFalse)
}
