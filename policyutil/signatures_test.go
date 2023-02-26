// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type signaturesSuite struct {
	testutil.TPMTest
}

var _ = Suite(&signaturesSuite{})

type testSignPolicyAuthorizationData struct {
	signer          crypto.Signer
	includeNonceTPM bool
	cpHashA         tpm2.Digest
	policyRef       tpm2.Nonce
	expiration      int32
	signerOpts      crypto.SignerOpts

	expectedScheme tpm2.SigSchemeId
	expectedHash   tpm2.HashAlgorithmId

	authKey *tpm2.Public
}

func (s *signaturesSuite) testSignPolicyAuthorization(c *C, data *testSignPolicyAuthorizationData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var nonceTPM tpm2.Nonce
	if data.includeNonceTPM {
		nonceTPM = session.NonceTPM()
	}

	auth, err := SignPolicyAuthorization(rand.Reader, data.signer, nonceTPM, data.cpHashA, data.policyRef, data.expiration, data.signerOpts)
	c.Assert(err, IsNil)
	c.Check(auth.SigAlg, Equals, data.expectedScheme)
	c.Check(auth.HashAlg(), Equals, data.expectedHash)

	key, err := s.TPM.LoadExternal(nil, data.authKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, _, err = s.TPM.PolicySigned(key, session, data.includeNonceTPM, data.cpHashA, data.policyRef, data.expiration, auth)
	c.Check(err, IsNil)
}

func (s *signaturesSuite) TestSignPolicyAuthorizationRSAPSS(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:         key,
		signerOpts:     &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		expectedScheme: tpm2.SigSchemeAlgRSAPSS,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationSHA1(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA1,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA1,
		authKey:        authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationIncludeNonceTPM(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:          key,
		includeNonceTPM: true,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256,
		authKey:         authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:         key,
		cpHashA:        h.Sum(nil),
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:         key,
		policyRef:      []byte("policy"),
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:          key,
		includeNonceTPM: true,
		expiration:      -100,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256,
		authKey:         authKey})
}

func (s *signaturesSuite) TestSignPolicyAuthorizationWithAllRestrictions(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicyAuthorization(c, &testSignPolicyAuthorizationData{
		signer:          key,
		includeNonceTPM: true,
		cpHashA:         h.Sum(nil),
		policyRef:       []byte("policy"),
		expiration:      -100,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256,
		authKey:         authKey})
}
