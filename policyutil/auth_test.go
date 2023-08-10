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

type authSuite struct {
	testutil.TPMTest
}

var _ = Suite(&authSuite{})

type testPolicySignedAuthorizationData struct {
	authKey         *tpm2.Public
	policyRef       tpm2.Nonce
	sessionAlg      tpm2.HashAlgorithmId
	includeNonceTPM bool
	cpHashA         CpHash
	expiration      int32

	signer     crypto.Signer
	signerOpts crypto.SignerOpts

	expectedScheme tpm2.SigSchemeId
	expectedHash   tpm2.HashAlgorithmId
}

func (s *authSuite) testPolicySignedAuthorization(c *C, data *testPolicySignedAuthorizationData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, data.sessionAlg)

	var nonceTPM tpm2.Nonce
	if data.includeNonceTPM {
		nonceTPM = session.NonceTPM()
	}

	auth, err := NewPolicySignedAuthorization(data.authKey, data.policyRef, data.sessionAlg, nonceTPM, data.cpHashA, data.expiration)
	c.Assert(err, IsNil)

	c.Check(auth.Sign(rand.Reader, data.signer, data.signerOpts), IsNil)

	c.Assert(auth.Signature, NotNil)
	c.Check(auth.Signature.SigAlg, Equals, data.expectedScheme)
	c.Check(auth.Signature.HashAlg(), Equals, data.expectedHash)

	key, err := s.TPM.LoadExternal(nil, data.authKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	var cpHashA tpm2.Digest
	if data.cpHashA != nil {
		cpHashA, err = data.cpHashA.Digest(data.sessionAlg)
		c.Check(err, IsNil)
	}

	_, _, err = s.TPM.PolicySigned(key, session, data.includeNonceTPM, cpHashA, data.policyRef, data.expiration, auth.Signature)
	c.Check(err, IsNil)
}

func (s *authSuite) TestPolicySignedAuthorizationRSAPSS(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		signer:         key,
		signerOpts:     &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		expectedScheme: tpm2.SigSchemeAlgRSAPSS,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationSHA1(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA1,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA1})
}

func (s *authSuite) TestPolicySignedAuthorizationIncludeNonceTPM(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:         authKey,
		sessionAlg:      tpm2.HashAlgorithmSHA256,
		includeNonceTPM: true,
		signer:          key,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationWithCpHashSHA256(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		cpHashA:        CommandParameters(tpm2.CommandUnseal, []Named{objectutil.NewSealedObjectTemplate()}),
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationWithCpHashSHA1(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA1,
		cpHashA:        CommandParameters(tpm2.CommandUnseal, []Named{objectutil.NewSealedObjectTemplate()}),
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationWithPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		policyRef:      []byte("policy"),
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:        authKey,
		sessionAlg:     tpm2.HashAlgorithmSHA256,
		expiration:     -100,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestPolicySignedAuthorizationWithAllRestrictions(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testPolicySignedAuthorization(c, &testPolicySignedAuthorizationData{
		authKey:         authKey,
		policyRef:       []byte("policy"),
		sessionAlg:      tpm2.HashAlgorithmSHA256,
		includeNonceTPM: true,
		cpHashA:         CommandParameters(tpm2.CommandUnseal, []Named{objectutil.NewSealedObjectTemplate()}),
		expiration:      -100,
		signer:          key,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256})
}

type testSignPolicySignedAuthorizationData struct {
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

func (s *authSuite) testSignPolicySignedAuthorization(c *C, data *testSignPolicySignedAuthorizationData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var nonceTPM tpm2.Nonce
	if data.includeNonceTPM {
		nonceTPM = session.NonceTPM()
	}

	auth, err := SignPolicySignedAuthorization(rand.Reader, data.signer, nonceTPM, data.cpHashA, data.policyRef, data.expiration, data.signerOpts)
	c.Assert(err, IsNil)
	c.Check(auth.SigAlg, Equals, data.expectedScheme)
	c.Check(auth.HashAlg(), Equals, data.expectedHash)

	key, err := s.TPM.LoadExternal(nil, data.authKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, _, err = s.TPM.PolicySigned(key, session, data.includeNonceTPM, data.cpHashA, data.policyRef, data.expiration, auth)
	c.Check(err, IsNil)
}

func (s *authSuite) TestSignPolicySignedAuthorizationRSAPSS(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:         key,
		signerOpts:     &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		expectedScheme: tpm2.SigSchemeAlgRSAPSS,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationECDSA(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationSHA1(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA1,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA1,
		authKey:        authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationIncludeNonceTPM(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:          key,
		includeNonceTPM: true,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256,
		authKey:         authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:         key,
		cpHashA:        h.Sum(nil),
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:         key,
		policyRef:      []byte("policy"),
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256,
		authKey:        authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		signer:          key,
		includeNonceTPM: true,
		expiration:      -100,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256,
		authKey:         authKey})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithAllRestrictions(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
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
