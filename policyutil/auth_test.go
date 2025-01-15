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
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type authSuite struct {
	testutil.TPMTest
}

var _ = Suite(&authSuite{})

type testSignPolicySignedAuthorizationData struct {
	session tpm2.SessionContext

	params     *PolicySignedParams
	authKey    *tpm2.Public
	policyRef  tpm2.Nonce
	signer     crypto.Signer
	signerOpts crypto.SignerOpts

	includeNonceTPM bool

	expectedScheme tpm2.SigSchemeId
	expectedHash   tpm2.HashAlgorithmId
}

func (s *authSuite) testSignPolicySignedAuthorization(c *C, data *testSignPolicySignedAuthorizationData) {
	auth, err := SignPolicySignedAuthorization(rand.Reader, data.params, data.authKey, data.policyRef, data.signer, data.signerOpts)
	c.Assert(err, IsNil)

	var expectedCpHash tpm2.Digest
	if data.params.CpHash != nil {
		expectedCpHash, err = data.params.CpHash.Digest(data.params.HashAlg)
		c.Check(err, IsNil)
	}

	c.Check(auth.NonceTPM, DeepEquals, data.params.NonceTPM)
	c.Check(auth.CpHash, DeepEquals, expectedCpHash)
	c.Check(auth.Expiration, DeepEquals, data.params.Expiration)
	c.Check(auth.AuthKey, DeepEquals, data.authKey)
	c.Check(auth.PolicyRef, DeepEquals, data.policyRef)
	c.Check(auth.Signature.SigAlg, Equals, data.expectedScheme)
	c.Check(auth.Signature.HashAlg(), Equals, data.expectedHash)

	ok, err := auth.Verify()
	c.Check(err, IsNil)
	c.Check(ok, internal_testutil.IsTrue)

	key, err := s.TPM.LoadExternal(nil, auth.AuthKey, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	_, _, err = s.TPM.PolicySigned(key, data.session, data.includeNonceTPM, auth.CpHash, auth.PolicyRef, auth.Expiration, auth.Signature)
	c.Check(err, IsNil)
}

func (s *authSuite) TestSignPolicySignedAuthorizationRSAPSS(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:        session,
		params:         &PolicySignedParams{},
		authKey:        authKey,
		signer:         key,
		signerOpts:     &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256},
		expectedScheme: tpm2.SigSchemeAlgRSAPSS,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationECDSA(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:        session,
		params:         &PolicySignedParams{},
		authKey:        authKey,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationSHA1(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:        session,
		params:         &PolicySignedParams{},
		authKey:        authKey,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA1,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA1})
}

func (s *authSuite) TestSignPolicySignedAuthorizationIncludeNonceTPM(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:         session,
		params:          &PolicySignedParams{NonceTPM: session.State().NonceTPM},
		authKey:         authKey,
		signer:          key,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		includeNonceTPM: true,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithCpHash(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session: session,
		params: &PolicySignedParams{
			HashAlg: tpm2.HashAlgorithmSHA256,
			CpHash:  CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil)),
		},
		authKey:        authKey,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithPolicyRef(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:        session,
		params:         &PolicySignedParams{},
		authKey:        authKey,
		policyRef:      []byte("policy"),
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithExpiration(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session:        session,
		params:         &PolicySignedParams{Expiration: -100},
		authKey:        authKey,
		signer:         key,
		signerOpts:     tpm2.HashAlgorithmSHA256,
		expectedScheme: tpm2.SigSchemeAlgECDSA,
		expectedHash:   tpm2.HashAlgorithmSHA256})
}

func (s *authSuite) TestSignPolicySignedAuthorizationWithAllRestrictions(c *C) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	s.testSignPolicySignedAuthorization(c, &testSignPolicySignedAuthorizationData{
		session: session,
		params: &PolicySignedParams{
			HashAlg:    tpm2.HashAlgorithmSHA256,
			NonceTPM:   session.State().NonceTPM,
			CpHash:     CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil)),
			Expiration: -100,
		},
		authKey:         authKey,
		policyRef:       []byte("policy"),
		signer:          key,
		signerOpts:      tpm2.HashAlgorithmSHA256,
		includeNonceTPM: true,
		expectedScheme:  tpm2.SigSchemeAlgECDSA,
		expectedHash:    tpm2.HashAlgorithmSHA256})
}
