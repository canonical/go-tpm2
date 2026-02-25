// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type mockSessionContext struct {
	session tpm2.SessionContext
	closed  bool
}

func (c *mockSessionContext) Session() tpm2.SessionContext {
	return c.session
}

func (c *mockSessionContext) Flush() error {
	c.closed = true
	return nil
}

type policySuiteNoTPM struct{}

var _ = Suite(&policySuiteNoTPM{})

func (s *policySuiteNoTPM) testMarshalUnmarshalPolicyBranchName(c *C, name PolicyBranchName, expected []byte) {
	b, err := mu.MarshalToBytes(name)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, expected)

	var recoveredName PolicyBranchName
	_, err = mu.UnmarshalFromBytes(b, &recoveredName)
	c.Check(recoveredName, Equals, name)
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName1(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "foo", []byte{0x00, 0x03, 0x66, 0x6f, 0x6f})
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName2(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "bar", []byte{0x00, 0x03, 0x62, 0x61, 0x72})
}

func (s *policySuiteNoTPM) TestMarshalInvalidPolicyBranchName(c *C) {
	_, err := mu.MarshalToBytes(PolicyBranchName("{foo}"))
	c.Check(err, ErrorMatches, `cannot marshal argument 0 whilst processing element of type policyutil.policyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestUnmarshalInvalidPolicyBranchName(c *C) {
	var name PolicyBranchName
	_, err := mu.UnmarshalFromBytes([]byte{0x00, 0x05, 0x7b, 0x66, 0x6f, 0x6f, 0x7d}, &name)
	c.Check(err, ErrorMatches, `cannot unmarshal argument 0 whilst processing element of type policyutil.policyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponent(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "foo")
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLeadingSeparator(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "foo")
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLast(c *C) {
	path := PolicyBranchPath("bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "bar")
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentEmpty(c *C) {
	path := PolicyBranchPath("")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "")
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleLeadingSeparators(c *C) {
	path := PolicyBranchPath("///foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "foo")
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleIntermediateSeparators(c *C) {
	path := PolicyBranchPath("foo////bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, "foo")
	c.Check(remaining, Equals, PolicyBranchPath("///bar"))
}

type testAuthorizePolicyData struct {
	hashAlg           tpm2.HashAlgorithmId
	keyPEM            string
	nameAlg           tpm2.HashAlgorithmId
	policyRef         tpm2.Nonce
	opts              crypto.SignerOpts
	expectedDigest    tpm2.Digest
	expectedSignature *tpm2.Signature
}

func (s *policySuiteNoTPM) testAuthorizePolicy(c *C, data *testAuthorizePolicyData) error {
	b, _ := pem.Decode([]byte(data.keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, internal_testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	keySign, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey, objectutil.WithNameAlg(data.nameAlg))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(data.hashAlg)
	builder.RootBranch().PolicyAuthValue()

	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	err = policy.Authorize(bytes.NewReader(make([]byte, 33)), keySign, data.policyRef, key.(crypto.Signer), data.opts)
	if err != nil {
		return err
	}

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: data.hashAlg, Digest: data.expectedDigest}},
		[]PolicyAuthorization{{AuthKey: keySign, PolicyRef: data.policyRef, Signature: data.expectedSignature}},
		NewMockPolicyAuthValueElement(),
	)
	c.Check(policy, DeepEquals, expectedPolicy)

	return nil
}

func (s *policySuiteNoTPM) TestAuthorizePolicy(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA256,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "fef27905ea5b0265ed72649b518c9dc34d9d729214fb65106b25188acdb0aa09"),
					SignatureS: internal_testutil.DecodeHexString(c, "55e8e6eb6bc688e16225539019ae82d6eba0ac9db61974d366f72a4d4c125ae4"),
				},
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyDifferentKey(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt7gAWQPrRPLVAexX
QO8Bog5Fu2sw+s+CVU1V41vVj4mhRANCAARij+FNq0+rxvdl+gIJPxY4nqMezDdo
c7C9ElAfzkjURTxVWrFldXF9M8kCdot7wNuLeWnIJL7p5y2A43mu4mOb
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA256,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "4ac10b34ab032a57fd2e430eadc31dedde61462cc8fa40ff6b13515abdb2b416"),
					SignatureS: internal_testutil.DecodeHexString(c, "3dbd37dbcb7b731c21505e919c003d23c8084e6c6ec0dfaa7b2a3341ec920514"),
				},
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyNoPolicyRef(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA256,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "5743fafc980e7dead11954e19ba3a0440f06fa0cd6eb2fbebc24a136834d392f"),
					SignatureS: internal_testutil.DecodeHexString(c, "8a0da89b7e1bd9cc56b21cb4b686b54d102d319186eeb819e2d70f80cf14d115"),
				},
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyDifferentSigningAlgorithm(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA256,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA1,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA1,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA1,
					SignatureR: internal_testutil.DecodeHexString(c, "2cabfc9be52de4b594be752e5d80f3651dde517e8a5bdb209883acb422335074"),
					SignatureS: internal_testutil.DecodeHexString(c, "01b3662bac8180fc4bce71dd512c54376408a79e1c35117a2006fdc534208684"),
				},
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyDifferentPolicyAlgorithm(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA1,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "af6038c78c5c962d37127e319124e3a8dc582e9b"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: &tpm2.SignatureU{
				ECDSA: &tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "a68ac303b875ed4428b6284d3d5ce020936eff45d239eb7949a1a390311248a9"),
					SignatureS: internal_testutil.DecodeHexString(c, "259695240c01bd676d059cb809cb8e117181e4b28987fbac60857b087edf1794"),
				},
			},
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyInvalidParams(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		hashAlg:        tpm2.HashAlgorithmSHA256,
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA1,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
	})
	c.Check(err, ErrorMatches, `mismatched authKey name and opts`)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyMultipleAlgs(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	b, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, internal_testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	keySign, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	expectedDigestSHA1 := tpm2.Digest(internal_testutil.DecodeHexString(c, "af6038c78c5c962d37127e319124e3a8dc582e9b"))
	expectedDigestSHA256 := tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"))

	digestSHA256, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(digestSHA256, DeepEquals, expectedDigestSHA256)

	digestSHA1, err := policy.AddDigest(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)
	c.Check(digestSHA1, DeepEquals, expectedDigestSHA1)

	err = policy.Authorize(bytes.NewReader(make([]byte, 66)), keySign, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	expectedSignatureSHA256 := &tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgECDSA,
		Signature: &tpm2.SignatureU{
			ECDSA: &tpm2.SignatureECDSA{
				Hash:       tpm2.HashAlgorithmSHA256,
				SignatureR: internal_testutil.DecodeHexString(c, "fef27905ea5b0265ed72649b518c9dc34d9d729214fb65106b25188acdb0aa09"),
				SignatureS: internal_testutil.DecodeHexString(c, "55e8e6eb6bc688e16225539019ae82d6eba0ac9db61974d366f72a4d4c125ae4"),
			},
		},
	}
	expectedSignatureSHA1 := &tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgECDSA,
		Signature: &tpm2.SignatureU{
			ECDSA: &tpm2.SignatureECDSA{
				Hash:       tpm2.HashAlgorithmSHA256,
				SignatureR: internal_testutil.DecodeHexString(c, "a68ac303b875ed4428b6284d3d5ce020936eff45d239eb7949a1a390311248a9"),
				SignatureS: internal_testutil.DecodeHexString(c, "259695240c01bd676d059cb809cb8e117181e4b28987fbac60857b087edf1794"),
			},
		},
	}

	expectedPolicy := NewMockPolicy(
		TaggedHashList{
			{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigestSHA256},
			{HashAlg: tpm2.HashAlgorithmSHA1, Digest: expectedDigestSHA1},
		},
		[]PolicyAuthorization{
			{AuthKey: keySign, PolicyRef: []byte("foo"), Signature: expectedSignatureSHA256},
			{AuthKey: keySign, PolicyRef: []byte("foo"), Signature: expectedSignatureSHA1},
		},
		NewMockPolicyAuthValueElement(),
	)
	c.Check(policy, DeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 # auth 0 authName:%#[2]x, policyRef:0x666f6f, sigAlg:TPM_ALG_ECDSA, hashAlg:TPM_ALG_SHA256
 # auth 1 authName:%#[2]x, policyRef:0x666f6f, sigAlg:TPM_ALG_ECDSA, hashAlg:TPM_ALG_SHA256
 PolicyAuthValue()
}`, expectedDigestSHA256, keySign.Name()))
	c.Check(policy.Stringer(tpm2.HashAlgorithmSHA1, nil).String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA1:%#[1]x
 # auth 0 authName:%#[2]x, policyRef:0x666f6f, sigAlg:TPM_ALG_ECDSA, hashAlg:TPM_ALG_SHA256
 # auth 1 authName:%#[2]x, policyRef:0x666f6f, sigAlg:TPM_ALG_ECDSA, hashAlg:TPM_ALG_SHA256
 PolicyAuthValue()
}`, expectedDigestSHA1, keySign.Name()))
}

func (s *policySuiteNoTPM) TestPolicyDigest1(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyDigest2(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVRead)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyDigestSHA1(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyAuthValue()

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type policySuite struct {
	testutil.TPMTest
}

func (s *policySuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&policySuite{})
