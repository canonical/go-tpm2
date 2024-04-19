// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
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

type mockAuthorizer struct {
	authorizeFn func(tpm2.ResourceContext) error
}

func (h *mockAuthorizer) Authorize(resource tpm2.ResourceContext) error {
	if h.authorizeFn == nil {
		return nil
	}
	return h.authorizeFn(resource)
}

type mockSignedAuthorizer struct {
	signAuthorization func(tpm2.HashAlgorithmId, tpm2.Nonce, tpm2.Name, tpm2.Nonce) (*PolicySignedAuthorization, error)
}

func (h *mockSignedAuthorizer) SignedAuthorization(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	if h.signAuthorization == nil {
		return nil, errors.New("not implemented")
	}
	return h.signAuthorization(sessionAlg, sessionNonce, authKey, policyRef)
}

type mockExternalSensitiveResources struct {
	externalSensitive func(tpm2.Name) (*tpm2.Sensitive, error)
}

func (h *mockExternalSensitiveResources) ExternalSensitive(name tpm2.Name) (*tpm2.Sensitive, error) {
	if h.externalSensitive == nil {
		return nil, errors.New("not implemented")
	}
	return h.externalSensitive(name)
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

func (s *policySuiteNoTPM) TestPolicyAddDigestCpHash(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyCpHash(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyCpHash assertion' task in root branch: cannot compute digest for policies with TPM2_PolicyCpHash assertion`)
}

func (s *policySuiteNoTPM) TestPolicyAddDigestNameHash(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNameHash(tpm2.MakeHandleName(tpm2.HandleOwner))

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNameHash assertion' task in root branch: cannot compute digest for policies with TPM2_PolicyNameHash assertion`)
}

func (s *policySuiteNoTPM) TestPolicyBranchesMultipleDigests(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashListSHA1 tpm2.DigestList
	var pHashListSHA256 tpm2.DigestList
	var policies []*Policy

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyAuthValue()
	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)
	policies = append(policies, policy)
	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)
	policies = append(policies, policy)
	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies...)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	expectedDigestSHA256, err := builder.Digest()
	c.Assert(err, IsNil)
	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA1, policies...)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	expectedDigestSHA1, err := builder.Digest()
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	digest, err = b1.PolicyAuthValue()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashListSHA1[0])

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	digest, err = b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashListSHA1[1])

	digest, err = builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigestSHA1)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{
			{HashAlg: tpm2.HashAlgorithmSHA1, Digest: expectedDigestSHA1},
			{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigestSHA256},
		},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[0]},
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[0]},
				},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[1]},
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[1]},
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	digest, policy, err = builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigestSHA1)

	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigestSHA256)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA1:%#[1]x
 PolicyNvWritten(true)
 BranchNode {
   Branch 0 (branch1) {
    # digest TPM_ALG_SHA1:%#[2]x
    PolicyAuthValue()
   }
   Branch 1 (branch2) {
    # digest TPM_ALG_SHA1:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
   }
 }
 PolicyOR(
  %#[2]x
  %#[3]x
 )
 PolicyCommandCode(TPM_CC_NV_ChangeAuth)
}`, expectedDigestSHA1, pHashListSHA1[0], pHashListSHA1[1]))
	c.Check(policy.Stringer(tpm2.HashAlgorithmSHA256, nil).String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 PolicyNvWritten(true)
 BranchNode {
   Branch 0 (branch1) {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
   }
   Branch 1 (branch2) {
    # digest TPM_ALG_SHA256:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
   }
 }
 PolicyOR(
  %#[2]x
  %#[3]x
 )
 PolicyCommandCode(TPM_CC_NV_ChangeAuth)
}`, expectedDigestSHA256, pHashListSHA256[0], pHashListSHA256[1]))
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
	c.Logf("%x", digest)

	err = policy.Authorize(bytes.NewReader(make([]byte, 33)), data.hashAlg, keySign, data.policyRef, key.(crypto.Signer), data.opts)
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

func (s *policySuiteNoTPM) TestPolicyValidate(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateWithBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateWithMultipleBranchNodes(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("")
	b1.PolicyAuthValue()

	b2 := node1.AddBranch("")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("")
	b3.PolicyCommandCode(tpm2.CommandNVChangeAuth)

	b4 := node2.AddBranch("")
	b4.PolicyCommandCode(tpm2.CommandObjectChangeAuth)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateMissingBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Validate(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)
}

func (s *policySuiteNoTPM) TestPolicyBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{""})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1", "branch2"})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithMultipleBranchNodes(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node1.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("branch3")
	b3.PolicyCommandCode(tpm2.CommandNVChangeAuth)

	b4 := node2.AddBranch("")
	b4.PolicyCommandCode(tpm2.CommandObjectChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1/branch3", "branch1/{1}", "branch2/branch3", "branch2/{1}"})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithAuthorize(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"<authorize:key:0x000b64dc4ba32a23deb5f2dfa58c03da0c3900ecd6f1409976e863009f42ab876ea1,ref:0x666f6f>"})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithAuthorize2(c *C) {
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

	pub, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)
	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	_, authPolicy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy1.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	_, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, NewPolicyAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{
		"8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e",
		"27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b",
	})
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

type testExecutePolicyNVData struct {
	nvPub      *tpm2.NVPublic
	readAuth   tpm2.ResourceContext
	readPolicy *Policy
	contents   []byte

	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp

	expectedCommands    int
	expectedAuthorize   bool
	expectedSessionType tpm2.HandleType
}

func (s *policySuite) testPolicyNV(c *C, data *testExecutePolicyNVData) error {
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, data.nvPub)
	c.Assert(s.TPM.NVWrite(index, index, data.contents, 0, nil), IsNil)

	readAuth := data.readAuth
	if readAuth == nil {
		readAuth = index
	}

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNV(nvPub, data.operandB, data.offset, data.operation)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var resources *PolicyResourcesData
	if data.readPolicy != nil {
		resources = &PolicyResourcesData{
			Persistent: []PersistentResource{
				{Name: readAuth.Name(), Handle: readAuth.Handle(), Policy: data.readPolicy},
			},
		}
	}

	authorized := false
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			authorized = true
			if !data.expectedAuthorize {
				resource.SetAuthValue([]byte("1234"))
			} else {
				c.Check(resource.Name(), DeepEquals, readAuth.Name())
			}
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(authorized, Equals, data.expectedAuthorize)

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-2]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicyNV)
	_, authArea, _ := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyNV(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperand(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001001"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOffset(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000010000000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              2,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperation(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpUnsignedGT,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVFails(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:             nvPub,
		contents:          internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:          internal_testutil.DecodeHexString(c, "00001000"),
		offset:            4,
		operation:         tpm2.OpEq,
		expectedAuthorize: true,
	})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index.Handle(), Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Index.Name(), DeepEquals, nvPub.Name())

	var e *tpm2.TPMError
	c.Assert(ne, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorPolicy})
}

func (s *policySuite) TestPolicyNVDifferentAuth(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		readAuth:            s.TPM.OwnerHandleContext(),
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    8,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithPolicySessionRequiresAuth(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    8,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVMissingPolicy(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:     nvPub,
		contents:  internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`cannot authorize resource with name 0x([[:xdigit:]]{68}): no auth types available`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index.Handle(), Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Index.Name(), DeepEquals, nvPub.Name())

	var re *ResourceAuthorizeError
	c.Assert(err, internal_testutil.ErrorAs, &re)
	c.Check(re.Name, DeepEquals, nvPub.Name())
}

func (s *policySuite) TestPolicyNVPrefersPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithSubPolicyError(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), nil)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:               nvPub,
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`cannot authorize resource with name 0x([[:xdigit:]]{68}): `+
		`cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x40000001, policyRef=: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index.Handle(), Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Index.Name(), DeepEquals, nvPub.Name())

	var rae *ResourceAuthorizeError
	c.Assert(ne, internal_testutil.ErrorAs, &rae)
	c.Check(rae.Name, DeepEquals, nvPub.Name())

	c.Assert(rae, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var se *tpm2.TPMSessionError
	c.Assert(pe, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

type testExecutePolicySecretData struct {
	authObject Named
	policyRef  tpm2.Nonce
	resources  *PolicyResourcesData

	expectedFlush       bool
	expectedCommands    int
	expectedAuth        int
	expectedSessionType tpm2.HandleType
}

func (s *policySuite) testPolicySecret(c *C, data *testExecutePolicySecretData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(data.authObject, data.policyRef)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	nAuths := 0
	var authObjectHandle tpm2.Handle
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			if nAuths == data.expectedAuth {
				c.Check(resource.Name(), DeepEquals, data.authObject.Name())
				authObjectHandle = resource.Handle()
			}
			nAuths++
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, data.resources, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(authObjectHandle, Not(Equals), tpm2.Handle(0))

	offsetEnd := 2
	if data.expectedFlush {
		offsetEnd++
	}

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-offsetEnd]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicySecret)
	_, authArea, cpBytes := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	var nonceTPM tpm2.Nonce
	var cpHashA tpm2.Digest
	var policyRef tpm2.Nonce
	var expiration int32
	_, err = mu.UnmarshalFromBytes(cpBytes, &nonceTPM, &cpHashA, &policyRef, &expiration)
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(nil))
	c.Check(expiration, Equals, int32(0))

	if data.expectedFlush {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	} else {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsTrue)
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicySecret(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		policyRef:           []byte("foo"),
		expectedCommands:    8,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretNoPolicyRef(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		expectedCommands:    8,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithTransientLoadRequiresPolicy(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandLoad)
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	template := testutil.NewRSAStorageKeyTemplate()
	template.AuthPolicy = policyDigest

	parent := s.CreatePrimary(c, tpm2.HandleOwner, template)
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
					Policy: policy,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    15,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithTransientPolicySession(c *C) {
	parent := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAStorageKeyTemplate())
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	template := objectutil.NewRSAStorageKeyTemplate(
		objectutil.WithoutDictionaryAttackProtection(),
		objectutil.WithUserAuthMode(objectutil.RequirePolicy),
		objectutil.WithAuthPolicy(policyDigest),
	)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, template, nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
					Policy:     policy,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    15,
		expectedAuth:        1,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithTransient(c *C) {
	parent := s.CreatePrimary(c, tpm2.HandleOwner, testutil.NewRSAStorageKeyTemplate())
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    14,
		expectedAuth:        1,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretFail(c *C) {
	s.TPM.OwnerHandleContext().SetAuthValue([]byte("1234"))

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x40000001, policyRef=0x666f6f: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, s.TPM.OwnerHandleContext().Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMSessionError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

func (s *policySuite) TestPolicySecretMissingResource(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: object.Name(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: cannot load resource with name 0x([[:xdigit:]]{68}): resource not found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, object.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var rle *ResourceLoadError
	c.Check(err, internal_testutil.ErrorAs, &rle)
	c.Check(rle.Name, DeepEquals, object.Name())
}

func (s *policySuite) TestPolicySecretWithNV(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          nvPub,
		policyRef:           []byte("foo"),
		expectedCommands:    11,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    10,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVPreferHMACSession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    9,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVMissingPolicySession(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	policyDigest, _, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x000b2ce1bec1b93901ee1e39517612a216fe496c26fa595fd5cf4149ff8f225e6aa9, policyRef=0x666f6f: `+
		`cannot authorize resource with name 0x000b2ce1bec1b93901ee1e39517612a216fe496c26fa595fd5cf4149ff8f225e6aa9: no auth types available`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, nvPub.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var re *ResourceAuthorizeError
	c.Assert(err, internal_testutil.ErrorAs, &re)
	c.Check(re.Name, DeepEquals, nvPub.Name())
}

type testExecutePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	signer            crypto.Signer
	includeNonceTPM   bool
	cpHashA           tpm2.Digest
	expiration        int32
	signerOpts        crypto.SignerOpts
	externalSensitive *tpm2.Sensitive
}

func (s *policySuite) testPolicySigned(c *C, data *testExecutePolicySignedData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySigned(data.authKey, data.policyRef)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionAlg, Equals, session.Params().HashAlg)
			c.Check(sessionNonce, DeepEquals, session.State().NonceTPM)
			c.Check(authKey, DeepEquals, data.authKey.Name())
			c.Check(policyRef, DeepEquals, data.policyRef)

			return SignPolicySignedAuthorization(rand.Reader, &PolicySignedParams{
				NonceTPM:   sessionNonce,
				CpHash:     data.cpHashA,
				Expiration: data.expiration,
			}, data.authKey, policyRef, data.signer, data.signerOpts)
		},
	}
	externalSensitiveResources := &mockExternalSensitiveResources{
		externalSensitive: func(name tpm2.Name) (*tpm2.Sensitive, error) {
			c.Check(data.externalSensitive, NotNil)
			c.Check(name, DeepEquals, data.authKey.Name())
			return data.externalSensitive, nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{SignedAuthorizer: authorizer, ExternalSensitiveResources: externalSensitiveResources}), NewTPMHelper(s.TPM, nil), nil)
	if err != nil {
		return err
	}
	if data.expiration < 0 && err == nil {
		c.Assert(result.NewTickets, internal_testutil.LenEquals, 1)
		c.Check(result.NewTickets[0].AuthName, DeepEquals, data.authKey.Name())
		c.Check(result.NewTickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(result.NewTickets[0].CpHash, DeepEquals, data.cpHashA)
		c.Check(result.NewTickets[0].Ticket.Tag, Equals, tpm2.TagAuthSigned)
		c.Check(result.NewTickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	}
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	if len(data.cpHashA) > 0 {
		cpHash, set := result.CpHash()
		c.Check(set, internal_testutil.IsTrue)
		c.Check(cpHash, DeepEquals, data.cpHashA)
	} else {
		_, set = result.CpHash()
		c.Check(set, internal_testutil.IsFalse)
	}
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicySigned(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:         pubKey,
		signer:          key,
		includeNonceTPM: true,
		signerOpts:      tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedIncludeTPMNonce(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    cpHashA,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		expiration: 100,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithRequestedTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    cpHashA,
		expiration: -100,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedHMAC(c *C) {
	hmacKey := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, hmacKey)
	c.Assert(err, IsNil)

	pubKey, sensitive, err := objectutil.NewHMACKey(rand.Reader, hmacKey, nil, objectutil.WithoutDictionaryAttackProtection())
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:           pubKey,
		policyRef:         []byte("foo"),
		signer:            cryptutil.HMACKey(hmacKey),
		signerOpts:        crypto.SHA256,
		externalSensitive: sensitive,
	})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySigned assertion' task in root branch: `+
		`cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 5 whilst executing command TPM_CC_PolicySigned: TPM_RC_SIGNATURE \(the signature is not valid\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySigned, Code: tpm2.ErrorSignature}, Index: 5})
}

func (s *policySuite) TestPolicySignedWithTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySigned(authKey, nil)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKeyName tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionAlg, Equals, session.Params().HashAlg)
			c.Check(sessionNonce, DeepEquals, session.State().NonceTPM)
			c.Check(authKeyName, DeepEquals, authKey.Name())
			c.Check(policyRef, IsNil)

			return SignPolicySignedAuthorization(rand.Reader, &PolicySignedParams{
				NonceTPM:   sessionNonce,
				Expiration: -100,
			}, authKey, policyRef, key, tpm2.HashAlgorithmSHA256)
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{SignedAuthorizer: authorizer}), NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 1)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params := &PolicyExecuteParams{Tickets: result.NewTickets}

	result, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), params)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set = result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyAuthorizeData struct {
	keySign                  *tpm2.Public
	policyRef                tpm2.Nonce
	authorizedPolicies       []*Policy
	path                     string
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
	expectedNvWrittenSet     bool
	expectedNvWritten        bool
}

func (s *policySuite) testPolicyAuthorize(c *C, data *testExecutePolicyAuthorizeData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize(data.policyRef, data.keySign)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: data.path,
	}
	resources := &PolicyResourcesData{
		AuthorizedPolicies: data.authorizedPolicies,
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, &TPMPolicyResourcesParams{Authorizer: new(mockAuthorizer)}), NewTPMHelper(s.TPM, nil), params)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	if data.expectedCommandCode == tpm2.CommandCode(0) {
		c.Check(set, internal_testutil.IsFalse)
	} else {
		c.Check(set, internal_testutil.IsTrue)
		c.Check(code, Equals, data.expectedCommandCode)
	}
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, Equals, data.expectedNvWrittenSet)
	c.Check(nvWritten, Equals, data.expectedNvWritten)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyAuthorize(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizeDifferentKeyNameAlg(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey, objectutil.WithNameAlg(tpm2.HashAlgorithmSHA1))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA1), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}
func (s *policySuite) TestPolicyAuthorizeWithNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, nil, key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizePolicyNotFound(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("bar"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x626172: no policies`)

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("bar"))
}

func (s *policySuite) TestPolicyAuthorizeInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("foo"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \(the signature is not valid\)`)

	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandVerifySignature, Code: tpm2.ErrorSignature}, Index: 2})

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) testPolicyAuthorizeWithSubPolicyBranches(c *C, path string, expectedRequireAuthValue bool, expectedPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	approvedPolicy, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		path:                     path,
		expectedRequireAuthValue: expectedRequireAuthValue,
		expectedPath:             strings.Join([]string{fmt.Sprintf("%x", approvedPolicy), expectedPath}, "/"),
		expectedCommandCode:      tpm2.CommandNVChangeAuth,
		expectedNvWrittenSet:     true,
		expectedNvWritten:        true,
	})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizeWithSubPolicyBranches(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "", true, "branch1")
}

func (s *policySuite) TestPolicyAuthorizeWithSubPolicyBranchesExplicitPath(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "*/branch2", false, "branch2")
}

func (s *policySuite) TestPolicyAuthorizeWithMultiplePolicies(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	builder.RootBranch().PolicyPCR(values)
	_, policy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy1.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	_, values, err = s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPCR(values)
	approvedPolicy, policy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy2.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy1, policy2},
		expectedRequireAuthValue: false,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyAuthValue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) testPolicyCommandCode(c *C, code tpm2.CommandCode) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCommandCode(code)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	codeResult, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(codeResult, Equals, code)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCommandCodeNVChangeAuth(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandNVChangeAuth)
}

func (s *policySuite) TestPolicyCommandCodeUnseal(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandUnseal)
}

type testExecutePolicyCounterTimerData struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyCounterTimer(c *C, data *testExecutePolicyCounterTimerData) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyCounterTimer1(c *C) {
	c.Skip("test fails in github")

	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedGT})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimer2(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint32(0)))
	binary.BigEndian.PutUint32(operandB, timeInfo.ClockInfo.RestartCount)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    20,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimerFails(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedLT})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyCounterTimer assertion' task in root branch: TPM returned an error whilst executing command TPM_CC_PolicyCounterTimer: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var e *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyCounterTimer, Code: tpm2.ErrorPolicy})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyCpHashData struct {
	code    tpm2.CommandCode
	handles []Named
	params  []interface{}
}

func (s *policySuite) testPolicyCpHash(c *C, data *testExecutePolicyCpHashData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	cpHash, set := result.CpHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedCpHash, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, data.code, data.handles, data.params...)
	c.Assert(err, IsNil)
	c.Check(cpHash, DeepEquals, expectedCpHash)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCpHash1(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policySuite) TestPolicyCpHash2(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policySuite) testPolicyNameHash(c *C, handles ...Named) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNameHash(handles...)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	nameHash, set := result.NameHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedNameHash, err := ComputeNameHash(tpm2.HashAlgorithmSHA256, handles...)
	c.Assert(err, IsNil)
	c.Check(nameHash, DeepEquals, expectedNameHash)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNameHash1(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x01})
}

func (s *policySuite) TestPolicyNameHash2(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x0b})
}

type testExecutePolicyBranchesData struct {
	usage                    *PolicySessionUsage
	path                     string
	ignoreAuthorizations     []PolicyAuthorizationID
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
}

func (s *policySuite) testPolicyBranches(c *C, data *testExecutePolicyBranchesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	b3 := node.AddBranch("branch3")
	b3.PolicySigned(pubKey, []byte("bar"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage:                data.usage,
		Path:                 data.path,
		IgnoreAuthorizations: data.ignoreAuthorizations,
	}
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}
	signedAuthorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			return SignPolicySignedAuthorization(rand.Reader, nil, pubKey, policyRef, key, crypto.SHA256)
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer, SignedAuthorizer: signedAuthorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWrittenSet, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		c.Check(log[i].GetCommandCode(c), Equals, data.expectedCommands[i])
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranches(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchesNumericSelector(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchesDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchesNumericSelectorDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "{1}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchAutoSelectNoUsage(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsage1(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsage2(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsageAndIgnore(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		ignoreAuthorizations: []PolicyAuthorizationID{
			{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
		},
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandLoadExternal,
			tpm2.CommandPolicySigned,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch3"})
}

func (s *policySuite) TestPolicyBranchesMultipleDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "branch1")
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWrittenSet, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyBranchesMultipleNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesMultipleNodes(c *C, data *testExecutePolicyBranchesMultipleNodesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node1.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("branch3")
	b3.PolicyCommandCode(tpm2.CommandNVChangeAuth)

	b4 := node2.AddBranch("branch4")
	b4.PolicyCommandCode(tpm2.CommandNVWriteLock)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, data.expectedCommandCode)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesMultipleNodes1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesNumericSelectors(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "{0}/{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch2/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "branch2",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "**/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

type testExecutePolicyBranchesEmbeddedNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesEmbeddedNodes(c *C, data *testExecutePolicyBranchesEmbeddedNodesData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	b1.PolicyAuthValue()

	node2 := b1.AddBranchNode()

	b2 := node2.AddBranch("branch2")
	b2.PolicyCommandCode(tpm2.CommandNVChangeAuth)

	b3 := node2.AddBranch("branch3")
	b3.PolicyCommandCode(tpm2.CommandNVWriteLock)

	b4 := node1.AddBranch("branch4")
	b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	node3 := b4.AddBranchNode()

	b5 := node3.AddBranch("branch5")
	b5.PolicyCommandCode(tpm2.CommandNVChangeAuth)

	b6 := node3.AddBranch("branch6")
	b6.PolicyCommandCode(tpm2.CommandNVWriteLock)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, nil, &TPMPolicyResourcesParams{Authorizer: authorizer}), NewTPMHelper(s.TPM, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, data.expectedCommandCode)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, internal_testutil.IsTrue)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesNumericSelectors(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "{0}/{0}",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch5",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes4(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch6",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)), tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch3",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch6",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []NamedHandle{tpm2.NewResourceContext(0x01000000, append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...))}, tpm2.Auth("foo")).WithoutAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandContextLoad,
			tpm2.CommandGetCapability,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesSelectorOutOfRange(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "{2}",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: selected path 2 out of range`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesInvalidSelector(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "{foo}",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: badly formatted path component "{foo}": expected integer`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesBranchNotFound(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "foo",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: no branch with name "foo"`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesMissingBranchDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in branch 'branch1': missing digest for session algorithm`)
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "branch1")
}

func (s *policySuite) testPolicyPCR(c *C, values tpm2.PCRValues) error {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPCR(values)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyPCR(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRDifferentDigestAndSelection(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRFails(c *C) {
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	err := s.testPolicyPCR(c, values)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyPCR assertion' task in root branch: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyPCR: TPM_RC_VALUE \(value is out of range or is not correct for the context\)`)
	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool
	usage         *PolicySessionUsage
}

func (s *policySuite) testPolicyDuplicationSelect(c *C, data *testExecutePolicyDuplicationSelectData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, &PolicyExecuteParams{Usage: data.usage})
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	code, set := result.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandDuplicate)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	nameHash, set := result.NameHash()
	c.Check(set, internal_testutil.IsTrue)
	var expectedNameHash tpm2.Digest
	if data.object != nil {
		expectedNameHash, err = ComputeNameHash(tpm2.HashAlgorithmSHA256, data.object.Name(), data.newParent.Name())
		c.Assert(err, IsNil)
	} else {
		c.Assert(data.usage, NotNil)
		expectedNameHash, err = data.usage.NameHash(tpm2.HashAlgorithmSHA256)
		c.Assert(err, IsNil)
	}
	c.Check(nameHash, DeepEquals, expectedNameHash)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: false})
}

func (s *policySuite) TestPolicyDuplicationSelectNoIncludeObjectName(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		newParent:     newParent,
		includeObject: false,
		usage:         NewPolicySessionUsage(tpm2.CommandDuplicate, []NamedHandle{tpm2.NewResourceContext(0x80000000, object), tpm2.NewResourceContext(0x80000001, newParent)}, tpm2.Data{}, tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull}),
	})
}

func (s *policySuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyPassword()
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyPassword)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) testPolicyNvWritten(c *C, writtenSet bool) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(writtenSet)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	nvWritten, set := result.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWritten, Equals, writtenSet)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, false)
}

func (s *policySuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, true)
}

type testExecutePolicyORData struct {
	policy    *Policy
	pHashList tpm2.DigestList
}

func (s *policySuite) testPolicyOR(c *C, data *testExecutePolicyORData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyOR(data.pHashList...)
	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = data.policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Check(err, IsNil)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyOR(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testExecutePolicyORData{
		policy:    policy,
		pHashList: tpm2.DigestList{digest1, digest2},
	})
}

func (s *policySuite) TestPolicyORDifferentDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testExecutePolicyORData{
		policy:    policy,
		pHashList: tpm2.DigestList{digest2, digest1},
	})
}

func (s *policySuiteNoTPM) TestPolicyDetails(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)

	nvPub := &tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	builder.RootBranch().PolicyNV(nvPub, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, 0, tpm2.OpUnsignedLT)

	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)
	builder.RootBranch().PolicySigned(pub, []byte("bar"))

	builder.RootBranch().PolicyAuthValue()
	builder.RootBranch().PolicyCommandCode(tpm2.CommandUnseal)
	builder.RootBranch().PolicyCounterTimer([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}, 0, tpm2.OpUnsignedLT)
	builder.RootBranch().PolicyCpHash(tpm2.CommandUnseal, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)})

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: foo, 7: bar}}
	builder.RootBranch().PolicyPCR(pcrValues)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, "", nil)
	c.Assert(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, exists := details[""]
	c.Assert(exists, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)

	c.Check(bd.NV, DeepEquals, []PolicyNVDetails{
		{Auth: nvPub.Index, Index: nvPub.Index, Name: nvPub.Name(), OperandB: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, Offset: 0, Operation: tpm2.OpUnsignedLT},
	})
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})
	c.Check(bd.Signed, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("bar")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandUnseal)

	c.Check(bd.CounterTimer, DeepEquals, []PolicyCounterTimerDetails{
		{OperandB: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}, Offset: 0, Operation: tpm2.OpUnsignedLT},
	})

	cpHash, set := bd.CpHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedCpHash, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandUnseal, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)})
	c.Check(err, IsNil)
	c.Check(cpHash, DeepEquals, expectedCpHash)

	_, set = bd.NameHash()
	c.Check(set, internal_testutil.IsFalse)

	expectedPcrs, expectedPcrDigest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	c.Check(err, IsNil)
	c.Check(bd.PCR, DeepEquals, []PolicyPCRDetails{{PCRDigest: expectedPcrDigest, PCRs: expectedPcrs}})

	_, set = bd.NvWritten()
	c.Check(set, internal_testutil.IsFalse)
}

func (s *policySuiteNoTPM) testPolicyDetailsWithBranches(c *C, path string) map[string]PolicyBranchDetails {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, path, nil)
	c.Assert(err, IsNil)
	return details
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithBranches(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "")
	c.Check(details, internal_testutil.LenEquals, 2)

	bd, exists := details["branch1"]
	c.Assert(exists, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)

	nvWrittenSet, set := bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(bd.Secret, internal_testutil.LenEquals, 0)

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)

	bd, exists = details["branch2"]
	c.Assert(exists, internal_testutil.IsTrue)

	nvWrittenSet, set = bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})

	code, set = bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithBranches2(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "branch2")
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, exists := details["branch2"]
	c.Assert(exists, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)

	nvWrittenSet, set := bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithAuthorize(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmNull, "", nil)
	c.Check(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, ok := details["<authorize:key:0x000b64dc4ba32a23deb5f2dfa58c03da0c3900ecd6f1409976e863009f42ab876ea1,ref:0x666f6f>"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithAuthorize2(c *C) {
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

	pub, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	_, authPolicy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy1.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	_, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmNull, "", NewPolicyAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 2)

	bd, ok := details["8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(bd.Secret, internal_testutil.LenEquals, 0)

	bd, ok = details["27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("bar")},
	})
}

func (s *policySuiteNoTPM) TestPolicyStringerWithAuthorized(c *C) {
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

	pub, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, authPolicy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy1.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	digest2, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, tpm2.HashAlgorithmSHA256, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	stringer := policy.Stringer(tpm2.HashAlgorithmNull, NewPolicyAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(stringer.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 AuthorizedPolicies {
   AuthorizedPolicy %[2]x {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
   }
   AuthorizedPolicy %[3]x {
    # digest TPM_ALG_SHA256:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x626172)
   }
 }
 PolicyAuthorize(policyRef:0x666f6f, keySign:%#[4]x)
}`, digest, digest1, digest2, pub.Name()))
}

func (s *policySuite) TestPolicyBranchesNVAutoSelected(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	node := builder.RootBranch().AddBranchNode()
	b1 := node.AddBranch("")
	b1.PolicyCommandCode(tpm2.CommandNVRead)
	b2 := node.AddBranch("")
	b2.PolicyCommandCode(tpm2.CommandPolicyNV)
	digest, nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	node = builder.RootBranch().AddBranchNode()
	b1 = node.AddBranch("")
	b1.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq)
	b2 = node.AddBranch("")
	b2.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpEq)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, nil), NewTPMHelper(s.TPM, nil), nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "{1}")

	digest, err = s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesNVAutoSelectedFail(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	node := builder.RootBranch().AddBranchNode()
	b1 := node.AddBranch("")
	b1.PolicyCommandCode(tpm2.CommandNVRead)
	b2 := node.AddBranch("")
	b2.PolicyCommandCode(tpm2.CommandPolicyNV)
	digest, nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	node = builder.RootBranch().AddBranchNode()
	b1 = node.AddBranch("")
	b1.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq)
	b2 = node.AddBranch("")
	b2.PolicyNV(nvPub, []byte{0}, 10, tpm2.OpEq)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), NewTPMPolicyResources(s.TPM, resources, nil), NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type policySuitePCR struct {
	testutil.TPMTest
}

func (s *policySuitePCR) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV | testutil.TPMFeaturePCR
}

var _ = Suite(&policySuitePCR{})

func (s *policySuitePCR) TestPolicyBranchesAutoSelected(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}})

	b2 := node.AddBranch("")
	b2.PolicyPCR(pcrValues)

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "{1}")
	_, set := result.CommandCode()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.CpHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NameHash()
	c.Check(set, internal_testutil.IsFalse)
	_, set = result.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuitePCR) TestPolicyBranchesAutoSelectFail(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}})

	b2 := node.AddBranch("")
	b2.PolicyPCR(pcrValues)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = policy.Execute(NewTPMPolicySession(s.TPM, session), nil, NewTPMHelper(s.TPM, nil), nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}
