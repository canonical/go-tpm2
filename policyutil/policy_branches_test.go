// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"

	. "gopkg.in/check.v1"
)

type policyBranchesSuite struct{}

var _ = Suite(&policyBranchesSuite{})

func (s *policyBranchesSuite) TestPolicyBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{""})
}

func (s *policyBranchesSuite) TestPolicyBranchesWithBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1", "branch2"})
}

func (s *policyBranchesSuite) TestPolicyBranchesWithMultipleBranchNodes(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch3", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandNVChangeAuth)
		})

		n.AddBranch("", func(b *PolicyBuilderBranch) {
			b.PolicyCommandCode(tpm2.CommandObjectChangeAuth)
		})
	})

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, nil)
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1/branch3", "branch1/{1}", "branch2/branch3", "branch2/{1}"})
}

func (s *policyBranchesSuite) TestPolicyBranchesWithAuthorize(c *C) {
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

func (s *policyBranchesSuite) TestPolicyBranchesWithAuthorize2(c *C) {
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
	c.Check(authPolicy1.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	_, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	branches, err := policy.Branches(tpm2.HashAlgorithmNull, NewPolicyAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{
		"8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e",
		"27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b",
	})
}
