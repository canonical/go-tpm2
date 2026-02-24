// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type policyComputeSuite struct{}

var _ = Suite(&policyComputeSuite{})

func (s *policyComputeSuite) TestPolicyAddDigestCpHash(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyCpHash(CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())))

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyCpHash assertion' task in root branch: cannot compute digest for policies with TPM2_PolicyCpHash assertion`)
}

func (s *policyComputeSuite) TestPolicyAddDigestNameHash(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyNameHash(CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner)))

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNameHash assertion' task in root branch: cannot compute digest for policies with TPM2_PolicyNameHash assertion`)
}

func (s *policyComputeSuite) TestPolicyAddDigestPolicyPCRDigest(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicyPCRDigest(make([]byte, 20), tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyPCR assertion' task in root branch: cannot compute digest for policies with TPM2_PolicyPCR assertions which contain pre-computed digests`)
}

func (s *policyComputeSuite) TestPolicyBranchesMultipleDigests(c *C) {
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

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			digest, err = b.PolicyAuthValue()
			c.Check(err, IsNil)
			c.Check(digest, DeepEquals, pHashListSHA1[0])
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			digest, err = b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
			c.Check(err, IsNil)
			c.Check(digest, DeepEquals, pHashListSHA1[1])
		})
	})

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
		NewMockPolicyBranchNodeElement(
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
