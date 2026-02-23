// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/policyutil"

	. "gopkg.in/check.v1"
)

type policyValidateSuite struct{}

var _ = Suite(&policyValidateSuite{})

func (s *policyValidateSuite) TestPolicyValidate(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	expectedDigest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policyValidateSuite) TestPolicyValidateWithBranches(c *C) {
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

func (s *policyValidateSuite) TestPolicyValidateWithMultipleBranchNodes(c *C) {
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

func (s *policyValidateSuite) TestPolicyValidateMissingBranches(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Validate(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)
}
