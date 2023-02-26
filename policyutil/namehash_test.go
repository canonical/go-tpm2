// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
)

type nameHashSuite struct{}

var _ = Suite(&nameHashSuite{})

func (s *nameHashSuite) TestCommandHandles1(c *C) {
	nameHash := CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner))
	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "16a3d3b482bb480394dfac704038a3708db2a77ccaa80ca419e91122406599ec")))
	c.Logf("%x", digest)
}

func (s *nameHashSuite) TestCommandHandles2(c *C) {
	nameHash := CommandHandles(objectutil.NewRSAAttestationKeyTemplate(), tpm2.MakeHandleName(tpm2.HandleEndorsement))
	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "513623acd2967b65470ef1d0f31306a60099279e099b6428270af4e431be9cae")))
	c.Logf("%x", digest)
}

func (s *nameHashSuite) TestCommandHandlesSHA1(c *C) {
	nameHash := CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner))
	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "97d538cbfae3f530b934596ea99c19a9b5c06d03")))
	c.Logf("%x", digest)
}

func (s *nameHashSuite) TestCommandHandleDigestSHA256(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "handles")

	nameHash := CommandHandleDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil))
	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h.Sum(nil)))
}

func (s *nameHashSuite) TestCommandHandleDigestSHA1(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "handles")

	nameHash := CommandHandleDigest(tpm2.HashAlgorithmSHA1, h.Sum(nil))
	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h.Sum(nil)))
}

func (s *nameHashSuite) TestCommandHandleDigestError(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "handles")

	nameHash := CommandHandleDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil))
	_, err := nameHash.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, ErrorMatches, "no digest for algorithm")
}

func (s *nameHashSuite) TestCommandHandleDigests(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "handles")
	h256 := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "handles")
	h1 := h.Sum(nil)

	nameHash := CommandHandleDigests(tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, h256), tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, h1))

	digest, err := nameHash.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h256))
	digest, err = nameHash.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h1))
}

func (s *nameHashSuite) TestCommandHandleDigestsError(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "handles")

	nameHash := CommandHandleDigests(tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, h.Sum(nil)))

	_, err := nameHash.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, ErrorMatches, "no digest for algorithm")
}

func (s *nameHashSuite) TestComputeNameHash1(c *C) {
	nameHash, err := ComputeNameHash(tpm2.HashAlgorithmSHA256, tpm2.MakeHandleName(tpm2.HandleOwner))
	c.Check(err, IsNil)
	c.Check(nameHash, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "16a3d3b482bb480394dfac704038a3708db2a77ccaa80ca419e91122406599ec")))
}

func (s *nameHashSuite) TestComputeNameHash2(c *C) {
	nameHash, err := ComputeNameHash(tpm2.HashAlgorithmSHA256, objectutil.NewRSAAttestationKeyTemplate(), tpm2.MakeHandleName(tpm2.HandleEndorsement))
	c.Check(err, IsNil)
	c.Check(nameHash, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "513623acd2967b65470ef1d0f31306a60099279e099b6428270af4e431be9cae")))
}

func (s *nameHashSuite) TestComputeNameHashSHA1(c *C) {
	nameHash, err := ComputeNameHash(tpm2.HashAlgorithmSHA1, tpm2.MakeHandleName(tpm2.HandleOwner))
	c.Check(err, IsNil)
	c.Check(nameHash, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "97d538cbfae3f530b934596ea99c19a9b5c06d03")))
}
