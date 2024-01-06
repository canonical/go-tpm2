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
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
)

type cpHashSuite struct{}

var _ = Suite(&cpHashSuite{})

func (s *cpHashSuite) TestCommandParameters(c *C) {
	cpHashA := CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "0d5c70236d9181ea6b26fb203d8a45bbb3d982926d6cf4ba60ce0fe5d5717ac3")))
}

func (s *cpHashSuite) TestCommandParametersDifferentParams(c *C) {
	cpHashA := CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4, 5}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "15fc1d7283e0f5f864651602c55f1d1dbebf7e573850bfae5235e94df0ac1fa1")))
}

func (s *cpHashSuite) TestCommandParametersDifferentHandles(c *C) {
	cpHashA := CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "4facb677c43722471af5c535353911e4882d26aa58f4859562b6861476f4aca3")))
}

func (s *cpHashSuite) TestCommandParametersSHA1(c *C) {
	cpHashA := CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "d98ba8350f71c34132f62f50a6b9f21c4fa54f75")))
}

func (s *cpHashSuite) TestCommandParameterDigestSHA256(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	cpHashA := CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h.Sum(nil)))
}

func (s *cpHashSuite) TestCommandParameterDigestSHA1(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "params")

	cpHashA := CommandParameterDigest(tpm2.HashAlgorithmSHA1, h.Sum(nil))
	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h.Sum(nil)))
}

func (s *cpHashSuite) TestCommandParameterDigestError(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	cpHashA := CommandParameterDigest(tpm2.HashAlgorithmSHA256, h.Sum(nil))
	_, err := cpHashA.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, ErrorMatches, "no digest for algorithm")
}

func (s *cpHashSuite) TestCommandParameterDigests(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "params")
	h256 := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "params")
	h1 := h.Sum(nil)

	cpHashA := CommandParameterDigests(tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, h256), tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, h1))

	digest, err := cpHashA.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h256))
	digest, err = cpHashA.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(h1))
}

func (s *cpHashSuite) TestCommandParameterDigestsError(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "params")

	cpHashA := CommandParameterDigests(tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, h.Sum(nil)))
	_, err := cpHashA.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, ErrorMatches, "no digest for algorithm")
}

func (s *cpHashSuite) TestComputeCpHash(c *C) {
	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "0d5c70236d9181ea6b26fb203d8a45bbb3d982926d6cf4ba60ce0fe5d5717ac3")))
}

func (s *cpHashSuite) TestComputeCpHashDifferentParams(c *C) {
	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4, 5}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "15fc1d7283e0f5f864651602c55f1d1dbebf7e573850bfae5235e94df0ac1fa1")))
}

func (s *cpHashSuite) TestComputeCpHashDifferentHandle(c *C) {
	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "4facb677c43722471af5c535353911e4882d26aa58f4859562b6861476f4aca3")))
}

func (s *cpHashSuite) TestComputeCpHashSHA1(c *C) {
	cpHashA, err := ComputeCpHash(tpm2.HashAlgorithmSHA1, tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()))
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "d98ba8350f71c34132f62f50a6b9f21c4fa54f75")))
}
