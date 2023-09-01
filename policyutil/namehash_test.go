// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	_ "crypto/sha1"
	_ "crypto/sha256"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
)

type nameHashSuite struct{}

var _ = Suite(&nameHashSuite{})

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
