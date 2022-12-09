// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
)

type typesSuite struct{}

var _ = Suite(&typesSuite{})

func (s *typesSuite) TestMarshalPCRValues(c *C) {
	values := make(PCRValues)
	c.Assert(values.SetValue(HashAlgorithmSHA256, 7, internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")), IsNil)
	c.Assert(values.SetValue(HashAlgorithmSHA1, 4, internal_testutil.DecodeHexString(c, "7448d8798a4380162d4b56f9b452e2f6f9e24e7a")), IsNil)
	c.Assert(values.SetValue(HashAlgorithmSHA256, 4, internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")), IsNil)

	b, err := mu.MarshalToBytes(values)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, internal_testutil.DecodeHexString(c, "00000002000403100000000b039000000000000300147448d8798a4380162d4b56f9b452e2f6f9e24e7a002053c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c300204355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
}

func (s *typesSuite) TestUnmarshalPCRValues(c *C) {
	expected := make(PCRValues)
	c.Assert(expected.SetValue(HashAlgorithmSHA256, 7, internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")), IsNil)
	c.Assert(expected.SetValue(HashAlgorithmSHA1, 4, internal_testutil.DecodeHexString(c, "7448d8798a4380162d4b56f9b452e2f6f9e24e7a")), IsNil)
	c.Assert(expected.SetValue(HashAlgorithmSHA256, 4, internal_testutil.DecodeHexString(c, "53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")), IsNil)

	b := internal_testutil.DecodeHexString(c, "00000002000403100000000b039000000000000300147448d8798a4380162d4b56f9b452e2f6f9e24e7a002053c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c300204355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	var values PCRValues
	_, err := mu.UnmarshalFromBytes(b, &values)
	c.Check(err, IsNil)
	c.Check(values, DeepEquals, expected)
}

func (s *typesSuite) TestMarshalPCRValuesInvalidPCR(c *C) {
	values := PCRValues{HashAlgorithmSHA256: {4000: internal_testutil.DecodeHexString(c, "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")}}

	_, err := mu.MarshalToBytes(values)
	c.Check(err, ErrorMatches, "cannot marshal argument 0 whilst processing element of type tpm2.PCRValues: invalid selection list: cannot marshal argument 0 whilst processing element of type tpm2.PCRSelection: invalid PCR index \\(> 2040\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... tpm2.PCRSelectionList index 0\n"+
		"=== END STACK ===\n")
}

func (s *typesSuite) TestUnmarshalPCRValuesInvalidPayload(c *C) {
	b := internal_testutil.DecodeHexString(c, "00000002000403100000000b079000000000000300147448d8798a4380162d4b56f9b452e2f6f9e24e7a002053c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c300204355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	var values PCRValues
	_, err := mu.UnmarshalFromBytes(b, &values)
	c.Check(err, ErrorMatches, `cannot unmarshal argument 0 whilst processing element of type tpm2.Digest: unexpected EOF

=== BEGIN STACK ===
... tpm2.DigestList index 0
... tpm2.PCRValues location .*\/types\.go:[[:digit:]]*, argument 1
=== END STACK ===
`)
}

func (s *typesSuite) TestUnmarshalPCRValuesInvalidDigestAlgorithm(c *C) {
	b := internal_testutil.DecodeHexString(c, "00000002000403100000001b039000000000000300147448d8798a4380162d4b56f9b452e2f6f9e24e7a002053c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c300204355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	var values PCRValues
	_, err := mu.UnmarshalFromBytes(b, &values)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type tpm2.PCRValues: invalid digest algorithm")
}

func (s *typesSuite) TestUnmarshalPCRValuesInsufficientDigests(c *C) {
	b := internal_testutil.DecodeHexString(c, "00000002000403100000000b039000000000000200147448d8798a4380162d4b56f9b452e2f6f9e24e7a002053c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3")

	var values PCRValues
	_, err := mu.UnmarshalFromBytes(b, &values)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type tpm2.PCRValues: insufficient digests")
}

func (s *typesSuite) TestUnmarshalPCRValuesInvalidDigestSize(c *C) {
	b := internal_testutil.DecodeHexString(c, "00000002000403100000000b039000000000000300147448d8798a4380162d4b56f9b452e2f6f9e24e7a0014cab3fe06fad053beb8ebfd8977b010655bfdd3c300204355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865")

	var values PCRValues
	_, err := mu.UnmarshalFromBytes(b, &values)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type tpm2.PCRValues: invalid digest size")
}
