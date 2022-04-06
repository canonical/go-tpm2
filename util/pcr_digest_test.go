// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	. "github.com/canonical/go-tpm2/util"
)

type pcrDigestSuite struct{}

var _ = Suite(&pcrDigestSuite{})

func (s *pcrDigestSuite) TestComputePCRDigestFromSinglePCR(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "cd446a8537e59056c999aeb7ecd47f6b4f82f86309d08789b169d43e9ce53935")))
}

func (s *pcrDigestSuite) TestComputePCRDigestFromMultiplePCRs(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {
		4: internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "6892d59ab3ec801e5f154a7d2767ff78f330aa1b015c16eed9c739d5920fe5f8")))
}

func (s *pcrDigestSuite) TestComputePCRDigestFromMultiplePCRsCheckSelectOrder(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 4}}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {
		4: internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "6892d59ab3ec801e5f154a7d2767ff78f330aa1b015c16eed9c739d5920fe5f8")))
}

func (s *pcrDigestSuite) TestComputePCRDigestFromMultiplePCRBanks(c *C) {
	pcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}
	pcrValues := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA1: {
			4: internal_testutil.DecodeHexString(c, "e242ed3bffccdf271b7fbaf34ed72d089537b42f")},
		tpm2.HashAlgorithmSHA256: {
			7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "803fa62e5e945f59af7d40a0e802201a5b0354472b4d7279289d8a6d32fabb6c")))
}

func (s *pcrDigestSuite) TestComputePCRDigestFromMultiplePCRBanksCheckBankOrder(c *C) {
	pcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}},
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}}}
	pcrValues := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA1: {
			4: internal_testutil.DecodeHexString(c, "e242ed3bffccdf271b7fbaf34ed72d089537b42f")},
		tpm2.HashAlgorithmSHA256: {
			7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "e77c036d95b0d378b1840381be684acf12d148366529f7226979dfd6ebe15ff9")))
}

func (s *pcrDigestSuite) TestComputePCRDigestUnusedValue(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {
		4: internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "cd446a8537e59056c999aeb7ecd47f6b4f82f86309d08789b169d43e9ce53935")))
}

func (s *pcrDigestSuite) TestComputePCRDigestSHA1(c *C) {
	pcrs := tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	digest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA1, pcrs, pcrValues)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "70b0873f47f961bbb891ccee9f8a57aacd167040")))
}

func (s *pcrDigestSuite) TestComputePCRDigestFromAllValuesFromSinglePCRValue(c *C) {
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	pcrs, digest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})

	expectedDigest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)

	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *pcrDigestSuite) TestComputePCRDigestFromAllValuesFromMultiplePCRValues(c *C) {
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {
		4: internal_testutil.DecodeHexString(c, "7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730"),
		7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	pcrs, digest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})

	expectedDigest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)

	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *pcrDigestSuite) TestComputePCRDigestFromAllValuesFromMultiplePCRBanks(c *C) {
	pcrValues := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA1: {
			4: internal_testutil.DecodeHexString(c, "e242ed3bffccdf271b7fbaf34ed72d089537b42f")},
		tpm2.HashAlgorithmSHA256: {
			7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	expectedPcrs := tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}}

	pcrs, digest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, expectedPcrs)

	expectedDigest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA256, pcrs, pcrValues)
	c.Check(err, IsNil)

	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *pcrDigestSuite) TestComputePCRDigestFromAllValuesSHA1(c *C) {
	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {7: internal_testutil.DecodeHexString(c, "b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")}}

	pcrs, digest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA1, pcrValues)
	c.Check(err, IsNil)
	c.Check(pcrs, DeepEquals, tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})

	expectedDigest, err := ComputePCRDigest(tpm2.HashAlgorithmSHA1, pcrs, pcrValues)
	c.Check(err, IsNil)

	c.Check(digest, DeepEquals, expectedDigest)
}
