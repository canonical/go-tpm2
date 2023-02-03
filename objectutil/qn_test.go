// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	. "github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
)

type qnSuiteNoTPM struct{}

type qnSuite struct {
	testutil.TPMTest
}

func (s *qnSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy
}

var _ = Suite(&qnSuiteNoTPM{})
var _ = Suite(&qnSuite{})

func (s *qnSuiteNoTPM) TestComputeQualifiedName(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "000b53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))

	expected := tpm2.Name(internal_testutil.DecodeHexString(c, "000b3e01dcd86b0426188bcd54271343a4baf067130f9ae6df0611d474e28b938ec0"))

	qn, err := ComputeQualifiedName(leaf, rootQn, primary)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expected)

	qn1, err := ComputeQualifiedName(primary, rootQn)
	c.Check(err, IsNil)
	qn, err = ComputeQualifiedName(leaf, qn1)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expected)
}

func (s *qnSuiteNoTPM) TestComputeQualifiedNameInvalidName(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "000453c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))

	_, err := ComputeQualifiedName(leaf, rootQn, primary)
	c.Check(err, ErrorMatches, "invalid name")
}

func (s *qnSuiteNoTPM) TestComputeQualifiedNameInvalidName2(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))

	_, err := ComputeQualifiedName(tpm2.Name(nil), rootQn, primary)
	c.Check(err, ErrorMatches, "invalid name")
}

func (s *qnSuiteNoTPM) TestComputeQualifiedNameInvalidName3(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	var primary tpm2.Name
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "000453c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))

	_, err := ComputeQualifiedName(leaf, rootQn, primary)
	c.Check(err, ErrorMatches, "cannot compute intermediate QN for ancestor at index 0: invalid name")
}
func (s *qnSuiteNoTPM) TestComputeQualifiedNameMismatchedAlgorithms(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "00047448d8798a4380162d4b56f9b452e2f6f9e24e7a"))

	_, err := ComputeQualifiedName(leaf, rootQn, primary)
	c.Check(err, ErrorMatches, "name algorithm mismatch")
}

func (s *qnSuiteNoTPM) TestComputeQualifiedNameInvalidRootQn(c *C) {
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "000453c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))

	_, err := ComputeQualifiedName(leaf, nil, primary)
	c.Check(err, ErrorMatches, "cannot compute intermediate QN for ancestor at index 0: invalid parent qualified name")
}

func (s *qnSuiteNoTPM) TestComputeQualifiedNameInHierarchy(c *C) {
	primary := tpm2.Name(internal_testutil.DecodeHexString(c, "000b4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865"))
	intermediate := tpm2.Name(internal_testutil.DecodeHexString(c, "000b53c234e5e8472b6ac51c1ae1cab3fe06fad053beb8ebfd8977b010655bfdd3c3"))
	leaf := tpm2.Name(internal_testutil.DecodeHexString(c, "000b1121cfccd5913f0a63fec40a6ffd44ea64f9dc135c66634ba001d10bcf4302a2"))

	expected := tpm2.Name(internal_testutil.DecodeHexString(c, "000b498fc06c91cca8c0a122d2d309f5b2e487c1d57da154d9109240506465c8b6c5"))

	qn, err := ComputeQualifiedNameInHierarchy(leaf, tpm2.HandleOwner, primary, intermediate)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expected)

	qn1, err := ComputeQualifiedNameInHierarchy(intermediate, tpm2.HandleOwner, primary)
	c.Check(err, IsNil)
	qn, err = ComputeQualifiedName(leaf, qn1)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expected)
}

func (s *qnSuite) TestComputeQualifiedName(c *C) {
	rootQn := mu.MustMarshalToBytes(tpm2.HandleOwner)
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, NewRSAKeyTemplate(UsageDecrypt|UsageSign), nil, nil, nil)
	c.Assert(err, IsNil)

	leaf, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	_, _, expectedQn, err := s.TPM.ReadPublic(leaf)
	c.Assert(err, IsNil)

	qn, err := ComputeQualifiedName(leaf, rootQn, primary)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expectedQn)
}

func (s *qnSuite) TestComputeQualifiedNameInHierarchy(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	intermediate, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err = s.TPM.Create(intermediate, nil, NewRSAKeyTemplate(UsageDecrypt|UsageSign), nil, nil, nil)
	c.Assert(err, IsNil)

	leaf, err := s.TPM.Load(intermediate, priv, pub, nil)
	c.Assert(err, IsNil)

	_, _, expectedQn, err := s.TPM.ReadPublic(leaf)
	c.Assert(err, IsNil)

	qn, err := ComputeQualifiedNameInHierarchy(leaf, tpm2.HandleOwner, primary, intermediate)
	c.Check(err, IsNil)
	c.Check(qn, DeepEquals, expectedQn)
}
