// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
)

type typesAttributesSuite struct{}

var _ = Suite(&typesAttributesSuite{})

func (s *typesAttributesSuite) TestLocalityIsValidTrue1(c *C) {
	locality := LocalityZero
	c.Check(locality.IsValid(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsValidTrue2(c *C) {
	locality := LocalityZero | LocalityThree
	c.Check(locality.IsValid(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsValidTrue3(c *C) {
	locality := Locality(41)
	c.Check(locality.IsValid(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsValidFalse(c *C) {
	var locality Locality
	c.Check(locality.IsValid(), internal_testutil.IsFalse)
}

func (s *typesAttributesSuite) TestLocalityIsExtendedTrue1(c *C) {
	locality := Locality(41)
	c.Check(locality.IsExtended(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsExtendedTrue2(c *C) {
	locality := Locality(249)
	c.Check(locality.IsExtended(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsExtendedFalse1(c *C) {
	locality := LocalityZero
	c.Check(locality.IsExtended(), internal_testutil.IsFalse)
}

func (s *typesAttributesSuite) TestLocalityIsExtendedFalse2(c *C) {
	locality := LocalityZero | LocalityThree
	c.Check(locality.IsExtended(), internal_testutil.IsFalse)
}

func (s *typesAttributesSuite) TestLocalityIsMultipleFalse1(c *C) {
	locality := Locality(41)
	c.Check(locality.IsMultiple(), internal_testutil.IsFalse)
}

func (s *typesAttributesSuite) TestLocalityIsMultipleFalse2(c *C) {
	locality := LocalityZero
	c.Check(locality.IsMultiple(), internal_testutil.IsFalse)
}

func (s *typesAttributesSuite) TestLocalityIsMultipleTrue1(c *C) {
	locality := LocalityZero | LocalityThree
	c.Check(locality.IsMultiple(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityIsMultipleTrue2(c *C) {
	locality := LocalityZero | LocalityThree | LocalityFour
	c.Check(locality.IsMultiple(), internal_testutil.IsTrue)
}

func (s *typesAttributesSuite) TestLocalityValuesExtended(c *C) {
	locality := Locality(41)
	c.Check(locality.Values(), DeepEquals, []uint8{41})
}

func (s *typesAttributesSuite) TestLocalityValuesSingle(c *C) {
	locality := LocalityZero
	c.Check(locality.Values(), DeepEquals, []uint8{0})
}

func (s *typesAttributesSuite) TestLocalityValuesMultiple(c *C) {
	locality := LocalityZero | LocalityThree
	c.Check(locality.Values(), DeepEquals, []uint8{0, 3})
}

func (s *typesAttributesSuite) TestLocalityValueExtended(c *C) {
	locality := Locality(41)
	c.Check(locality.Value(), internal_testutil.IntEqual, 41)
}

func (s *typesAttributesSuite) TestLocalityValueSingle1(c *C) {
	locality := LocalityZero
	c.Check(locality.Value(), internal_testutil.IntEqual, 0)
}

func (s *typesAttributesSuite) TestLocalityValueSingle3(c *C) {
	locality := LocalityThree
	c.Check(locality.Value(), internal_testutil.IntEqual, 3)
}

func (s *typesAttributesSuite) TestLocalityValueMultiplePanic(c *C) {
	locality := LocalityZero | LocalityThree
	c.Check(func() { locality.Value() }, PanicMatches, `unset or multiple localities are represented`)
}

func (s *typesAttributesSuite) TestLocalityValueZeroPanic(c *C) {
	var locality Locality
	c.Check(func() { locality.Value() }, PanicMatches, `unset or multiple localities are represented`)
}
