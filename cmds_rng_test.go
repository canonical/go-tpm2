// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto/rand"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
)

type rngSuite struct {
	testutil.TPMTest
}

func (s *rngSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureNV
}

var _ = Suite(&rngSuite{})

func (s *rngSuite) testGetRandom(c *C, bytesRequested uint16) {
	data, err := s.TPM.GetRandom(bytesRequested)
	c.Check(err, IsNil)
	c.Check(data, internal_testutil.LenEquals, int(bytesRequested))

	_, _, rpBytes, _ := s.LastCommand(c).UnmarshalResponse(c)

	var expected Digest
	_, err = mu.UnmarshalFromBytes(rpBytes, &expected)
	c.Check(err, IsNil)

	c.Check(data, DeepEquals, expected)
}

func (s *rngSuite) TestGetRandom32(c *C) {
	s.testGetRandom(c, 32)
}

func (s *rngSuite) TestGetRandom20(c *C) {
	s.testGetRandom(c, 32)
}

func (s *rngSuite) TestStirRandom(c *C) {
	inData := make([]byte, 32)
	rand.Read(inData)

	c.Check(s.TPM.StirRandom(inData), IsNil)

	_, _, cpBytes := s.LastCommand(c).UnmarshalCommand(c)

	var expected []byte
	_, err := mu.UnmarshalFromBytes(cpBytes, &expected)
	c.Check(err, IsNil)

	c.Check(inData, DeepEquals, expected)
}
