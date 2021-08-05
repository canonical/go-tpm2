// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/testutil"
	. "github.com/canonical/go-tpm2/util"
)

type qnSuite struct {
	testutil.TPMTest
}

func (s *qnSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy
}

var _ = Suite(&qnSuite{})

func (s *qnSuite) TestComputeQualifiedName(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	_, _, primaryQn, err := s.TPM.ReadPublic(primary)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, templates.NewRSAKeyWithDefaults(0), nil, nil, nil)
	c.Assert(err, IsNil)

	object, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	_, _, expectedQn, err := s.TPM.ReadPublic(object)
	c.Assert(err, IsNil)

	c.Check(ComputeQualifiedName(object.Name(), primaryQn), DeepEquals, expectedQn)
}

func (s *qnSuite) TestComputeQualifiedNameFull(c *C) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	priv, pub, _, _, _, err := s.TPM.Create(primary, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	object1, err := s.TPM.Load(primary, priv, pub, nil)
	c.Assert(err, IsNil)

	priv, pub, _, _, _, err = s.TPM.Create(object1, nil, templates.NewRSAKeyWithDefaults(0), nil, nil, nil)
	c.Assert(err, IsNil)

	object2, err := s.TPM.Load(object1, priv, pub, nil)
	c.Assert(err, IsNil)

	_, _, expectedQn, err := s.TPM.ReadPublic(object2)
	c.Assert(err, IsNil)

	c.Check(ComputeQualifiedNameFull(object2.Name(), tpm2.HandleOwner, primary.Name(), object1.Name()), DeepEquals, expectedQn)
}
