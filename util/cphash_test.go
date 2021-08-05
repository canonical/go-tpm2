// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	"crypto"
	"encoding/binary"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	. "github.com/canonical/go-tpm2/util"
)

type cpHashSuite struct{}

var _ = Suite(&cpHashSuite{})

func (s *cpHashSuite) TestComputeCpHashUnseal(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "object")
	object := mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))

	digest, err := ComputeCpHash(crypto.SHA256, tpm2.CommandUnseal, []tpm2.Name{object})
	c.Check(err, IsNil)

	expectedDigest := tpm2.ComputeCpHash(crypto.SHA256, tpm2.CommandUnseal, []tpm2.Name{object}, nil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *cpHashSuite) TestComputeCpHashHierarchyChangeAuth(c *C) {
	hierarchy := make(tpm2.Name, 4)
	binary.BigEndian.PutUint32(hierarchy, uint32(tpm2.HandleOwner))

	newAuth := tpm2.Auth("1234")

	digest, err := ComputeCpHash(crypto.SHA256, tpm2.CommandHierarchyChangeAuth, []tpm2.Name{hierarchy}, newAuth)
	c.Check(err, IsNil)

	expectedDigest := tpm2.ComputeCpHash(crypto.SHA256, tpm2.CommandHierarchyChangeAuth, []tpm2.Name{hierarchy}, mu.MustMarshalToBytes(newAuth))
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *cpHashSuite) TestComputeCpHashSHA1(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "object")
	object := mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))

	digest, err := ComputeCpHash(crypto.SHA1, tpm2.CommandUnseal, []tpm2.Name{object})
	c.Check(err, IsNil)

	expectedDigest := tpm2.ComputeCpHash(crypto.SHA1, tpm2.CommandUnseal, []tpm2.Name{object}, nil)
	c.Check(digest, DeepEquals, expectedDigest)
}
