// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
	. "github.com/canonical/go-tpm2/util"
)

type keysSuite struct {
	testutil.TPMTest
}

var _ = Suite(&keysSuite{})

func (s *keysSuite) TestNewExternalRSAPublicKeyWithDefaults(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	pub := NewExternalRSAPublicKeyWithDefaults(0, &key.PublicKey)
	c.Check(pub, NotNil)

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewExternalECCPublicKeyWithDefaults(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pub := NewExternalECCPublicKeyWithDefaults(0, &key.PublicKey)
	c.Check(pub, NotNil)

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewSealedObject(c *C) {
	authValue := []byte("1234")
	data := []byte("secret data")

	pub, sensitive := NewSealedObject(tpm2.HashAlgorithmSHA256, authValue, data)
	c.Check(pub, NotNil)
	c.Check(sensitive, NotNil)

	pub.Attrs |= tpm2.AttrNoDA

	object, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	object.SetAuthValue(authValue)

	recoveredData, err := s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
	c.Check(recoveredData, DeepEquals, tpm2.SensitiveData(data))
}
