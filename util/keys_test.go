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
	c.Check(pub.Params.RSADetail.Exponent, Equals, uint32(key.E))
	c.Check(pub.Unique.RSA, DeepEquals, tpm2.PublicKeyRSA(key.N.Bytes()))

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewExternalECCPublicKeyWithDefaults(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pub := NewExternalECCPublicKeyWithDefaults(0, &key.PublicKey)
	c.Check(pub, NotNil)
	c.Check(pub.Params.ECCDetail.CurveID, Equals, tpm2.ECCCurveNIST_P256)
	c.Check(pub.Unique.ECC.X, DeepEquals, tpm2.ECCParameter(ZeroExtendBytes(key.X, 32)))
	c.Check(pub.Unique.ECC.Y, DeepEquals, tpm2.ECCParameter(ZeroExtendBytes(key.Y, 32)))

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewExternalSealedObject(c *C) {
	authValue := []byte("1234")
	data := []byte("secret data")

	pub, sensitive := NewExternalSealedObject(tpm2.HashAlgorithmSHA256, authValue, data)
	c.Check(pub, NotNil)
	c.Check(sensitive, NotNil)
	c.Check(sensitive.AuthValue, DeepEquals, tpm2.Auth(append(authValue, make([]byte, 28)...)))
	c.Check(sensitive.Sensitive.Bits, DeepEquals, tpm2.SensitiveData(data))

	pub.Attrs |= tpm2.AttrNoDA

	object, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	object.SetAuthValue(authValue)

	recoveredData, err := s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
	c.Check(recoveredData, DeepEquals, tpm2.SensitiveData(data))
}

func (s *keysSuite) TestNewExternalHMACKeyWithDefaults(c *C) {
	authValue := []byte("1234")
	key := make([]byte, 32)
	rand.Read(key)

	pub, sensitive := NewExternalHMACKeyWithDefaults(authValue, key)
	c.Check(pub, NotNil)
	c.Check(sensitive, NotNil)
	c.Check(sensitive.AuthValue, DeepEquals, tpm2.Auth(append(authValue, make([]byte, 28)...)))
	c.Check(sensitive.Sensitive.Bits, DeepEquals, tpm2.SensitiveData(key))

	_, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
}
