// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	. "github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
)

type keysSuite struct {
	testutil.TPMTest
}

var _ = Suite(&keysSuite{})

func (s *keysSuite) TestNewRSAPublicKey(c *C) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	pub, err := NewRSAPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeRSA)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(pub.Attrs, Equals, tpm2.AttrSign)
	c.Check(pub.Params.RSADetail(), testutil.TPMValueDeepEquals, &tpm2.RSAParams{
		Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
		Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
		KeyBits:   2048})

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewECCPublicKey(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pub, err := NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeECC)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(pub.Attrs, Equals, tpm2.AttrSign)
	c.Check(pub.Params.ECCDetail(), testutil.TPMValueDeepEquals, &tpm2.ECCParams{
		Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
		Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
		CurveID:   tpm2.ECCCurveNIST_P256,
		KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}})

	_, err = s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Check(err, IsNil)
}

func (s *keysSuite) TestNewSealedObject(c *C) {
	authValue := []byte("1234")
	data := []byte("secret data")
	seed := internal_testutil.DecodeHexString(c, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	pub, sensitive, err := NewSealedObject(bytes.NewReader(seed), data, authValue, WithoutDictionaryAttackProtection())
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(pub.Attrs, Equals, tpm2.AttrNoDA|tpm2.AttrUserWithAuth)
	c.Check(pub.Params.KeyedHashDetail(), testutil.TPMValueDeepEquals, &tpm2.KeyedHashParams{
		Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}})

	c.Check(sensitive.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(sensitive.AuthValue, DeepEquals, tpm2.Auth(append(authValue, make([]byte, 28)...)))
	c.Check(sensitive.SeedValue, DeepEquals, tpm2.Digest(seed))
	c.Check(sensitive.Sensitive.Bits(), DeepEquals, tpm2.SensitiveData(data))

	object, err := s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)

	recoveredData, err := s.TPM.Unseal(object, nil)
	c.Check(err, IsNil)
	c.Check(recoveredData, DeepEquals, tpm2.SensitiveData(data))
}

func (s *keysSuite) TestNewSymmetricKey(c *C) {
	authValue := []byte("1234")
	key := make([]byte, 32)
	rand.Read(key)
	seed := internal_testutil.DecodeHexString(c, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	pub, sensitive, err := NewSymmetricKey(bytes.NewReader(seed), UsageDecrypt, key, authValue)
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeSymCipher)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(pub.Attrs, Equals, tpm2.AttrUserWithAuth|tpm2.AttrDecrypt)
	c.Check(pub.Params.SymDetail(), testutil.TPMValueDeepEquals, &tpm2.SymCipherParams{
		Sym: tpm2.SymDefObject{
			Algorithm: tpm2.SymObjectAlgorithmAES,
			KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
			Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
		},
	})

	c.Check(sensitive.Type, Equals, tpm2.ObjectTypeSymCipher)
	c.Check(sensitive.AuthValue, DeepEquals, tpm2.Auth(append(authValue, make([]byte, 28)...)))
	c.Check(sensitive.SeedValue, DeepEquals, tpm2.Digest(seed))
	c.Check(sensitive.Sensitive.Sym(), DeepEquals, tpm2.SymKey(key))

	_, err = s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
}

func (s *keysSuite) TestNewHMACKey(c *C) {
	authValue := []byte("1234")
	key := make([]byte, 32)
	rand.Read(key)
	seed := internal_testutil.DecodeHexString(c, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")

	pub, sensitive, err := NewHMACKey(bytes.NewReader(seed), key, authValue)
	c.Assert(err, IsNil)

	c.Check(pub.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(pub.Attrs, Equals, tpm2.AttrUserWithAuth|tpm2.AttrSign)
	c.Check(pub.Params.KeyedHashDetail(), testutil.TPMValueDeepEquals, &tpm2.KeyedHashParams{
		Scheme: tpm2.KeyedHashScheme{
			Scheme:  tpm2.KeyedHashSchemeHMAC,
			Details: tpm2.MakeSchemeKeyedHashUnion(tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256}),
		},
	})

	c.Check(sensitive.Type, Equals, tpm2.ObjectTypeKeyedHash)
	c.Check(sensitive.AuthValue, DeepEquals, tpm2.Auth(append(authValue, make([]byte, 28)...)))
	c.Check(sensitive.SeedValue, DeepEquals, tpm2.Digest(seed))
	c.Check(sensitive.Sensitive.Bits(), DeepEquals, tpm2.SensitiveData(key))

	_, err = s.TPM.LoadExternal(sensitive, pub, tpm2.HandleNull)
	c.Assert(err, IsNil)
}
