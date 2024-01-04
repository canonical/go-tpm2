// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	. "github.com/canonical/go-tpm2/objectutil"
)

type duplicationSuite struct{}

var _ = Suite(&duplicationSuite{})

type testCreateUnwrapDuplicationData struct {
	parentPriv    crypto.PrivateKey
	parentPublic  *tpm2.Public
	encryptionKey tpm2.Data
	symmetricAlg  *tpm2.SymDefObject
}

func (s *duplicationSuite) testCreateUnwrapDuplication(c *C, data *testCreateUnwrapDuplicationData) {
	public, sensitiveIn, err := NewSealedObject(rand.Reader, []byte("super secret data"), []byte("foo"))
	c.Assert(err, IsNil)

	encryptionKey, duplicate, symSeed, err := CreateImportable(rand.Reader, sensitiveIn, public, data.parentPublic, data.encryptionKey, data.symmetricAlg)
	c.Check(err, IsNil)
	if data.symmetricAlg != nil && data.symmetricAlg.Algorithm != tpm2.SymObjectAlgorithmNull && len(data.encryptionKey) == 0 {
		c.Check(encryptionKey, internal_testutil.LenEquals, int(data.symmetricAlg.KeyBits.Sym()/8))
	} else {
		c.Check(encryptionKey, IsNil)
		encryptionKey = data.encryptionKey
	}

	parentNameAlg := tpm2.HashAlgorithmNull
	var parentSymmetricAlg *tpm2.SymDefObject
	if data.parentPublic != nil {
		parentNameAlg = data.parentPublic.NameAlg
		parentSymmetricAlg = &data.parentPublic.Params.AsymDetail().Symmetric
	}

	sensitive, err := UnwrapDuplicated(duplicate, public, data.parentPriv, parentNameAlg, parentSymmetricAlg, symSeed, encryptionKey, data.symmetricAlg)
	c.Check(err, IsNil)
	c.Assert(sensitive, NotNil)

	c.Check(sensitive.Type, Equals, sensitiveIn.Type)
	c.Check(sensitive.AuthValue, internal_testutil.LenEquals, crypto.SHA256.Size())
	c.Check(sensitive.AuthValue[:len(sensitiveIn.AuthValue)], DeepEquals, sensitiveIn.AuthValue)
	c.Check(sensitive.AuthValue[len(sensitiveIn.AuthValue):], DeepEquals, make(tpm2.Auth, crypto.SHA256.Size()-len(sensitiveIn.AuthValue)))
	c.Check(sensitive.SeedValue, DeepEquals, sensitiveIn.SeedValue)
	c.Check(sensitive.Sensitive, DeepEquals, sensitiveIn.Sensitive)
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationNoWrapper(c *C) {
	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithInnerWrapper(c *C) {
	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		symmetricAlg: &tpm2.SymDefObject{
			Algorithm: tpm2.SymObjectAlgorithmAES,
			KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
			Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
		},
	})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithInnerWrapperAndSuppliedKey(c *C) {
	symKey := make([]byte, 16)
	rand.Read(symKey)

	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		encryptionKey: symKey,
		symmetricAlg: &tpm2.SymDefObject{
			Algorithm: tpm2.SymObjectAlgorithmAES,
			KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
			Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
		},
	})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithOuterWrapperRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		parentPriv: privKey,
		parentPublic: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: tpm2.MakePublicParamsUnion(
				tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
						Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
					},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: uint32(privKey.E),
				},
			),
			Unique: tpm2.MakePublicIDUnion(tpm2.PublicKeyRSA(privKey.N.Bytes())),
		},
	})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithOuterWrapperECC1(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		parentPriv: privKey,
		parentPublic: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: tpm2.MakePublicParamsUnion(
				tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
						Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
					},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				},
			),
			Unique: tpm2.MakePublicIDUnion(
				tpm2.ECCPoint{
					X: ZeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: ZeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			),
		},
	})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithOuterWrapperECCAndSHA1(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		parentPriv: privKey,
		parentPublic: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: tpm2.MakePublicParamsUnion(
				tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
						Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
					},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				},
			),
			Unique: tpm2.MakePublicIDUnion(
				tpm2.ECCPoint{
					X: ZeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: ZeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			),
		},
	})
}

func (s *duplicationSuite) TestCreateUnwrapDuplicationWithBothWrappers(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplication(c, &testCreateUnwrapDuplicationData{
		symmetricAlg: &tpm2.SymDefObject{
			Algorithm: tpm2.SymObjectAlgorithmAES,
			KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
			Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
		},
		parentPriv: privKey,
		parentPublic: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: tpm2.MakePublicParamsUnion(
				tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
						Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
					},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
				},
			),
			Unique: tpm2.MakePublicIDUnion(
				tpm2.ECCPoint{
					X: ZeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: ZeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			),
		},
	})
}
