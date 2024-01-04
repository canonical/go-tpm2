// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package objectutil_test

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/objectutil"
	"github.com/canonical/go-tpm2/testutil"
)

type templatesSuite struct{}

var _ = Suite(&templatesSuite{})

func (s *templatesSuite) TestWithNameAlgSHA256(c *C) {
	pub := new(tpm2.Public)
	WithNameAlg(tpm2.HashAlgorithmSHA256)(pub)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA256)
}

func (s *templatesSuite) TestWithNameAlgSHA512(c *C) {
	pub := new(tpm2.Public)
	WithNameAlg(tpm2.HashAlgorithmSHA512)(pub)
	c.Check(pub.NameAlg, Equals, tpm2.HashAlgorithmSHA512)
}

func (s *templatesSuite) TestWithUserAuthModeAllowAuthValue(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrSign}
	WithUserAuthMode(AllowAuthValue)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{Attrs: tpm2.AttrUserWithAuth | tpm2.AttrSign})
}

func (s *templatesSuite) TestWithUserAuthModeRequirePolicy(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrUserWithAuth | tpm2.AttrSign}
	WithUserAuthMode(RequirePolicy)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{Attrs: tpm2.AttrSign})
}

func (s *templatesSuite) TestWithAdminAuthModeAllowAuthValue(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrAdminWithPolicy | tpm2.AttrSign}
	WithAdminAuthMode(AllowAuthValue)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{Attrs: tpm2.AttrSign})
}

func (s *templatesSuite) TestWithAdminAuthModeRequirePolicy(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrSign}
	WithAdminAuthMode(RequirePolicy)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{Attrs: tpm2.AttrAdminWithPolicy | tpm2.AttrSign})
}

func (s *templatesSuite) TestWithProtectionGroupModeNonDuplicable(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrEncryptedDuplication | tpm2.AttrSign}
	WithProtectionGroupMode(NonDuplicable)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithProtectionGroupModeDuplicable1(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrDecrypt}
	WithProtectionGroupMode(Duplicable)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedParent|tpm2.AttrDecrypt)
}

func (s *templatesSuite) TestWithProtectionGroupModeDuplicable2(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrEncryptedDuplication | tpm2.AttrDecrypt}
	WithProtectionGroupMode(Duplicable)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrDecrypt)
}

func (s *templatesSuite) TestWithProtectionGroupModeDuplicableEncrypted1(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSign}
	WithProtectionGroupMode(DuplicableEncrypted)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedParent|tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithProtectionGroupModeDuplicableEncrypted2(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrSign}
	WithProtectionGroupMode(DuplicableEncrypted)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithProtectionGroupModeFromParentNonDuplicable(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrEncryptedDuplication | tpm2.AttrSign}
	WithProtectionGroupModeFromParent(&tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent})(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithProtectionGroupModeFromParentDuplicable(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrDecrypt}
	WithProtectionGroupModeFromParent(&tpm2.Public{})(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedParent|tpm2.AttrDecrypt)
}

func (s *templatesSuite) TestWithProtectionGroupModeFromParentDuplicableEncrypted(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSign}
	WithProtectionGroupModeFromParent(&tpm2.Public{Attrs: tpm2.AttrEncryptedDuplication})(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedParent|tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeFixedParent1(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSign}
	WithDuplicationMode(FixedParent)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedTPM|tpm2.AttrFixedParent|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeFixedParent2(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrDecrypt}
	WithDuplicationMode(FixedParent)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrFixedParent|tpm2.AttrDecrypt)
}

func (s *templatesSuite) TestWithDuplicationModeDuplicationRoot1(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSign}
	WithDuplicationMode(DuplicationRoot)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeDuplicationRoot2(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedParent | tpm2.AttrDecrypt}
	WithDuplicationMode(DuplicationRoot)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrDecrypt)
}

func (s *templatesSuite) TestWithDuplicationModeDuplicationRoot3(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedParent | tpm2.AttrEncryptedDuplication | tpm2.AttrSign}
	WithDuplicationMode(DuplicationRoot)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeDuplicationRootEncrypted1(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSign}
	WithDuplicationMode(DuplicationRootEncrypted)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeDuplicationRootEncrypted2(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedParent | tpm2.AttrEncryptedDuplication | tpm2.AttrSign}
	WithDuplicationMode(DuplicationRootEncrypted)(pub)
	c.Check(pub.Attrs, Equals, tpm2.AttrEncryptedDuplication|tpm2.AttrSign)
}

func (s *templatesSuite) TestWithDuplicationModeInvalidProtectionGroupMode(c *C) {
	pub := &tpm2.Public{Attrs: tpm2.AttrFixedParent | tpm2.AttrSign}
	c.Check(func() { WithDuplicationMode(DuplicationRootEncrypted)(pub) }, PanicMatches, "invalid mode for protection group")
}

func (s *templatesSuite) TestWithAuthPolicy(c *C) {
	pub := &tpm2.Public{NameAlg: tpm2.HashAlgorithmSHA256}
	WithAuthPolicy(make([]byte, 32))(pub)
	c.Check(pub.AuthPolicy, DeepEquals, make(tpm2.Digest, 32))
}

func (s *templatesSuite) TestWithSymmetricSchemeRSA(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 128, tpm2.SymModeCFB)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithSymmetricSchemeECC(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithSymmetricScheme(tpm2.SymObjectAlgorithmNull, 0, tpm2.SymModeNull)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmNull,
					KeyBits:   tpm2.MakeSymKeyBitsUnion(tpm2.EmptyValue),
					Mode:      tpm2.MakeSymModeUnion(tpm2.EmptyValue),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithSymmetricSchemeSymCipher(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(tpm2.SymCipherParams{}),
	}
	WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 256, tpm2.SymModeCFB)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithSymmetricSchemeInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(tpm2.KeyedHashParams{}),
	}
	c.Check(func() { WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 128, tpm2.SymModeCFB)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithSymmetricUnique(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(tpm2.SymCipherParams{}),
	}
	WithSymmetricUnique(make([]byte, 256))(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type:   tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(tpm2.SymCipherParams{}),
		Unique: tpm2.MakePublicIDUnion(make(tpm2.Digest, 256)),
	})
}

func (s *templatesSuite) TestWithSymmetricUniqueInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	c.Check(func() { WithSymmetricUnique(make([]byte, 256))(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithRSAKeyBits2048(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAKeyBits(2048)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{KeyBits: 2048},
		),
	})
}

func (s *templatesSuite) TestWithRSAKeyBits3072(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAKeyBits(3072)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{KeyBits: 3072},
		),
	})
}

func (s *templatesSuite) TestWithRSAKeyBitsInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	c.Check(func() { WithRSAKeyBits(2048)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithRSAParams2048AndDefaultExp(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAParams(2048, tpm2.DefaultRSAExponent)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{KeyBits: 2048},
		),
	})
}

func (s *templatesSuite) TestWithRSAParams3072AndNonDefaultExp(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAParams(3072, 257)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				KeyBits:  3072,
				Exponent: 257,
			},
		),
	})
}

func (s *templatesSuite) TestWithRSAParamsInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	c.Check(func() { WithRSAParams(2048, tpm2.DefaultRSAExponent)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithRSASchemeSSA(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAScheme(tpm2.RSASchemeRSASSA, tpm2.HashAlgorithmSHA256)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSASSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithRSASchemeES(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAScheme(tpm2.RSASchemeRSAES, tpm2.HashAlgorithmNull)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSAES,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.EncSchemeRSAES{},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithRSASchemeInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	c.Check(func() { WithRSAScheme(tpm2.RSASchemeRSASSA, tpm2.HashAlgorithmSHA256)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithRSAUnique(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	WithRSAUnique(make([]byte, 256))(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
		Unique: tpm2.MakePublicIDUnion(make(tpm2.PublicKeyRSA, 256)),
	})
}

func (s *templatesSuite) TestWithRSAUniqueInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	c.Check(func() { WithRSAUnique(make([]byte, 256))(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithECCCurveP256(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithECCCurve(tpm2.ECCCurveNIST_P256)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{CurveID: tpm2.ECCCurveNIST_P256},
		),
	})
}

func (s *templatesSuite) TestWithECCCurveP521(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithECCCurve(tpm2.ECCCurveNIST_P521)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{CurveID: tpm2.ECCCurveNIST_P521},
		),
	})
}

func (s *templatesSuite) TestWithECCCurveInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	c.Check(func() { WithECCCurve(tpm2.ECCCurveNIST_P256)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithECCSchemeECDSA(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithECCScheme(tpm2.ECCSchemeECDSA, tpm2.HashAlgorithmSHA256)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithECCSchemeECDH(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithECCScheme(tpm2.ECCSchemeECDH, tpm2.HashAlgorithmSHA256)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDH,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.KeySchemeECDH{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithECCSchemeInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	c.Check(func() { WithECCScheme(tpm2.ECCSchemeECDSA, tpm2.HashAlgorithmSHA256)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithECCUnique(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
	}
	WithECCUnique(&tpm2.ECCPoint{X: make([]byte, 32), Y: make([]byte, 32)})(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type:   tpm2.ObjectTypeECC,
		Params: tpm2.MakePublicParamsUnion(tpm2.ECCParams{}),
		Unique: tpm2.MakePublicIDUnion(tpm2.ECCPoint{X: make([]byte, 32), Y: make([]byte, 32)}),
	})
}

func (s *templatesSuite) TestWithECCUniqueInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeRSA,
		Params: tpm2.MakePublicParamsUnion(tpm2.RSAParams{}),
	}
	c.Check(func() { WithECCUnique(new(tpm2.ECCPoint))(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithHMACDigestSHA256(c *C) {
	pub := &tpm2.Public{
		Type: tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeHMAC},
			},
		),
	}
	WithHMACDigest(tpm2.HashAlgorithmSHA256)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithHMACDigestSHA512(c *C) {
	pub := &tpm2.Public{
		Type: tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeHMAC},
			},
		),
	}
	WithHMACDigest(tpm2.HashAlgorithmSHA512)(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type: tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA512},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestWithHMACDigestInvalidType1(c *C) {
	pub := &tpm2.Public{
		Type: tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeXOR}},
		),
	}
	c.Check(func() { WithHMACDigest(tpm2.HashAlgorithmSHA256)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithHMACDigestInvalidType2(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(tpm2.SymCipherParams{}),
	}
	c.Check(func() { WithHMACDigest(tpm2.HashAlgorithmSHA256)(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestWithKeyedHashUnique(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(tpm2.KeyedHashParams{}),
	}
	WithKeyedHashUnique(make([]byte, 256))(pub)
	c.Check(pub, DeepEquals, &tpm2.Public{
		Type:   tpm2.ObjectTypeKeyedHash,
		Params: tpm2.MakePublicParamsUnion(tpm2.KeyedHashParams{}),
		Unique: tpm2.MakePublicIDUnion(make(tpm2.Digest, 256)),
	})
}

func (s *templatesSuite) TestWithKeyedHashUniqueInvalidType(c *C) {
	pub := &tpm2.Public{
		Type:   tpm2.ObjectTypeSymCipher,
		Params: tpm2.MakePublicParamsUnion(tpm2.SymCipherParams{}),
	}
	c.Check(func() { WithKeyedHashUnique(make([]byte, 256))(pub) }, PanicMatches, "invalid object type")
}

func (s *templatesSuite) TestNewRSAStorageKeyTemplate(c *C) {
	template := NewRSAStorageKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
				Scheme:  tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits: 2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAStorageKeyTemplateWithOptions(c *C) {
	template := NewRSAStorageKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithProtectionGroupMode(Duplicable),
		WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 256, tpm2.SymModeCFB))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
				Scheme:  tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits: 2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAAttestationKeyTemplate(c *C) {
	template := NewRSAAttestationKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSAPSS,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
				KeyBits: 2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAAttestationKeyTemplateWithOptions(c *C) {
	template := NewRSAAttestationKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA384),
		WithRSAKeyBits(3072),
		WithRSAScheme(tpm2.RSASchemeRSASSA, tpm2.HashAlgorithmSHA512))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA384,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSASSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA512},
					),
				},
				KeyBits: 3072,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAKeyTemplateSign(c *C) {
	template := NewRSAKeyTemplate(UsageSign)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAKeyTemplateDecrypt(c *C) {
	template := NewRSAKeyTemplate(UsageDecrypt)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAKeyTemplateWithOptions(c *C) {
	template := NewRSAKeyTemplate(UsageSign,
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithoutDictionaryAttackProtection(),
		WithDuplicationMode(DuplicationRootEncrypted),
		WithRSAKeyBits(3072),
		WithRSAScheme(tpm2.RSASchemeRSASSA, tpm2.HashAlgorithmSHA256))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrEncryptedDuplication | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSASSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
				KeyBits: 3072,
			},
		),
	})
}

func (s *templatesSuite) TestNewRSAKeyTemplateSignAndDecrypt(c *C) {
	template := NewRSAKeyTemplate(UsageSign | UsageDecrypt)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
			},
		),
	})
}

func (s *templatesSuite) TestNewECCStorageKeyTemplate(c *C) {
	template := NewECCStorageKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
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
	})

}

func (s *templatesSuite) TestNewECCStorageKeyTemplateWithOptions(c *C) {
	template := NewECCStorageKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithProtectionGroupMode(Duplicable),
		WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 256, tpm2.SymModeCFB))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
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
	})
}

func (s *templatesSuite) TestNewECCAttestationKeyTemplate(c *C) {
	template := NewECCAttestationKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
				CurveID: tpm2.ECCCurveNIST_P256,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewECCAttestationKeyTemplateWithOptions(c *C) {
	template := NewECCAttestationKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA384),
		WithECCCurve(tpm2.ECCCurveNIST_P521),
		WithECCScheme(tpm2.ECCSchemeECDSA, tpm2.HashAlgorithmSHA512))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA384,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDSA,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA512},
					),
				},
				CurveID: tpm2.ECCCurveNIST_P521,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewECCKeyTemplateSign(c *C) {
	template := NewECCKeyTemplate(UsageSign)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewECCKeyTemplateKeyAgreement(c *C) {
	template := NewECCKeyTemplate(UsageKeyAgreement)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewECCKeyTemplateWithOptions(c *C) {
	template := NewECCKeyTemplate(UsageKeyAgreement,
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithoutDictionaryAttackProtection(),
		WithDuplicationMode(DuplicationRootEncrypted),
		WithECCCurve(tpm2.ECCCurveNIST_P521),
		WithECCScheme(tpm2.ECCSchemeECDH, tpm2.HashAlgorithmSHA256))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrEncryptedDuplication | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDH,
					Details: tpm2.MakeAsymSchemeUnion(
						tpm2.KeySchemeECDH{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
				CurveID: tpm2.ECCCurveNIST_P521,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewECCKeyTemplateSignAndKeyAgreement(c *C) {
	template := NewECCKeyTemplate(UsageSign | UsageKeyAgreement)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID:   tpm2.ECCCurveNIST_P256,
				KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyTemplate(c *C) {
	template := NewSymmetricStorageKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyTemplateWithOptions(c *C) {
	template := NewSymmetricStorageKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithProtectionGroupMode(Duplicable),
		WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 256, tpm2.SymModeCFB))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricKeyTemplateEncrypt(c *C) {
	template := NewSymmetricKeyTemplate(UsageEncrypt)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricKeyTemplateEncryptAndDecrypt(c *C) {
	template := NewSymmetricKeyTemplate(UsageEncrypt | UsageDecrypt)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricKeyTemplateWithOptions(c *C) {
	template := NewSymmetricKeyTemplate(UsageEncrypt,
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithoutDictionaryAttackProtection(),
		WithDuplicationMode(DuplicationRootEncrypted),
		WithSymmetricScheme(tpm2.SymObjectAlgorithmAES, 256, tpm2.SymModeCFB))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrEncryptedDuplication | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](256),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSymmetricKeyTemplateDecrypt(c *C) {
	template := NewSymmetricKeyTemplate(UsageDecrypt)
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   tpm2.MakeSymKeyBitsUnion[uint16](128),
					Mode:      tpm2.MakeSymModeUnion(tpm2.SymModeCFB),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewHMACKeyTemplate(c *C) {
	template := NewHMACKeyTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA256},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewHMACKeyTemplateWithOptions(c *C) {
	template := NewHMACKeyTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA384),
		WithoutDictionaryAttackProtection(),
		WithDuplicationMode(DuplicationRoot),
		WithHMACDigest(tpm2.HashAlgorithmSHA512))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA384,
		Attrs:   tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrSign,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeHMAC{HashAlg: tpm2.HashAlgorithmSHA512},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewDerivationParentTemplate(c *C) {
	template := NewDerivationParentTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeXOR,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeXOR{
							HashAlg: tpm2.HashAlgorithmSHA256,
							KDF:     tpm2.KDFAlgorithmKDF1_SP800_108,
						},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewDerivationParentTemplateWithOptions(c *C) {
	template := NewDerivationParentTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithoutDictionaryAttackProtection(),
		WithDerivationScheme(tpm2.HashAlgorithmSHA512, tpm2.KDFAlgorithmKDF1_SP800_108))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeXOR,
					Details: tpm2.MakeSchemeKeyedHashUnion(
						tpm2.SchemeXOR{
							HashAlg: tpm2.HashAlgorithmSHA512,
							KDF:     tpm2.KDFAlgorithmKDF1_SP800_108,
						},
					),
				},
			},
		),
	})
}

func (s *templatesSuite) TestNewSealedObjectTemplate(c *C) {
	template := NewSealedObjectTemplate()
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull},
			},
		),
	})
}

func (s *templatesSuite) TestNewSealedObjectTemplateWithOptions(c *C) {
	template := NewSealedObjectTemplate(
		WithNameAlg(tpm2.HashAlgorithmSHA512),
		WithUserAuthMode(RequirePolicy))
	c.Check(template, testutil.TPMValueDeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA512,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent,
		Params: tpm2.MakePublicParamsUnion(
			tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull},
			},
		),
	})
}
