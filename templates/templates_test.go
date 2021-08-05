// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package templates_test

import (
	"flag"
	"fmt"
	"os"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/templates"
	"github.com/canonical/go-tpm2/testutil"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type templatesSuite struct {
	testutil.TPMTest
}

func (s *templatesSuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy
}

var _ = Suite(&templatesSuite{})

type testNewRSAStorageKeyData struct {
	nameAlg     tpm2.HashAlgorithmId
	algorithm   tpm2.SymObjectAlgorithmId
	symKeyBits  uint16
	asymKeyBits uint16

	expected *tpm2.Public
}

func (s *templatesSuite) testNewRSAStorageKey(c *C, data *testNewRSAStorageKeyData) {
	template := NewRSAStorageKey(data.nameAlg, data.algorithm, data.symKeyBits, data.asymKeyBits)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewRSAStorageKeyDefault(c *C) {
	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyDefaultSpecified(c *C) {
	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:     tpm2.HashAlgorithmSHA256,
		algorithm:   tpm2.SymObjectAlgorithmAES,
		symKeyBits:  128,
		asymKeyBits: 2048,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyDifferentAlgorithm(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmCamellia, 128)

	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmCamellia,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmCamellia,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyDefaultDifferentSymKeyBits(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmAES, 256)

	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:    tpm2.HashAlgorithmNull,
		algorithm:  tpm2.SymObjectAlgorithmNull,
		symKeyBits: 256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyDefaultDifferentAsymKeyBits(c *C) {
	s.RequireRSAKeySize(c, 1024)

	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:     tpm2.HashAlgorithmNull,
		algorithm:   tpm2.SymObjectAlgorithmNull,
		asymKeyBits: 1024,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  1024,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyDifferentNameAlg(c *C) {
	s.testNewRSAStorageKey(c, &testNewRSAStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		algorithm: tpm2.SymObjectAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAStorageKeyWithDefaults(c *C) {
	template := NewRSAStorageKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewRestrictedRSASigningKeyData struct {
	nameAlg tpm2.HashAlgorithmId
	scheme  *tpm2.RSAScheme
	keyBits uint16

	expected *tpm2.Public
}

func (s *templatesSuite) testNewRestrictedRSASigningKey(c *C, data *testNewRestrictedRSASigningKeyData) {
	template := NewRestrictedRSASigningKey(data.nameAlg, data.scheme, data.keyBits)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyDefaults(c *C) {
	s.testNewRestrictedRSASigningKey(c, &testNewRestrictedRSASigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSASSA,
						Details: &tpm2.AsymSchemeU{
							RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyDefaultsSpecified(c *C) {
	s.testNewRestrictedRSASigningKey(c, &testNewRestrictedRSASigningKeyData{
		nameAlg: tpm2.HashAlgorithmSHA256,
		scheme: &tpm2.RSAScheme{
			Scheme: tpm2.RSASchemeRSASSA,
			Details: &tpm2.AsymSchemeU{
				RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
		keyBits: 2048,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSASSA,
						Details: &tpm2.AsymSchemeU{
							RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyDifferentNameAlg(c *C) {
	s.testNewRestrictedRSASigningKey(c, &testNewRestrictedRSASigningKeyData{
		nameAlg: tpm2.HashAlgorithmSHA1,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSASSA,
						Details: &tpm2.AsymSchemeU{
							RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA1}}},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyDifferentScheme(c *C) {
	s.testNewRestrictedRSASigningKey(c, &testNewRestrictedRSASigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		scheme: &tpm2.RSAScheme{
			Scheme: tpm2.RSASchemeRSAPSS,
			Details: &tpm2.AsymSchemeU{
				RSAPSS: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA1}}},
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSAPSS,
						Details: &tpm2.AsymSchemeU{
							RSAPSS: &tpm2.SigSchemeRSAPSS{HashAlg: tpm2.HashAlgorithmSHA1}}},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyDifferentKeyBits(c *C) {
	s.RequireRSAKeySize(c, 1024)

	s.testNewRestrictedRSASigningKey(c, &testNewRestrictedRSASigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		keyBits: 1024,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeRSASSA,
						Details: &tpm2.AsymSchemeU{
							RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					KeyBits:  1024,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRestrictedRSASigningKeyWithDefaults(c *C) {
	template := NewRestrictedRSASigningKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.RSAScheme{
					Scheme: tpm2.RSASchemeRSASSA,
					Details: &tpm2.AsymSchemeU{
						RSASSA: &tpm2.SigSchemeRSASSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewRSAKeyData struct {
	nameAlg tpm2.HashAlgorithmId
	usage   KeyUsage
	scheme  *tpm2.RSAScheme
	keyBits uint16

	expected *tpm2.Public
}

func (s *templatesSuite) testNewRSAKey(c *C, data *testNewRSAKeyData) {
	template := NewRSAKey(data.nameAlg, data.usage, data.scheme, data.keyBits)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewRSAKeyDefaults(c *C) {
	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeyDefaultsSpecified(c *C) {
	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmSHA256,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		scheme:  &tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
		keyBits: 2048,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeySignOnly(c *C) {
	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeyDecryptOnly(c *C) {
	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageDecrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeyDifferentScheme(c *C) {
	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageDecrypt,
		scheme: &tpm2.RSAScheme{
			Scheme: tpm2.RSASchemeOAEP,
			Details: &tpm2.AsymSchemeU{
				OAEP: &tpm2.EncSchemeOAEP{HashAlg: tpm2.HashAlgorithmSHA1}}},
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.RSAScheme{
						Scheme: tpm2.RSASchemeOAEP,
						Details: &tpm2.AsymSchemeU{
							OAEP: &tpm2.EncSchemeOAEP{HashAlg: tpm2.HashAlgorithmSHA1}}},
					KeyBits:  2048,
					Exponent: 0}}}})
}

func (s *templatesSuite) TestNewRSAKeyDifferentKeyBits(c *C) {
	s.RequireRSAKeySize(c, 1024)

	s.testNewRSAKey(c, &testNewRSAKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		keyBits: 1024,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   1024,
					Exponent:  0}}}})
}

type testNewRSAKeyWithDefaultsData struct {
	usage KeyUsage

	expected *tpm2.Public
}

func (s *templatesSuite) testNewRSAKeyWithDefaults(c *C, data *testNewRSAKeyWithDefaultsData) {
	template := NewRSAKeyWithDefaults(data.usage)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewRSAKeyWithDefaultsSign(c *C) {
	s.testNewRSAKeyWithDefaults(c, &testNewRSAKeyWithDefaultsData{
		usage: KeyUsageSign,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeyWithDefaultsDecrypt(c *C) {
	s.testNewRSAKeyWithDefaults(c, &testNewRSAKeyWithDefaultsData{
		usage: KeyUsageDecrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

func (s *templatesSuite) TestNewRSAKeyWithDefaults(c *C) {
	s.testNewRSAKeyWithDefaults(c, &testNewRSAKeyWithDefaultsData{
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeRSA,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				RSADetail: &tpm2.RSAParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0}}}})
}

type testNewSealedObjectData struct {
	nameAlg tpm2.HashAlgorithmId

	expected *tpm2.Public
}

func (s *templatesSuite) testNewSealedObject(c *C, data *testNewSealedObjectData) {
	primaryTemplate := NewRSAStorageKey(tpm2.HashAlgorithmSHA256, tpm2.SymObjectAlgorithmAES, 128, 2048)
	primaryTemplate.Attrs |= tpm2.AttrNoDA

	primary := s.CreatePrimary(c, tpm2.HandleOwner, primaryTemplate)

	template := NewSealedObject(data.nameAlg)
	c.Check(template, DeepEquals, data.expected)

	sensitive := tpm2.SensitiveCreate{Data: []byte("foo")}
	_, _, _, _, _, err := s.TPM.Create(primary, &sensitive, template, nil, nil, nil)
	c.Check(err, IsNil)
}

func (s *templatesSuite) TestNewSealedObjectDefaults(c *C) {
	s.testNewSealedObject(c, &testNewSealedObjectData{
		nameAlg: tpm2.HashAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}})
}

func (s *templatesSuite) TestNewSealedObjectDefaultsSpecified(c *C) {
	s.testNewSealedObject(c, &testNewSealedObjectData{
		nameAlg: tpm2.HashAlgorithmSHA256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}})
}

func (s *templatesSuite) TestNewSealedObjectDifferentNameAlg(c *C) {
	s.testNewSealedObject(c, &testNewSealedObjectData{
		nameAlg: tpm2.HashAlgorithmSHA1,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrUserWithAuth,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{Scheme: tpm2.KeyedHashSchemeNull}}}}})
}

type testNewECCStorageKeyData struct {
	nameAlg   tpm2.HashAlgorithmId
	algorithm tpm2.SymObjectAlgorithmId
	keyBits   uint16
	curve     tpm2.ECCCurve

	expected *tpm2.Public
}

func (s *templatesSuite) testNewECCStorageKey(c *C, data *testNewECCStorageKeyData) {
	template := NewECCStorageKey(data.nameAlg, data.algorithm, data.keyBits, data.curve)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewECCStorageKeyDefaults(c *C) {
	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		curve:     tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyDefaultsSpecified(c *C) {
	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA256,
		algorithm: tpm2.SymObjectAlgorithmAES,
		keyBits:   128,
		curve:     tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyDifferentNameAlg(c *C) {
	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		algorithm: tpm2.SymObjectAlgorithmNull,
		curve:     tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyDifferentAlgorithm(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmCamellia, 128)

	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmCamellia,
		curve:     tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmCamellia,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyDifferentKeyBits(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmAES, 256)

	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		keyBits:   256,
		curve:     tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyDifferentCurve(c *C) {
	s.RequireECCCurve(c, tpm2.ECCCurveNIST_P384)

	s.testNewECCStorageKey(c, &testNewECCStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		curve:     tpm2.ECCCurveNIST_P384,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
					Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID: tpm2.ECCCurveNIST_P384,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCStorageKeyWithDefaults(c *C) {
	template := NewECCStorageKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}},
				Scheme:  tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
				CurveID: tpm2.ECCCurveNIST_P256,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewRestrictedECCSigningKeyData struct {
	nameAlg tpm2.HashAlgorithmId
	scheme  *tpm2.ECCScheme
	curve   tpm2.ECCCurve

	expected *tpm2.Public
}

func (s *templatesSuite) testNewRestrictedECCSigningKey(c *C, data *testNewRestrictedECCSigningKeyData) {
	template := NewRestrictedECCSigningKey(data.nameAlg, data.scheme, data.curve)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyDefaults(c *C) {
	s.testNewRestrictedECCSigningKey(c, &testNewRestrictedECCSigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECDSA,
						Details: &tpm2.AsymSchemeU{
							ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyDefaultsSpecified(c *C) {
	s.testNewRestrictedECCSigningKey(c, &testNewRestrictedECCSigningKeyData{
		nameAlg: tpm2.HashAlgorithmSHA256,
		scheme: &tpm2.ECCScheme{
			Scheme: tpm2.ECCSchemeECDSA,
			Details: &tpm2.AsymSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
		curve: tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECDSA,
						Details: &tpm2.AsymSchemeU{
							ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyDifferentNameAlg(c *C) {
	s.testNewRestrictedECCSigningKey(c, &testNewRestrictedECCSigningKeyData{
		nameAlg: tpm2.HashAlgorithmSHA1,
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECDSA,
						Details: &tpm2.AsymSchemeU{
							ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA1}}},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyDifferentScheme(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmECSCHNORR)

	s.testNewRestrictedECCSigningKey(c, &testNewRestrictedECCSigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		scheme: &tpm2.ECCScheme{
			Scheme: tpm2.ECCSchemeECSCHNORR,
			Details: &tpm2.AsymSchemeU{
				ECSCHNORR: &tpm2.SigSchemeECSCHNORR{HashAlg: tpm2.HashAlgorithmSHA1}}},
		curve: tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECSCHNORR,
						Details: &tpm2.AsymSchemeU{
							ECSCHNORR: &tpm2.SigSchemeECSCHNORR{HashAlg: tpm2.HashAlgorithmSHA1}}},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyDifferentCurve(c *C) {
	s.RequireECCCurve(c, tpm2.ECCCurveNIST_P384)

	s.testNewRestrictedECCSigningKey(c, &testNewRestrictedECCSigningKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		curve:   tpm2.ECCCurveNIST_P384,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECDSA,
						Details: &tpm2.AsymSchemeU{
							ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
					CurveID: tpm2.ECCCurveNIST_P384,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewRestrictedECCSigningKeyWithDefaults(c *C) {
	template := NewRestrictedECCSigningKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeECC,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			ECCDetail: &tpm2.ECCParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme: tpm2.ECCScheme{
					Scheme: tpm2.ECCSchemeECDSA,
					Details: &tpm2.AsymSchemeU{
						ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA256}}},
				CurveID: tpm2.ECCCurveNIST_P256,
				KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewECCKeyData struct {
	nameAlg tpm2.HashAlgorithmId
	usage   KeyUsage
	scheme  *tpm2.ECCScheme
	curve   tpm2.ECCCurve

	expected *tpm2.Public
}

func (s *templatesSuite) testNewECCKey(c *C, data *testNewECCKeyData) {
	template := NewECCKey(data.nameAlg, data.usage, data.scheme, data.curve)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewECCKeyDefaults(c *C) {
	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyDefaultsSpecified(c *C) {
	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmSHA256,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		scheme:  &tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeySignOnly(c *C) {
	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign,
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyDecryptOnly(c *C) {
	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageDecrypt,
		curve:   tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyDifferentScheme(c *C) {
	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign,
		scheme: &tpm2.ECCScheme{
			Scheme: tpm2.ECCSchemeECDSA,
			Details: &tpm2.AsymSchemeU{
				ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA1}}},
		curve: tpm2.ECCCurveNIST_P256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme: tpm2.ECCScheme{
						Scheme: tpm2.ECCSchemeECDSA,
						Details: &tpm2.AsymSchemeU{
							ECDSA: &tpm2.SigSchemeECDSA{HashAlg: tpm2.HashAlgorithmSHA1}}},
					CurveID: tpm2.ECCCurveNIST_P256,
					KDF:     tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyDifferentCurve(c *C) {
	s.RequireECCCurve(c, tpm2.ECCCurveNIST_P384)

	s.testNewECCKey(c, &testNewECCKeyData{
		nameAlg: tpm2.HashAlgorithmNull,
		usage:   KeyUsageSign | KeyUsageDecrypt,
		curve:   tpm2.ECCCurveNIST_P384,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P384,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

type testNewECCKeyWithDefaultsData struct {
	usage KeyUsage

	expected *tpm2.Public
}

func (s *templatesSuite) testNewECCKeyWithDefaults(c *C, data *testNewECCKeyWithDefaultsData) {
	template := NewECCKeyWithDefaults(data.usage)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewECCKeyWithDefaultsSign(c *C) {
	s.testNewECCKeyWithDefaults(c, &testNewECCKeyWithDefaultsData{
		usage: KeyUsageSign,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyWithDefaultsDecrypt(c *C) {
	s.testNewECCKeyWithDefaults(c, &testNewECCKeyWithDefaultsData{
		usage: KeyUsageDecrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

func (s *templatesSuite) TestNewECCKeyWithDefaults(c *C) {
	s.testNewECCKeyWithDefaults(c, &testNewECCKeyWithDefaultsData{
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeECC,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				ECCDetail: &tpm2.ECCParams{
					Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
					Scheme:    tpm2.ECCScheme{Scheme: tpm2.ECCSchemeNull},
					CurveID:   tpm2.ECCCurveNIST_P256,
					KDF:       tpm2.KDFScheme{Scheme: tpm2.KDFAlgorithmNull}}}}})
}

type testNewSymmetricStorageKeyData struct {
	nameAlg   tpm2.HashAlgorithmId
	algorithm tpm2.SymObjectAlgorithmId
	keyBits   uint16

	expected *tpm2.Public
}

func (s *templatesSuite) testNewSymmetricStorageKey(c *C, data *testNewSymmetricStorageKeyData) {
	template := NewSymmetricStorageKey(data.nameAlg, data.algorithm, data.keyBits)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewSymmetricStorageKeyDefaults(c *C) {
	s.testNewSymmetricStorageKey(c, &testNewSymmetricStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyDefaultsSpecified(c *C) {
	s.testNewSymmetricStorageKey(c, &testNewSymmetricStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA256,
		algorithm: tpm2.SymObjectAlgorithmAES,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyDifferentNameAlg(c *C) {
	s.testNewSymmetricStorageKey(c, &testNewSymmetricStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		algorithm: tpm2.SymObjectAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyDifferentAlgorithm(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmCamellia, 128)

	s.testNewSymmetricStorageKey(c, &testNewSymmetricStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmCamellia,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmCamellia,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricStorageKeyDifferentKeyBits(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmAES, 256)

	s.testNewSymmetricStorageKey(c, &testNewSymmetricStorageKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		algorithm: tpm2.SymObjectAlgorithmNull,
		keyBits:   256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) NewSymmetricStorageKeyWithDefaults(c *C) {
	template := NewSymmetricStorageKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeSymCipher,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrRestricted | tpm2.AttrDecrypt,
		Params: &tpm2.PublicParamsU{
			SymDetail: &tpm2.SymCipherParams{
				Sym: tpm2.SymDefObject{
					Algorithm: tpm2.SymObjectAlgorithmAES,
					KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
					Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewSymmetricKeyData struct {
	nameAlg   tpm2.HashAlgorithmId
	usage     KeyUsage
	algorithm tpm2.SymObjectAlgorithmId
	keyBits   uint16
	mode      tpm2.SymModeId

	expected *tpm2.Public
}

func (s *templatesSuite) testNewSymmetricKey(c *C, data *testNewSymmetricKeyData) {
	template := NewSymmetricKey(data.nameAlg, data.usage, data.algorithm, data.keyBits, data.mode)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewSymmetricKeyDefaults(c *C) {
	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDefaultsSpecified(c *C) {
	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA256,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmAES,
		keyBits:   128,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyEncryptOnly(c *C) {
	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageEncrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDecryptOnly(c *C) {
	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDifferentNameAlg(c *C) {
	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDifferentAlgorithm(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmCamellia, 128)

	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmCamellia,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmCamellia,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDifferentKeyBits(c *C) {
	s.RequireSymmetricAlgorithm(c, tpm2.SymObjectAlgorithmAES, 256)

	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		keyBits:   256,
		mode:      tpm2.SymModeCFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 256},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyDifferentMode(c *C) {
	s.RequireAlgorithm(c, tpm2.AlgorithmOFB)

	s.testNewSymmetricKey(c, &testNewSymmetricKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		usage:     KeyUsageEncrypt | KeyUsageDecrypt,
		algorithm: tpm2.SymObjectAlgorithmNull,
		mode:      tpm2.SymModeOFB,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeOFB}}}}}})
}

type testNewSymmetricKeyWithDefaultsData struct {
	usage KeyUsage

	expected *tpm2.Public
}

func (s *templatesSuite) testNewSymmetricKeyWithDefaults(c *C, data *testNewSymmetricKeyWithDefaultsData) {
	template := NewSymmetricKeyWithDefaults(data.usage)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewSymmetricKeyWithDefaultsEncrypt(c *C) {
	s.testNewSymmetricKeyWithDefaults(c, &testNewSymmetricKeyWithDefaultsData{
		usage: KeyUsageEncrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyWithDefaultsDecrypt(c *C) {
	s.testNewSymmetricKeyWithDefaults(c, &testNewSymmetricKeyWithDefaultsData{
		usage: KeyUsageDecrypt,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

func (s *templatesSuite) TestNewSymmetricKeyWithDefaults(c *C) {
	s.testNewSymmetricKeyWithDefaults(c, &testNewSymmetricKeyWithDefaultsData{
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeSymCipher,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign | tpm2.AttrDecrypt,
			Params: &tpm2.PublicParamsU{
				SymDetail: &tpm2.SymCipherParams{
					Sym: tpm2.SymDefObject{
						Algorithm: tpm2.SymObjectAlgorithmAES,
						KeyBits:   &tpm2.SymKeyBitsU{Sym: 128},
						Mode:      &tpm2.SymModeU{Sym: tpm2.SymModeCFB}}}}}})
}

type testNewHMACKeyData struct {
	nameAlg   tpm2.HashAlgorithmId
	schemeAlg tpm2.HashAlgorithmId

	expected *tpm2.Public
}

func (s *templatesSuite) testNewHMACKey(c *C, data *testNewHMACKeyData) {
	template := NewHMACKey(data.nameAlg, data.schemeAlg)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewHMACKeyDefaults(c *C) {
	s.testNewHMACKey(c, &testNewHMACKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		schemeAlg: tpm2.HashAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeHMAC,
						Details: &tpm2.SchemeKeyedHashU{
							HMAC: &tpm2.SchemeHMAC{
								HashAlg: tpm2.HashAlgorithmSHA256}}}}}}})
}

func (s *templatesSuite) TestNewHMACKeyDefaultsSpecified(c *C) {
	s.testNewHMACKey(c, &testNewHMACKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA256,
		schemeAlg: tpm2.HashAlgorithmSHA256,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeHMAC,
						Details: &tpm2.SchemeKeyedHashU{
							HMAC: &tpm2.SchemeHMAC{
								HashAlg: tpm2.HashAlgorithmSHA256}}}}}}})
}

func (s *templatesSuite) TestNewHMACKeyDifferentNameAlg(c *C) {
	s.testNewHMACKey(c, &testNewHMACKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		schemeAlg: tpm2.HashAlgorithmNull,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeHMAC,
						Details: &tpm2.SchemeKeyedHashU{
							HMAC: &tpm2.SchemeHMAC{
								HashAlg: tpm2.HashAlgorithmSHA1}}}}}}})
}

func (s *templatesSuite) TestNewHMACKeyDifferentSchemeAlg(c *C) {
	s.testNewHMACKey(c, &testNewHMACKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		schemeAlg: tpm2.HashAlgorithmSHA1,
		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeHMAC,
						Details: &tpm2.SchemeKeyedHashU{
							HMAC: &tpm2.SchemeHMAC{
								HashAlg: tpm2.HashAlgorithmSHA1}}}}}}})
}

func (s *templatesSuite) TestNewHMACKeyWithDefaults(c *C) {
	template := NewHMACKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeHMAC,
					Details: &tpm2.SchemeKeyedHashU{
						HMAC: &tpm2.SchemeHMAC{
							HashAlg: tpm2.HashAlgorithmSHA256}}}}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

type testNewDerivationParentKeyData struct {
	nameAlg   tpm2.HashAlgorithmId
	schemeAlg tpm2.HashAlgorithmId

	expected *tpm2.Public
}

func (s *templatesSuite) testNewDerivationParentKey(c *C, data *testNewDerivationParentKeyData) {
	template := NewDerivationParentKey(data.nameAlg, data.schemeAlg)
	c.Check(template, DeepEquals, data.expected)
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func (s *templatesSuite) TestNewDerivationParentKeyDefaults(c *C) {
	s.testNewDerivationParentKey(c, &testNewDerivationParentKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		schemeAlg: tpm2.HashAlgorithmNull,

		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeXOR,
						Details: &tpm2.SchemeKeyedHashU{
							XOR: &tpm2.SchemeXOR{
								HashAlg: tpm2.HashAlgorithmSHA256,
								KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}}})
}

func (s *templatesSuite) TestNewDerivationParentKeyDefaultsSpecified(c *C) {
	s.testNewDerivationParentKey(c, &testNewDerivationParentKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA256,
		schemeAlg: tpm2.HashAlgorithmSHA256,

		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeXOR,
						Details: &tpm2.SchemeKeyedHashU{
							XOR: &tpm2.SchemeXOR{
								HashAlg: tpm2.HashAlgorithmSHA256,
								KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}}})
}

func (s *templatesSuite) TestNewDerivationParentKeyDifferentNameAlg(c *C) {
	s.testNewDerivationParentKey(c, &testNewDerivationParentKeyData{
		nameAlg:   tpm2.HashAlgorithmSHA1,
		schemeAlg: tpm2.HashAlgorithmNull,

		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeXOR,
						Details: &tpm2.SchemeKeyedHashU{
							XOR: &tpm2.SchemeXOR{
								HashAlg: tpm2.HashAlgorithmSHA1,
								KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}}})
}

func (s *templatesSuite) TestNewDerivationParentKeyDifferentSchemeAlg(c *C) {
	s.testNewDerivationParentKey(c, &testNewDerivationParentKeyData{
		nameAlg:   tpm2.HashAlgorithmNull,
		schemeAlg: tpm2.HashAlgorithmSHA1,

		expected: &tpm2.Public{
			Type:    tpm2.ObjectTypeKeyedHash,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
			Params: &tpm2.PublicParamsU{
				KeyedHashDetail: &tpm2.KeyedHashParams{
					Scheme: tpm2.KeyedHashScheme{
						Scheme: tpm2.KeyedHashSchemeXOR,
						Details: &tpm2.SchemeKeyedHashU{
							XOR: &tpm2.SchemeXOR{
								HashAlg: tpm2.HashAlgorithmSHA1,
								KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}}})
}

func (s *templatesSuite) TestNewDerivationParentKeyWithDefaults(c *C) {
	template := NewDerivationParentKeyWithDefaults()
	c.Check(template, DeepEquals, &tpm2.Public{
		Type:    tpm2.ObjectTypeKeyedHash,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrDecrypt | tpm2.AttrRestricted,
		Params: &tpm2.PublicParamsU{
			KeyedHashDetail: &tpm2.KeyedHashParams{
				Scheme: tpm2.KeyedHashScheme{
					Scheme: tpm2.KeyedHashSchemeXOR,
					Details: &tpm2.SchemeKeyedHashU{
						XOR: &tpm2.SchemeXOR{
							HashAlg: tpm2.HashAlgorithmSHA256,
							KDF:     tpm2.KDFAlgorithmKDF1_SP800_108}}}}}})
	s.CreatePrimary(c, tpm2.HandleOwner, template)
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if testutil.TPMBackend == testutil.TPMBackendMssim {
			simulatorCleanup, err := testutil.LaunchTPMSimulator(nil)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot launch TPM simulator: %v\n", err)
				return 1
			}
			defer simulatorCleanup()
		}

		return m.Run()
	}())
}
