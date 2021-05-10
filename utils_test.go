package tpm2_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"math/big"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

func zeroExtendBytes(x *big.Int, l int) (out []byte) {
	out = make([]byte, l)
	tmp := x.Bytes()
	copy(out[len(out)-len(tmp):], tmp)
	return
}

type utilsSuite struct{}

var _ = Suite(&utilsSuite{})

type testCreateUnwrapDuplicationObjectData struct {
	parentPriv    crypto.PrivateKey
	parentPublic  *Public
	encryptionKey Data
	symmetricAlg  *SymDefObject
}

func (s *utilsSuite) testCreateUnwrapDuplicationObject(c *C, data *testCreateUnwrapDuplicationObjectData) {
	sensitiveIn := &Sensitive{
		Type:      ObjectTypeKeyedHash,
		AuthValue: []byte("foo"),
		SeedValue: make([]byte, crypto.SHA256.Size()),
		Sensitive: &SensitiveCompositeU{Bits: []byte("super secret data")}}

	h := crypto.SHA256.New()
	h.Write(sensitiveIn.SeedValue)
	h.Write(sensitiveIn.Sensitive.Bits)

	public := &Public{
		Type:    ObjectTypeKeyedHash,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrUserWithAuth,
		Params: &PublicParamsU{
			KeyedHashDetail: &KeyedHashParams{
				Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull},
			},
		},
		Unique: &PublicIDU{KeyedHash: h.Sum(nil)}}

	encryptionKey, duplicate, symSeed, err := CreateDuplicationObjectFromSensitive(sensitiveIn, public, data.parentPublic, data.encryptionKey, data.symmetricAlg)
	c.Check(err, IsNil)
	if data.symmetricAlg != nil && data.symmetricAlg.Algorithm != SymObjectAlgorithmNull && len(data.encryptionKey) == 0 {
		c.Check(encryptionKey, HasLen, int(data.symmetricAlg.KeyBits.Sym/8))
	} else {
		c.Check(encryptionKey, IsNil)
		encryptionKey = data.encryptionKey
	}

	parentNameAlg := HashAlgorithmNull
	var parentSymmetricAlg *SymDefObject
	if data.parentPublic != nil {
		parentNameAlg = data.parentPublic.NameAlg
		parentSymmetricAlg = &data.parentPublic.Params.AsymDetail().Symmetric
	}

	sensitive, err := UnwrapDuplicationObjectToSensitive(duplicate, public, data.parentPriv, parentNameAlg, parentSymmetricAlg, encryptionKey, symSeed, data.symmetricAlg)
	c.Check(err, IsNil)
	c.Assert(sensitive, NotNil)

	c.Check(sensitive.Type, Equals, sensitiveIn.Type)
	c.Check(sensitive.AuthValue, HasLen, crypto.SHA256.Size())
	c.Check(sensitive.AuthValue[:len(sensitiveIn.AuthValue)], DeepEquals, sensitiveIn.AuthValue)
	c.Check(sensitive.AuthValue[len(sensitiveIn.AuthValue):], DeepEquals, make(Auth, crypto.SHA256.Size()-len(sensitiveIn.AuthValue)))
	c.Check(sensitive.SeedValue, DeepEquals, sensitiveIn.SeedValue)
	c.Check(sensitive.Sensitive, DeepEquals, sensitiveIn.Sensitive)
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectNoWrapper(c *C) {
	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectInnerWrapper1(c *C) {
	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		symmetricAlg: &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   &SymKeyBitsU{Sym: 256},
			Mode:      &SymModeU{Sym: SymModeCFB}},
	})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectInnerWrapper2(c *C) {
	symKey := make([]byte, 16)
	rand.Read(symKey)

	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		encryptionKey: symKey,
		symmetricAlg: &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   &SymKeyBitsU{Sym: 128},
			Mode:      &SymModeU{Sym: SymModeCFB}},
	})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectOuterWrapperRSA(c *C) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		parentPriv: privKey,
		parentPublic: &Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: &PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB},
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: uint32(privKey.E),
				},
			},
			Unique: &PublicIDU{RSA: privKey.N.Bytes()},
		},
	})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectOuterWrapperECC1(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		parentPriv: privKey,
		parentPublic: &Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: &PublicParamsU{
				ECCDetail: &ECCParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 128},
						Mode:      &SymModeU{Sym: SymModeCFB},
					},
					Scheme:  ECCScheme{Scheme: ECCSchemeNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull},
				},
			},
			Unique: &PublicIDU{
				ECC: &ECCPoint{
					X: zeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: zeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			},
		},
	})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectOuterWrapperECC2(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		parentPriv: privKey,
		parentPublic: &Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA1,
			Attrs:   AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: &PublicParamsU{
				ECCDetail: &ECCParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 128},
						Mode:      &SymModeU{Sym: SymModeCFB},
					},
					Scheme:  ECCScheme{Scheme: ECCSchemeNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull},
				},
			},
			Unique: &PublicIDU{
				ECC: &ECCPoint{
					X: zeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: zeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			},
		},
	})
}

func (s *utilsSuite) TestCreateUnwrapDuplicationObjectBothWrappers(c *C) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	s.testCreateUnwrapDuplicationObject(c, &testCreateUnwrapDuplicationObjectData{
		symmetricAlg: &SymDefObject{
			Algorithm: SymObjectAlgorithmAES,
			KeyBits:   &SymKeyBitsU{Sym: 256},
			Mode:      &SymModeU{Sym: SymModeCFB}},
		parentPriv: privKey,
		parentPublic: &Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: &PublicParamsU{
				ECCDetail: &ECCParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   &SymKeyBitsU{Sym: 256},
						Mode:      &SymModeU{Sym: SymModeCFB},
					},
					Scheme:  ECCScheme{Scheme: ECCSchemeNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull},
				},
			},
			Unique: &PublicIDU{
				ECC: &ECCPoint{
					X: zeroExtendBytes(privKey.X, elliptic.P256().Params().BitSize/8),
					Y: zeroExtendBytes(privKey.Y, elliptic.P256().Params().BitSize/8),
				},
			},
		},
	})
}

type mockHandleContext struct {
	name Name
}

func (c *mockHandleContext) Name() Name {
	return c.name
}
func (c *mockHandleContext) Handle() Handle                    { return HandleNull }
func (c *mockHandleContext) SerializeToBytes() []byte          { return nil }
func (c *mockHandleContext) SerializeToWriter(io.Writer) error { return nil }

func TestComputeCpHash(t *testing.T) {
	h := crypto.SHA256.New()
	h.Write([]byte("foo"))
	name, _ := mu.MarshalToBytes(HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))
	rc := &mockHandleContext{name}

	for _, data := range []struct {
		desc     string
		alg      HashAlgorithmId
		command  CommandCode
		params   []interface{}
		expected Digest
	}{
		{
			desc:    "Unseal",
			alg:     HashAlgorithmSHA256,
			command: CommandUnseal,
			params:  []interface{}{rc},
			expected: Digest{0xe5, 0xe8, 0x03, 0xe4, 0xcb, 0xd3, 0x3f, 0x78, 0xc5, 0x65, 0x1b, 0x49, 0xf2, 0x83, 0xba, 0x63, 0x8a, 0xdf, 0x34,
				0xca, 0x69, 0x60, 0x76, 0x40, 0xfb, 0xea, 0x9e, 0xe2, 0x89, 0xfd, 0x93, 0xe7},
		},
		{
			desc:    "EvictControl",
			alg:     HashAlgorithmSHA1,
			command: CommandEvictControl,
			params:  []interface{}{HandleOwner, rc, Handle(0x8100ffff)},
			expected: Digest{0x40, 0x93, 0x38, 0x44, 0x00, 0xde, 0x24, 0x3a, 0xcb, 0x81, 0x04, 0xba, 0x14, 0xbf, 0x2f, 0x2e, 0xf8, 0xa8, 0x27,
				0x0b},
		},
		{
			desc:    "DAParameters",
			alg:     HashAlgorithmSHA256,
			command: CommandDictionaryAttackParameters,
			params:  []interface{}{HandleLockout, Delimiter, uint32(32), uint32(7200), uint32(86400)},
			expected: Digest{0x8e, 0xa6, 0x7e, 0x49, 0x3d, 0x62, 0x56, 0x21, 0x4c, 0x2e, 0xd2, 0xe9, 0xfd, 0x69, 0xbe, 0x71, 0x4a, 0x5e, 0x1b,
				0xab, 0x5d, 0x55, 0x24, 0x56, 0xd0, 0x29, 0x82, 0xe1, 0x5c, 0xd2, 0x61, 0xde},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			cpHash, err := ComputeCpHash(data.alg, data.command, data.params...)
			if err != nil {
				t.Fatalf("ComputeCpHash failed: %v", err)
			}

			if !bytes.Equal(cpHash, data.expected) {
				t.Errorf("Unexpected digest (got %x, expected %x)", cpHash, data.expected)
			}
		})
	}
}

func TestComputePCRDigest(t *testing.T) {
	for _, data := range []struct {
		desc     string
		alg      HashAlgorithmId
		pcrs     PCRSelectionList
		values   PCRValues
		expected Digest
		err      string
	}{
		{
			desc: "SinglePCRValue",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			values: PCRValues{HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96,
				0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}}},
			expected: Digest{0xcd, 0x44, 0x6a, 0x85, 0x37, 0xe5, 0x90, 0x56, 0xc9, 0x99, 0xae, 0xb7, 0xec, 0xd4, 0x7f, 0x6b, 0x4f, 0x82, 0xf8,
				0x63, 0x09, 0xd0, 0x87, 0x89, 0xb1, 0x69, 0xd4, 0x3e, 0x9c, 0xe5, 0x39, 0x35},
		},
		{
			desc: "MultiplePCRValues/1",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{4, 7}}},
			values: PCRValues{
				HashAlgorithmSHA256: {
					4: Digest{0x7d, 0x86, 0x5e, 0x95, 0x9b, 0x24, 0x66, 0x91, 0x8c, 0x98, 0x63, 0xaf, 0xca, 0x94, 0x2d, 0x0f, 0xb8, 0x9d, 0x7c, 0x9a,
						0xc0, 0xc9, 0x9b, 0xaf, 0xc3, 0x74, 0x95, 0x04, 0xde, 0xd9, 0x77, 0x30},
					7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2,
						0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c},
				},
			},
			expected: Digest{0x68, 0x92, 0xd5, 0x9a, 0xb3, 0xec, 0x80, 0x1e, 0x5f, 0x15, 0x4a, 0x7d, 0x27, 0x67, 0xff, 0x78, 0xf3, 0x30, 0xaa,
				0x1b, 0x01, 0x5c, 0x16, 0xee, 0xd9, 0xc7, 0x39, 0xd5, 0x92, 0x0f, 0xe5, 0xf8},
		},
		{
			desc: "MultiplePCRValues/2",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7, 4}}},
			values: PCRValues{
				HashAlgorithmSHA256: {
					4: Digest{0x7d, 0x86, 0x5e, 0x95, 0x9b, 0x24, 0x66, 0x91, 0x8c, 0x98, 0x63, 0xaf, 0xca, 0x94, 0x2d, 0x0f, 0xb8, 0x9d, 0x7c, 0x9a,
						0xc0, 0xc9, 0x9b, 0xaf, 0xc3, 0x74, 0x95, 0x04, 0xde, 0xd9, 0x77, 0x30},
					7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2,
						0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c},
				},
			},
			expected: Digest{0x68, 0x92, 0xd5, 0x9a, 0xb3, 0xec, 0x80, 0x1e, 0x5f, 0x15, 0x4a, 0x7d, 0x27, 0x67, 0xff, 0x78, 0xf3, 0x30, 0xaa,
				0x1b, 0x01, 0x5c, 0x16, 0xee, 0xd9, 0xc7, 0x39, 0xd5, 0x92, 0x0f, 0xe5, 0xf8},
		},
		{
			desc: "MultiplePCRBanks/1",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{4}},
				{Hash: HashAlgorithmSHA256, Select: []int{7}},
			},
			values: PCRValues{
				HashAlgorithmSHA1: {4: Digest{0xe2, 0x42, 0xed, 0x3b, 0xff, 0xcc, 0xdf, 0x27, 0x1b, 0x7f, 0xba, 0xf3, 0x4e, 0xd7, 0x2d, 0x08,
					0x95, 0x37, 0xb4, 0x2f}},
				HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc,
					0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}},
			},
			expected: Digest{0x80, 0x3f, 0xa6, 0x2e, 0x5e, 0x94, 0x5f, 0x59, 0xaf, 0x7d, 0x40, 0xa0, 0xe8, 0x02, 0x20, 0x1a, 0x5b, 0x03, 0x54,
				0x47, 0x2b, 0x4d, 0x72, 0x79, 0x28, 0x9d, 0x8a, 0x6d, 0x32, 0xfa, 0xbb, 0x6c},
		},
		{
			desc: "MultiplePCRBanks/2",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{7}},
				{Hash: HashAlgorithmSHA1, Select: []int{4}},
			},
			values: PCRValues{
				HashAlgorithmSHA1: {4: Digest{0xe2, 0x42, 0xed, 0x3b, 0xff, 0xcc, 0xdf, 0x27, 0x1b, 0x7f, 0xba, 0xf3, 0x4e, 0xd7, 0x2d, 0x08,
					0x95, 0x37, 0xb4, 0x2f}},
				HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc,
					0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}},
			},
			expected: Digest{0xe7, 0x7c, 0x03, 0x6d, 0x95, 0xb0, 0xd3, 0x78, 0xb1, 0x84, 0x03, 0x81, 0xbe, 0x68, 0x4a, 0xcf, 0x12, 0xd1, 0x48,
				0x36, 0x65, 0x29, 0xf7, 0x22, 0x69, 0x79, 0xdf, 0xd6, 0xeb, 0xe1, 0x5f, 0xf9},
		},
		{
			desc: "UnusedPCRValues",
			alg:  HashAlgorithmSHA256,
			pcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			values: PCRValues{
				HashAlgorithmSHA256: {
					4: Digest{0x7d, 0x86, 0x5e, 0x95, 0x9b, 0x24, 0x66, 0x91, 0x8c, 0x98, 0x63, 0xaf, 0xca, 0x94, 0x2d, 0x0f, 0xb8, 0x9d, 0x7c, 0x9a,
						0xc0, 0xc9, 0x9b, 0xaf, 0xc3, 0x74, 0x95, 0x04, 0xde, 0xd9, 0x77, 0x30},
					7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2,
						0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c},
				},
			},
			expected: Digest{0xcd, 0x44, 0x6a, 0x85, 0x37, 0xe5, 0x90, 0x56, 0xc9, 0x99, 0xae, 0xb7, 0xec, 0xd4, 0x7f, 0x6b, 0x4f, 0x82, 0xf8,
				0x63, 0x09, 0xd0, 0x87, 0x89, 0xb1, 0x69, 0xd4, 0x3e, 0x9c, 0xe5, 0x39, 0x35},
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			pcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			values: PCRValues{HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96,
				0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}}},
			expected: Digest{0x70, 0xb0, 0x87, 0x3f, 0x47, 0xf9, 0x61, 0xbb, 0xb8, 0x91, 0xcc, 0xee, 0x9f, 0x8a, 0x57, 0xaa, 0xcd, 0x16, 0x70,
				0x40},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			digest, err := ComputePCRDigest(data.alg, data.pcrs, data.values)
			if data.err == "" {
				if err != nil {
					t.Fatalf("ComputePCRDigest failed: %v", err)
				}
				if !bytes.Equal(digest, data.expected) {
					t.Errorf("Unexpected digest: %x", digest)
				}
			} else {
				if err == nil {
					t.Fatalf("Expected an error")
				}
				if err.Error() != data.err {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestComputePCRDigestSimple(t *testing.T) {
	for _, data := range []struct {
		desc           string
		alg            HashAlgorithmId
		values         PCRValues
		expectedPcrs   PCRSelectionList
		expectedDigest Digest
	}{
		{
			desc: "SinglePCRValue",
			alg:  HashAlgorithmSHA256,
			values: PCRValues{HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96,
				0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}}},
			expectedPcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			expectedDigest: Digest{0xcd, 0x44, 0x6a, 0x85, 0x37, 0xe5, 0x90, 0x56, 0xc9, 0x99, 0xae, 0xb7, 0xec, 0xd4, 0x7f, 0x6b, 0x4f, 0x82,
				0xf8, 0x63, 0x09, 0xd0, 0x87, 0x89, 0xb1, 0x69, 0xd4, 0x3e, 0x9c, 0xe5, 0x39, 0x35},
		},
		{
			desc: "MultiplePCRValues",
			alg:  HashAlgorithmSHA256,
			values: PCRValues{
				HashAlgorithmSHA256: {
					4: Digest{0x7d, 0x86, 0x5e, 0x95, 0x9b, 0x24, 0x66, 0x91, 0x8c, 0x98, 0x63, 0xaf, 0xca, 0x94, 0x2d, 0x0f, 0xb8, 0x9d, 0x7c, 0x9a,
						0xc0, 0xc9, 0x9b, 0xaf, 0xc3, 0x74, 0x95, 0x04, 0xde, 0xd9, 0x77, 0x30},
					7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2,
						0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c},
				},
			},
			expectedPcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{4, 7}}},
			expectedDigest: Digest{0x68, 0x92, 0xd5, 0x9a, 0xb3, 0xec, 0x80, 0x1e, 0x5f, 0x15, 0x4a, 0x7d, 0x27, 0x67, 0xff, 0x78, 0xf3, 0x30,
				0xaa, 0x1b, 0x01, 0x5c, 0x16, 0xee, 0xd9, 0xc7, 0x39, 0xd5, 0x92, 0x0f, 0xe5, 0xf8},
		},
		{
			desc: "MultiplePCRBanks",
			alg:  HashAlgorithmSHA256,
			values: PCRValues{
				HashAlgorithmSHA1: {4: Digest{0xe2, 0x42, 0xed, 0x3b, 0xff, 0xcc, 0xdf, 0x27, 0x1b, 0x7f, 0xba, 0xf3, 0x4e, 0xd7, 0x2d, 0x08,
					0x95, 0x37, 0xb4, 0x2f}},
				HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96, 0xd7, 0x8d, 0xcc,
					0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}},
			},
			expectedPcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{4}},
				{Hash: HashAlgorithmSHA256, Select: []int{7}},
			},
			expectedDigest: Digest{0x80, 0x3f, 0xa6, 0x2e, 0x5e, 0x94, 0x5f, 0x59, 0xaf, 0x7d, 0x40, 0xa0, 0xe8, 0x02, 0x20, 0x1a, 0x5b, 0x03, 0x54,
				0x47, 0x2b, 0x4d, 0x72, 0x79, 0x28, 0x9d, 0x8a, 0x6d, 0x32, 0xfa, 0xbb, 0x6c},
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			values: PCRValues{HashAlgorithmSHA256: {7: Digest{0xb5, 0xbb, 0x9d, 0x80, 0x14, 0xa0, 0xf9, 0xb1, 0xd6, 0x1e, 0x21, 0xe7, 0x96,
				0xd7, 0x8d, 0xcc, 0xdf, 0x13, 0x52, 0xf2, 0x3c, 0xd3, 0x28, 0x12, 0xf4, 0x85, 0x0b, 0x87, 0x8a, 0xe4, 0x94, 0x4c}}},
			expectedPcrs: PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{7}}},
			expectedDigest: Digest{0x70, 0xb0, 0x87, 0x3f, 0x47, 0xf9, 0x61, 0xbb, 0xb8, 0x91, 0xcc, 0xee, 0x9f, 0x8a, 0x57, 0xaa, 0xcd, 0x16, 0x70,
				0x40},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcrs, digest, err := ComputePCRDigestSimple(data.alg, data.values)
			if err != nil {
				t.Fatalf("ComputePCRDigestSimple failed: %v", err)
			}
			if !bytes.Equal(digest, data.expectedDigest) {
				t.Errorf("Unexpected digest: %x", digest)
			}
			if !pcrs.Equal(data.expectedPcrs) {
				t.Errorf("Unexpected pcrs")
			}
		})
	}
}

func TestTrialPolicySigned(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	key := createAndLoadRSAPSSKeyForTesting(t, tpm, primary)
	defer flushContext(t, tpm, key)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			h := crypto.SHA256.New()
			binary.Write(h, binary.BigEndian, int32(0))
			h.Write(data.policyRef)
			aHash := h.Sum(nil)

			signature, err := tpm.Sign(key, aHash, nil, nil, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if _, _, err := tpm.PolicySigned(key, sessionContext, false, nil, data.policyRef, 0, signature); err != nil {
				t.Fatalf("PolicySigned failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicySigned(key.Name(), data.policyRef)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicySecret(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
	}{
		{
			desc: "NoPolicyRef",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: []byte("bar"),
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if _, _, err := tpm.PolicySecret(primary, sessionContext, nil, data.policyRef, 0, nil); err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicySecret(primary.Name(), data.policyRef)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyOR(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	digests := make(map[HashAlgorithmId]DigestList)
	for _, d := range []string{"foo", "bar", "xyz"} {
		for _, a := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
			if _, exists := digests[a]; !exists {
				digests[a] = make(DigestList, 0)
			}
			h := a.NewHash()
			h.Write([]byte(d))
			digests[a] = append(digests[a], h.Sum(nil))
		}
	}

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		pHashList DigestList
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
			pHashList: DigestList{
				digests[HashAlgorithmSHA256][0],
				digests[HashAlgorithmSHA256][2],
				digests[HashAlgorithmSHA256][1]},
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			pHashList: DigestList{
				digests[HashAlgorithmSHA1][1],
				digests[HashAlgorithmSHA1][0]},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyOR(sessionContext, data.pHashList); err != nil {
				t.Fatalf("PolicyOR failed: %v", err)
			}
			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			// Perform another assertion first to make sure that the PolicyOR resets the digest
			trial.PolicyPassword()
			if err := trial.PolicyOR(data.pHashList); err != nil {
				t.Errorf("PolicyOR failed: %v", err)
			}

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyPCR(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	digests := make(map[HashAlgorithmId]Digest)
	for _, a := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
		h := a.NewHash()
		h.Write([]byte("foo"))
		digests[a] = h.Sum(nil)
	}

	for _, data := range []struct {
		desc   string
		alg    HashAlgorithmId
		digest Digest
		pcrs   PCRSelectionList
	}{
		{
			desc:   "SHA256",
			alg:    HashAlgorithmSHA256,
			digest: digests[HashAlgorithmSHA256],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}},
		},
		{
			desc:   "SHA1",
			alg:    HashAlgorithmSHA1,
			digest: digests[HashAlgorithmSHA1],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{7, 8}}},
		},
		{
			desc:   "Mixed",
			alg:    HashAlgorithmSHA256,
			digest: digests[HashAlgorithmSHA256],
			pcrs: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{7, 8}},
				{Hash: HashAlgorithmSHA256, Select: []int{2, 4}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyPCR(sessionContext, data.digest, data.pcrs); err != nil {
				t.Fatalf("PolicyPCR failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyPCR(data.digest, data.pcrs)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyNV(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureNV)
	defer closeTPM(t, tpm)

	owner := tpm.OwnerHandleContext()

	nvPub := NVPublic{
		Index:   0x0181ffff,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   NVTypeOrdinary.WithAttrs(AttrNVAuthRead | AttrNVAuthWrite | AttrNVNoDA),
		Size:    64}
	index, err := tpm.NVDefineSpace(owner, nil, &nvPub, nil)
	if err != nil {
		t.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer undefineNVSpace(t, tpm, index, owner)

	twentyFiveUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(twentyFiveUint64, 25)

	tenUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(tenUint64, 10)

	fortyUint32 := make(Operand, 4)
	binary.BigEndian.PutUint32(fortyUint32, 40)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc:      "SHA256",
			alg:       HashAlgorithmSHA256,
			operandB:  tenUint64,
			offset:    0,
			operation: OpUnsignedLT,
		},
		{
			desc:      "SHA1",
			alg:       HashAlgorithmSHA1,
			operandB:  twentyFiveUint64,
			offset:    0,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Partial",
			alg:       HashAlgorithmSHA1,
			operandB:  fortyUint32,
			offset:    4,
			operation: OpUnsignedGE,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNV(index, index, sessionContext, data.operandB, data.offset, data.operation, nil); err != nil {
				t.Fatalf("PolicyNV failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNV(index.Name(), data.operandB, data.offset, data.operation)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyCounterTimer(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	uint64a := make(Operand, 8)
	binary.BigEndian.PutUint64(uint64a, 1603123)

	uint64b := make(Operand, 8)
	binary.BigEndian.PutUint64(uint64b, 6658125610)

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc:      "SHA256",
			alg:       HashAlgorithmSHA256,
			operandB:  uint64b,
			offset:    8,
			operation: OpUnsignedGT,
		},
		{
			desc:      "SHA1",
			alg:       HashAlgorithmSHA1,
			operandB:  uint64b,
			offset:    8,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Time",
			alg:       HashAlgorithmSHA256,
			operandB:  uint64a,
			offset:    0,
			operation: OpUnsignedGE,
		},
		{
			desc:      "Safe",
			alg:       HashAlgorithmSHA256,
			operandB:  Operand{0x01},
			offset:    24,
			operation: OpEq,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCounterTimer(sessionContext, data.operandB, data.offset, data.operation, nil); err != nil {
				t.Fatalf("PolicyCounterTimer failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCounterTimer(data.operandB, data.offset, data.operation)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}
func TestTrialPolicyCommandCode(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
		code CommandCode
	}{
		{
			desc: "Unseal",
			alg:  HashAlgorithmSHA256,
			code: CommandUnseal,
		},
		{
			desc: "NVChangeAuth",
			alg:  HashAlgorithmSHA256,
			code: CommandNVChangeAuth,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
			code: CommandUnseal,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCommandCode(sessionContext, data.code); err != nil {
				t.Fatalf("PolicyCommandCode failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCommandCode(data.code)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyCpHash(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			cpHashA := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyCpHash(sessionContext, cpHashA); err != nil {
				t.Fatalf("PolicyCpHash failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyCpHash(cpHashA)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyNameHash(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			nameHash := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNameHash(sessionContext, nameHash); err != nil {
				t.Fatalf("PolicyNameHash failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNameHash(nameHash)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyDuplicationSelect(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc          string
		alg           HashAlgorithmId
		includeObject bool
	}{
		{
			desc:          "SHA256",
			alg:           HashAlgorithmSHA256,
			includeObject: true,
		},
		{
			desc:          "NoIncludeObject",
			alg:           HashAlgorithmSHA256,
			includeObject: false,
		},
		{
			desc:          "SHA1",
			alg:           HashAlgorithmSHA1,
			includeObject: true,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			h := data.alg.NewHash()
			h.Write([]byte("12345"))
			objectName := h.Sum(nil)

			h = data.alg.NewHash()
			h.Write([]byte("67890"))
			newParentName := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyDuplicationSelect(sessionContext, objectName, newParentName, data.includeObject); err != nil {
				t.Fatalf("PolicyDuplicationSelect failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyDuplicationSelect(objectName, newParentName, data.includeObject)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyAuthorize(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	var keySignSHA1 Name
	var keySignSHA256 Name

	h := HashAlgorithmSHA1.NewHash()
	h.Write([]byte("foo"))
	keySignSHA1, _ = mu.MarshalToBytes(HashAlgorithmSHA1, mu.RawBytes(h.Sum(nil)))

	h = HashAlgorithmSHA256.NewHash()
	h.Write([]byte("foo"))
	keySignSHA256, _ = mu.MarshalToBytes(HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))

	for _, data := range []struct {
		desc      string
		alg       HashAlgorithmId
		policyRef Nonce
		keySign   Name
	}{
		{
			desc:    "SHA256",
			alg:     HashAlgorithmSHA256,
			keySign: keySignSHA256,
		},
		{
			desc:    "SHA1",
			alg:     HashAlgorithmSHA1,
			keySign: keySignSHA1,
		},
		{
			desc:      "WithPolicyRef",
			alg:       HashAlgorithmSHA256,
			policyRef: Nonce("bar"),
			keySign:   keySignSHA256,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyAuthorize(sessionContext, make(Digest, data.alg.Size()), data.policyRef, data.keySign, nil); err != nil {
				t.Fatalf("PolicyAuthorize failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyAuthorize(data.policyRef, data.keySign)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyAuthValue(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyAuthValue(sessionContext); err != nil {
				t.Fatalf("PolicyAuthValue failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyAuthValue()

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyPassword(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		alg  HashAlgorithmId
	}{
		{
			desc: "SHA256",
			alg:  HashAlgorithmSHA256,
		},
		{
			desc: "SHA1",
			alg:  HashAlgorithmSHA1,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyPassword(sessionContext); err != nil {
				t.Fatalf("PolicyPassword failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyPassword()

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestTrialPolicyNvWritten(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, 0)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc       string
		alg        HashAlgorithmId
		writtenSet bool
	}{
		{
			desc:       "SHA256/1",
			alg:        HashAlgorithmSHA256,
			writtenSet: true,
		},
		{
			desc:       "SHA1",
			alg:        HashAlgorithmSHA1,
			writtenSet: false,
		},
		{
			desc:       "SHA256/2",
			alg:        HashAlgorithmSHA256,
			writtenSet: false,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, data.alg)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNvWritten(sessionContext, data.writtenSet); err != nil {
				t.Fatalf("PolicyNvWritten failed: %v", err)
			}

			trial, err := ComputeAuthPolicy(data.alg)
			if err != nil {
				t.Fatalf("ComputeAuthPolicy failed: %v", err)
			}
			trial.PolicyNvWritten(data.writtenSet)

			tpmDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(tpmDigest, trial.GetDigest()) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}
