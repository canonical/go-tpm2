// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type computeSuite struct{}

var _ = Suite(&computeSuite{})

type testComputePolicyNVData struct {
	nvPub     *tpm2.NVPublic
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyNV(c *C, data *testComputePolicyNVData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNV(data.nvPub, data.operandB, data.offset, data.operation), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyNV(c *C) {
	s.testPolicyNV(c, &testComputePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:         0,
		operation:      tpm2.OpUnsignedLT,
		expectedDigest: internal_testutil.DecodeHexString(c, "aca835ee02ef5c2060c5b833ccee0ae9117321b162b10a9dd69b0cbc5b4b90d1")})
}

func (s *computeSuite) TestPolicyNVDifferentName(c *C) {
	s.testPolicyNV(c, &testComputePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:         0,
		operation:      tpm2.OpUnsignedLT,
		expectedDigest: internal_testutil.DecodeHexString(c, "5f38b62e654501aee4cc0c26c999cd16333c8695701eaff1f0f85b658f662f6d")})
}

func (s *computeSuite) TestPolicyNVDifferentOperand(c *C) {
	s.testPolicyNV(c, &testComputePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:       []byte{0x00, 0x00, 0x00, 0xff},
		offset:         0,
		operation:      tpm2.OpUnsignedLT,
		expectedDigest: internal_testutil.DecodeHexString(c, "e9cd39141ce8ce274dc491a10426b05bfe4e493b8ca583bd01d10aba60f8af02")})
}

func (s *computeSuite) TestPolicyNVDifferentOffset(c *C) {
	s.testPolicyNV(c, &testComputePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:       []byte{0x00, 0x10},
		offset:         6,
		operation:      tpm2.OpUnsignedLT,
		expectedDigest: internal_testutil.DecodeHexString(c, "718deb133fdb34530a37cfcc0c26f9552c5703bf56520e129aa73f5cd8621343")})
}

func (s *computeSuite) TestPolicyNVDifferentOperation(c *C) {
	s.testPolicyNV(c, &testComputePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:         0,
		operation:      tpm2.OpUnsignedGE,
		expectedDigest: internal_testutil.DecodeHexString(c, "f50564e250f80476c988180e87202c01fd52129abfea4f26eae04ac99641f735")})
}

type testComputePolicySecretData struct {
	authObjectName tpm2.Name
	policyRef      tpm2.Nonce

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicySecret(c *C, data *testComputePolicySecretData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(data.authObjectName, data.policyRef), IsNil)

	policy, err := builder.Policy()
	c.Check(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicySecret(c *C) {
	s.testPolicySecret(c, &testComputePolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		policyRef:      []byte("foo"),
		expectedDigest: internal_testutil.DecodeHexString(c, "62fd94980db2a746545cab626e9df21a1d0f00472f637d4bf567026e40a6ebed")})
}

func (s *computeSuite) TestPolicySecretNoPolicyRef(c *C) {
	s.testPolicySecret(c, &testComputePolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		expectedDigest: internal_testutil.DecodeHexString(c, "0d84f55daf6e43ac97966e62c9bb989d3397777d25c5f749868055d65394f952")})
}

func (s *computeSuite) TestPolicySecretDifferentAuthObject(c *C) {
	nv := tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	s.testPolicySecret(c, &testComputePolicySecretData{
		authObjectName: nv.Name(),
		policyRef:      []byte("foo"),
		expectedDigest: internal_testutil.DecodeHexString(c, "01e965ae5e8858d01355dd9f622b555c1acad6c0f839bb35e1d4bea18bb9837a")})
}

type testComputePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicySigned(c *C, data *testComputePolicySignedData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(data.authKey, data.policyRef), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicySigned(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicySigned(c, &testComputePolicySignedData{
		authKey:        pub,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "a427234d360e414f9abd854890b06734a84c3a5663e676ac3041e0d72988b741")})
}

func (s *computeSuite) TestPolicySignedDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicySigned(c, &testComputePolicySignedData{
		authKey:        pub,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "51fc047473eb0bd181b2c0f06de721e94756f14bf99722e5aee66785d1455f69")})
}

func (s *computeSuite) TestPolicySignedNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicySigned(c, &testComputePolicySignedData{
		authKey:        pub,
		expectedDigest: internal_testutil.DecodeHexString(c, "f6b5bdee979628699a12ebba3a7befbae9d5f1f69fed98db1a957c6ab3e8bf33")})
}

type testComputePolicyAuthorizeData struct {
	policyRef tpm2.Nonce
	keySign   *tpm2.Public

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyAuthorize(c *C, data *testComputePolicyAuthorizeData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthorize(data.policyRef, data.keySign), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyAuthorize(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testComputePolicyAuthorizeData{
		keySign:        pub,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "3e95800218d3f20c23f130503cd8c991dc662bd104ba85ab31519815f33fdc15")})
}

func (s *computeSuite) TestPolicyAuthorizeDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testComputePolicyAuthorizeData{
		keySign:        pub,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "903f9c07e5244f29fec17d24e266012ad41c509de509c39d5d953bccdb52f20e")})
}

func (s *computeSuite) TestPolicyAuthorizeNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	s.testPolicyAuthorize(c, &testComputePolicyAuthorizeData{
		keySign:        pub,
		expectedDigest: internal_testutil.DecodeHexString(c, "79eb5a0b041d2174a08c34c9207ae675aa7fdee856722e9eb85c885c09f0f959")})
}

func (s *computeSuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e")))
}

type testComputePolicyCommandCodeData struct {
	code           tpm2.CommandCode
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyCommandCode(c *C, data *testComputePolicyCommandCodeData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(data.code), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyCommandCode1(c *C) {
	s.testPolicyCommandCode(c, &testComputePolicyCommandCodeData{
		code:           tpm2.CommandNVChangeAuth,
		expectedDigest: internal_testutil.DecodeHexString(c, "445ed953601a045504550999bf2cbb2992cba2dbb5121bcf03869f65b50c26e5")})
}

func (s *computeSuite) TestPolicyCommandCode2(c *C) {
	s.testPolicyCommandCode(c, &testComputePolicyCommandCodeData{
		code:           tpm2.CommandDuplicate,
		expectedDigest: internal_testutil.DecodeHexString(c, "bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2")})
}

type testComputePolicyCounterTimerData struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyCounterTimer(c *C, data *testComputePolicyCounterTimerData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyCounterTimer(c *C) {
	s.testPolicyCounterTimer(c, &testComputePolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "038e1eee9e35e6991d98b4cff4d5a7c4eba13d9693238cdccc3dd11d776ddca9")})
}

func (s *computeSuite) TestPolicyCounterTimerDifferentOperand(c *C) {
	s.testPolicyCounterTimer(c, &testComputePolicyCounterTimerData{
		operandB:       []byte{0x00, 0x10, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "2c26c1612ea8733ee855e7d29707b7046ecb0a44073561dd45995e69a6b07a06")})
}

func (s *computeSuite) TestPolicyCounterTimerDifferentOffset(c *C) {
	s.testPolicyCounterTimer(c, &testComputePolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         16,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "50877e50def909d9e34dbade2459ddd88f0c7af1bd7198f6e5dd4fe5b28bb035")})
}

func (s *computeSuite) TestPolicyCounterTimerDifferentOperation(c *C) {
	s.testPolicyCounterTimer(c, &testComputePolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedLE,
		expectedDigest: internal_testutil.DecodeHexString(c, "7735b776359160ef57169e0e318da04102cf5eaf0bb316a1a3fe560e1c1a79e7")})
}

type testComputePolicyCpHashData struct {
	alg tpm2.HashAlgorithmId

	code    tpm2.CommandCode
	handles []Named
	params  []interface{}

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyCpHash(c *C, data *testComputePolicyCpHashData) {
	expectedCpHashA, err := ComputeCpHash(data.alg, data.code, data.handles, data.params...)
	c.Check(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(data.alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.alg, digest)},
		nil,
		NewMockPolicyCpHashElement(nil, expectedCpHashA),
	)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedDigest: internal_testutil.DecodeHexString(c, "79cefecd804486b13ac906b061a6d0faffacb46d7f387d91771b9455242de694")})
}

func (s *computeSuite) TestPolicyCpHashDifferentParams(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedDigest: internal_testutil.DecodeHexString(c, "801e24b6989cfea7a0ec1d885d21aa9311331443d7f21e1bbcb51675b0927475")})
}

func (s *computeSuite) TestPolicyCpHashDifferentHandles(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedDigest: internal_testutil.DecodeHexString(c, "62d74f265639e887956694eb36a4106228a08879ce1ade983cf0b28c2415acbb")})
}

func (s *computeSuite) TestPolicyCpHashSHA1(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA1,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedDigest: internal_testutil.DecodeHexString(c, "a59f3e6a358dee7edfd733373d7c8a9851296d26")})
}

func (s *computeSuite) TestPolicyCpHashMultipleDigests(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `policies that use TPM2_PolicyCpHash and TPM2_PolicyNameHash can't be computed for more than one digest algorithm`)
}

type testComputePolicyNameHashData struct {
	alg tpm2.HashAlgorithmId

	handles []Named

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyNameHash(c *C, data *testComputePolicyNameHashData) {
	expectedNameHash, err := ComputeNameHash(data.alg, data.handles...)
	c.Check(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(data.handles...), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(data.alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.alg, digest)},
		nil,
		NewMockPolicyNameHashElement(nil, expectedNameHash),
	)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyNameHash(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		handles:        []Named{tpm2.MakeHandleName(tpm2.HandleOwner)},
		expectedDigest: internal_testutil.DecodeHexString(c, "f46ca197c159be2500db41866e2713bd5e25cda9bbd46e2a398550010d7e5e5b")})
}

func (s *computeSuite) TestPolicyNameHashDifferentHandles(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		handles:        []Named{tpm2.MakeHandleName(tpm2.HandleEndorsement)},
		expectedDigest: internal_testutil.DecodeHexString(c, "3e3fbf3b3c59ba10ae0f02c691ceb60ba87fd7463c4100c1bb85c143e24e6eab")})
}

func (s *computeSuite) TestPolicyNameHashSHA1(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		alg:            tpm2.HashAlgorithmSHA1,
		handles:        []Named{tpm2.MakeHandleName(tpm2.HandleOwner)},
		expectedDigest: internal_testutil.DecodeHexString(c, "022794dd35419f458603c2c11808dced821078d2")})
}

func (s *computeSuite) TestPolicyNameHashMultipleDigests(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(tpm2.MakeHandleName(tpm2.HandleOwner)), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `policies that use TPM2_PolicyCpHash and TPM2_PolicyNameHash can't be computed for more than one digest algorithm`)
}

type testComputePolicyPCRData struct {
	values         tpm2.PCRValues
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyPCR(c *C, data *testComputePolicyPCRData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(data.values), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyPCR(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testComputePolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: foo,
				7: bar}},
		expectedDigest: internal_testutil.DecodeHexString(c, "5dedc710ee0e797130756bd024372dfa9a9e3fc5b5c60897304fdda88ec2b887")})
}

func (s *computeSuite) TestPolicyPCRDifferentDigest(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testComputePolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: bar,
				7: foo}},
		expectedDigest: internal_testutil.DecodeHexString(c, "463dc37a6f3a37d7125524a2e6047c4befa650cdbb53369615503ca422f10da1")})
}

func (s *computeSuite) TestPolicyPCRDifferentDigestAndSelection(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testComputePolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo,
				7: bar}},
		expectedDigest: internal_testutil.DecodeHexString(c, "52ec898cf6a800715e9314c90ba91636970ceeea6416bf2da62b5e633480aa43")})
}

func (s *computeSuite) TestPolicyPCRMultipleBanks(c *C) {
	// Make sure that a selection with multiple banks always produces the same value
	// (the selection is sorted correctly)
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testComputePolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo},
			tpm2.HashAlgorithmSHA256: {
				7: bar}},
		expectedDigest: internal_testutil.DecodeHexString(c, "5079c1d53de12dd44e988d5b0a31cd30701ffb24b7bd5d5b68d5f9f5819163be")})
}

type testComputePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyDuplicationSelect(c *C, data *testComputePolicyDuplicationSelectData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testComputePolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "d3b51a457e1ffc76592514a9c754c7111bbb49c872e11a61cb4ae14acd384b4e")})
}

func (s *computeSuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testComputePolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  false,
		expectedDigest: internal_testutil.DecodeHexString(c, "a9ceacb309fb05bdc45784f0647641bcd2f3a05a10ed94c5525413c7da33234e")})
}

func (s *computeSuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testComputePolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "df247a269a89dc38ac8d2065abee11d094b66a6b6a7ce984a3d937c584adcebc")})
}

func (s *computeSuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPassword(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e")))
}

type testComputePolicyNvWrittenData struct {
	writtenSet     bool
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyNvWritten(c *C, data *testComputePolicyNvWrittenData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(data.writtenSet), IsNil)

	policy, err := builder.Policy()
	c.Check(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *computeSuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, &testComputePolicyNvWrittenData{
		writtenSet:     false,
		expectedDigest: internal_testutil.DecodeHexString(c, "3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e")})
}

func (s *computeSuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, &testComputePolicyNvWrittenData{
		writtenSet:     true,
		expectedDigest: internal_testutil.DecodeHexString(c, "f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb")})
}

func (s *computeSuite) TestPolicyMixed(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "426df7ddd07dbfaa400237f773da801e464ef2766084966b04d8b4dfc0feeee5")))
}

func (s *computeSuite) TestPolicyMixedSHA1(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	digest, err := policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "abdce83ab50f4d5fd378181e21de9486559612d3")))
}

func (s *computeSuite) TestPolicyBranches(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList tpm2.DigestList

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	initialDigest := TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial := NewComputePolicySession(&initialDigest)
	c.Check(trial.PolicyOR(pHashList), IsNil)
	c.Check(policy.ComputeForDigest(&initialDigest), IsNil)
	expectedDigest := initialDigest.Digest

	// Now build a profile with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err = builder.Policy()
	c.Assert(err, IsNil)

	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, digest)},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList[0])},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList[1])},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyBranchesMultipleDigests(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashListSHA1 tpm2.DigestList
	var pHashListSHA256 tpm2.DigestList

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	expectedDigests := []TaggedHash{
		{HashAlg: tpm2.HashAlgorithmSHA1, Digest: make(tpm2.Digest, 20)},
		{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)},
	}
	trial := NewComputePolicySession(&expectedDigests[0])
	c.Check(trial.PolicyOR(pHashListSHA1), IsNil)
	c.Check(policy.ComputeForDigest(&expectedDigests[0]), IsNil)
	trial = NewComputePolicySession(&expectedDigests[1])
	c.Check(trial.PolicyOR(pHashListSHA256), IsNil)
	c.Check(policy.ComputeForDigest(&expectedDigests[1]), IsNil)

	// Now build a profile with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err = builder.Policy()
	c.Assert(err, IsNil)

	digestSHA1, err := policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digestSHA1, DeepEquals, expectedDigests[0].Digest)
	digestSHA256, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digestSHA256, DeepEquals, expectedDigests[1].Digest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, digestSHA1),
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, digestSHA256),
		},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, pHashListSHA1[0]),
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashListSHA256[0]),
				},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, pHashListSHA1[1]),
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashListSHA256[1]),
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyBranchesMultipleNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList1 tpm2.DigestList

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList1 = append(pHashList1, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList1 = append(pHashList1, digest)

	var pHashList2 tpm2.DigestList

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	initialDigest := TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial := NewComputePolicySession(&initialDigest)
	c.Check(trial.PolicyOR(pHashList1), IsNil)
	c.Check(policy.ComputeForDigest(&initialDigest), IsNil)
	pHashList2 = append(pHashList2, initialDigest.Digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	initialDigest = TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial = NewComputePolicySession(&initialDigest)
	c.Check(trial.PolicyOR(pHashList1), IsNil)
	c.Check(policy.ComputeForDigest(&initialDigest), IsNil)
	pHashList2 = append(pHashList2, initialDigest.Digest)

	expectedDigest := TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial = NewComputePolicySession(&expectedDigest)
	c.Check(trial.PolicyOR(pHashList2), IsNil)

	// Now build a profile with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("branch4")
	c.Check(b4.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	policy, err = builder.Policy()
	c.Assert(err, IsNil)

	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest.Digest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, digest)},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList1[0]),
				},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList1[1]),
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch3", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList2[0]),
				},
				NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
			),
			NewMockPolicyBranch(
				"branch4", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList2[1]),
				},
				NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
			),
		),
	)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyBranchesEmbeddedNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList2 tpm2.DigestList

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList2 = append(pHashList2, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList2 = append(pHashList2, digest)

	var pHashList3 tpm2.DigestList

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList3 = append(pHashList3, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	policy, err = builder.Policy()
	c.Assert(err, IsNil)
	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	pHashList3 = append(pHashList3, digest)

	var pHashList1 tpm2.DigestList

	initialDigest := TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial := NewComputePolicySession(&initialDigest)
	c.Check(trial.PolicyOR(pHashList2), IsNil)
	pHashList1 = append(pHashList1, initialDigest.Digest)

	initialDigest = TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial = NewComputePolicySession(&initialDigest)
	c.Check(trial.PolicyOR(pHashList3), IsNil)
	pHashList1 = append(pHashList1, initialDigest.Digest)

	expectedDigest := TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: make(tpm2.Digest, 32)}
	trial = NewComputePolicySession(&expectedDigest)
	c.Check(trial.PolicyOR(pHashList1), IsNil)

	// Now build a profile with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	node2 := b1.AddBranchNode()

	b2 := node2.AddBranch("branch2")
	c.Check(b2.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	b4 := node1.AddBranch("branch4")
	c.Check(b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node3 := b4.AddBranchNode()

	b5 := node3.AddBranch("branch5")
	c.Check(b5.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b6 := node3.AddBranch("branch6")
	c.Check(b6.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	policy, err = builder.Policy()
	c.Assert(err, IsNil)

	digest, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest.Digest)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, digest)},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList1[0]),
				},
				NewMockPolicyAuthValueElement(),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch2", tpm2.TaggedHashList{
							tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList2[0]),
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch3", tpm2.TaggedHashList{
							tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList2[1]),
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
					),
				),
			),
			NewMockPolicyBranch(
				"branch4", tpm2.TaggedHashList{
					tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList1[1]),
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch5", tpm2.TaggedHashList{
							tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList3[0]),
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch6", tpm2.TaggedHashList{
							tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, pHashList3[1]),
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
					),
				),
			),
		),
	)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

type mockSessionContext struct {
	session tpm2.SessionContext
	closed  bool
}

func (c *mockSessionContext) Session() tpm2.SessionContext {
	return c.session
}

func (c *mockSessionContext) Flush() error {
	c.closed = true
	return nil
}

type mockAuthorizer struct {
	authorizeFn func(tpm2.ResourceContext) error
}

func (h *mockAuthorizer) Authorize(resource tpm2.ResourceContext) error {
	if h.authorizeFn == nil {
		return nil
	}
	return h.authorizeFn(resource)
}

type mockSignedAuthorizer struct {
	signAuthorization func(tpm2.Nonce, tpm2.Name, tpm2.Nonce) (*PolicySignedAuthorization, error)
}

func (h *mockSignedAuthorizer) SignedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	if h.signAuthorization == nil {
		return nil, errors.New("not implemented")
	}
	return h.signAuthorization(sessionNonce, authKey, policyRef)
}

type policySuiteNoTPM struct{}

var _ = Suite(&policySuiteNoTPM{})

func (s *policySuiteNoTPM) testMarshalUnmarshalPolicyBranchName(c *C, name PolicyBranchName, expected []byte) {
	b, err := mu.MarshalToBytes(name)
	c.Check(err, IsNil)
	c.Check(b, DeepEquals, expected)

	var recoveredName PolicyBranchName
	_, err = mu.UnmarshalFromBytes(b, &recoveredName)
	c.Check(recoveredName, Equals, name)
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName1(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "foo", []byte{0x00, 0x03, 0x66, 0x6f, 0x6f})
}

func (s *policySuiteNoTPM) TestMarshalUnmarshalPolicyBranchName2(c *C) {
	s.testMarshalUnmarshalPolicyBranchName(c, "bar", []byte{0x00, 0x03, 0x62, 0x61, 0x72})
}

func (s *policySuiteNoTPM) TestMarshalInvalidPolicyBranchName(c *C) {
	_, err := mu.MarshalToBytes(PolicyBranchName("$foo"))
	c.Check(err, ErrorMatches, `cannot marshal argument 0 whilst processing element of type policyutil.policyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestUnmarshalInvalidPolicyBranchName(c *C) {
	var name PolicyBranchName
	_, err := mu.UnmarshalFromBytes([]byte{0x00, 0x04, 0x24, 0x66, 0x6f, 0x6f}, &name)
	c.Check(err, ErrorMatches, `cannot unmarshal argument 0 whilst processing element of type policyutil.policyBranchName: invalid name`)
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponent(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLeadingSeparator(c *C) {
	path := PolicyBranchPath("foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentLast(c *C) {
	path := PolicyBranchPath("bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("bar"))
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentEmpty(c *C) {
	path := PolicyBranchPath("")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath(""))
	c.Check(remaining, Equals, PolicyBranchPath(""))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleLeadingSeparators(c *C) {
	path := PolicyBranchPath("///foo/bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("bar"))
}

func (s *policySuiteNoTPM) TestPolicyBranchPathPopNextComponentMultipleIntermediateSeparators(c *C) {
	path := PolicyBranchPath("foo////bar")
	next, remaining := path.PopNextComponent()
	c.Check(next, Equals, PolicyBranchPath("foo"))
	c.Check(remaining, Equals, PolicyBranchPath("///bar"))
}

type testAuthorizePolicyData struct {
	keyPEM            string
	nameAlg           tpm2.HashAlgorithmId
	policyRef         tpm2.Nonce
	opts              crypto.SignerOpts
	expectedDigest    tpm2.Digest
	expectedSignature *tpm2.Signature
}

func (s *policySuiteNoTPM) testAuthorizePolicy(c *C, data *testAuthorizePolicyData) error {
	b, _ := pem.Decode([]byte(data.keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, internal_testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	keySign, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey, objectutil.WithNameAlg(data.nameAlg))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	err = policy.Authorize(bytes.NewReader(make([]byte, 33)), keySign, data.policyRef, key.(crypto.Signer), data.opts)
	if err != nil {
		return err
	}

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.nameAlg, data.expectedDigest)},
		[]PolicyAuthorization{{AuthKey: keySign, PolicyRef: data.policyRef, Signature: data.expectedSignature}},
		NewMockPolicyAuthValueElement(),
	)
	c.Check(policy, DeepEquals, expectedPolicy)

	return nil
}

func (s *policySuiteNoTPM) TestAuthorizePolicy(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.MakeSignatureUnion(
				tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "fef27905ea5b0265ed72649b518c9dc34d9d729214fb65106b25188acdb0aa09"),
					SignatureS: internal_testutil.DecodeHexString(c, "55e8e6eb6bc688e16225539019ae82d6eba0ac9db61974d366f72a4d4c125ae4"),
				},
			),
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyDifferentKey(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgt7gAWQPrRPLVAexX
QO8Bog5Fu2sw+s+CVU1V41vVj4mhRANCAARij+FNq0+rxvdl+gIJPxY4nqMezDdo
c7C9ElAfzkjURTxVWrFldXF9M8kCdot7wNuLeWnIJL7p5y2A43mu4mOb
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.MakeSignatureUnion(
				tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "4ac10b34ab032a57fd2e430eadc31dedde61462cc8fa40ff6b13515abdb2b416"),
					SignatureS: internal_testutil.DecodeHexString(c, "3dbd37dbcb7b731c21505e919c003d23c8084e6c6ec0dfaa7b2a3341ec920514"),
				},
			),
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyNoPolicyRef(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA256,
		opts:           crypto.SHA256,
		expectedDigest: internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.MakeSignatureUnion(
				tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA256,
					SignatureR: internal_testutil.DecodeHexString(c, "5743fafc980e7dead11954e19ba3a0440f06fa0cd6eb2fbebc24a136834d392f"),
					SignatureS: internal_testutil.DecodeHexString(c, "8a0da89b7e1bd9cc56b21cb4b686b54d102d319186eeb819e2d70f80cf14d115"),
				},
			),
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyDifferentAlgorithm(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		keyPEM:         keyPEM,
		nameAlg:        tpm2.HashAlgorithmSHA1,
		policyRef:      []byte("foo"),
		opts:           crypto.SHA1,
		expectedDigest: internal_testutil.DecodeHexString(c, "af6038c78c5c962d37127e319124e3a8dc582e9b"),
		expectedSignature: &tpm2.Signature{
			SigAlg: tpm2.SigSchemeAlgECDSA,
			Signature: tpm2.MakeSignatureUnion(
				tpm2.SignatureECDSA{
					Hash:       tpm2.HashAlgorithmSHA1,
					SignatureR: internal_testutil.DecodeHexString(c, "039dfb9e7b2ab5546fe8c47c8ddfc20a966fae87397bfdb1f7007e2db971f603"),
					SignatureS: internal_testutil.DecodeHexString(c, "cf61bdfff0ddf9edce5a2ebb53f3910b88c9406cb35bb5a117fb149b2550250c"),
				},
			),
		},
	})
	c.Check(err, IsNil)
}

func (s *policySuiteNoTPM) TestAuthorizePolicyInvalidParams(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	err := s.testAuthorizePolicy(c, &testAuthorizePolicyData{
		keyPEM:    keyPEM,
		nameAlg:   tpm2.HashAlgorithmSHA256,
		policyRef: []byte("foo"),
		opts:      crypto.SHA1,
	})
	c.Check(err, ErrorMatches, `mismatched authKey name and opts`)
}

func (s *policySuiteNoTPM) TestPolicyValidate(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateWithBranches(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateWithMultipleBranchNodes(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("")
	c.Check(b4.PolicyCommandCode(tpm2.CommandObjectChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	digest, err := policy.Validate(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyValidateMissingBranches(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	_, err = policy.Validate(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)
}

func (s *policySuiteNoTPM) TestPolicyBranches(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches()
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{""})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithBranches(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches()
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1", "branch2"})
}

func (s *policySuiteNoTPM) TestPolicyBranchesWithMultipleBranchNodes(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("")
	c.Check(b4.PolicyCommandCode(tpm2.CommandObjectChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	branches, err := policy.Branches()
	c.Check(err, IsNil)
	c.Check(branches, DeepEquals, []string{"branch1/branch3", "branch1/$[1]", "branch2/branch3", "branch2/$[1]"})
}

func (s *policySuiteNoTPM) TestPolicyDigest1(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, Equals, ErrMissingDigest)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyDigest2(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVRead), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, Equals, ErrMissingDigest)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuiteNoTPM) TestPolicyDigestSHA1(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, Equals, ErrMissingDigest)

	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)

	digest, err := policy.Digest(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type policySuite struct {
	testutil.TPMTest
}

func (s *policySuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&policySuite{})

type testExecutePolicyNVData struct {
	nvPub      *tpm2.NVPublic
	readAuth   tpm2.ResourceContext
	readPolicy *Policy
	contents   []byte

	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp

	expectedCommands    int
	expectedAuthorize   bool
	expectedSessionType tpm2.HandleType
}

func (s *policySuite) testPolicyNV(c *C, data *testExecutePolicyNVData) error {
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, data.nvPub)
	c.Assert(s.TPM.NVWrite(index, index, data.contents, 0, nil), IsNil)

	readAuth := data.readAuth
	if readAuth == nil {
		readAuth = index
	}

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNV(nvPub, data.operandB, data.offset, data.operation), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var resources *PolicyResourcesData
	if data.readPolicy != nil {
		resources = &PolicyResourcesData{
			Persistent: []PersistentResource{
				{Name: readAuth.Name(), Handle: readAuth.Handle(), Policy: data.readPolicy},
			},
		}
	}

	authorized := false
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			authorized = true
			if !data.expectedAuthorize {
				resource.SetAuthValue([]byte("1234"))
			} else {
				c.Check(resource.Name(), DeepEquals, readAuth.Name())
			}
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, resources, authorizer, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	c.Check(authorized, Equals, data.expectedAuthorize)

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-2]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicyNV)
	_, authArea, _ := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyNV(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperand(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001001"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOffset(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000010000000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              2,
		operation:           tpm2.OpEq,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVDifferentOperation(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		contents:            internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpUnsignedGT,
		expectedCommands:    6,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVFails(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:             nvPub,
		contents:          internal_testutil.DecodeHexString(c, "0000000000001001"),
		operandB:          internal_testutil.DecodeHexString(c, "00001000"),
		offset:            4,
		operation:         tpm2.OpEq,
		expectedAuthorize: true,
	})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var e *tpm2.TPMError
	c.Assert(ne, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorPolicy})
}

func (s *policySuite) TestPolicyNVDifferentAuth(c *C) {
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVOwnerRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		readAuth:            s.TPM.OwnerHandleContext(),
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    5,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithPolicySession(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithPolicySessionRequiresAuth(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    8,
		expectedAuthorize:   true,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVMissingPolicy(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	err := s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:     nvPub,
		contents:  internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:  internal_testutil.DecodeHexString(c, "00001000"),
		offset:    4,
		operation: tpm2.OpEq})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`TPM returned an error whilst executing command TPM_CC_PolicyNV: TPM_RC_AUTH_UNAVAILABLE \(authValue or authPolicy is not available for selected entity\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var e *tpm2.TPMError
	c.Assert(ne, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyNV, Code: tpm2.ErrorAuthUnavailable})
}

func (s *policySuite) TestPolicyNVPrefersPolicySession(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandPolicyNV), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:      s.NextAvailableHandle(c, 0x0181f000),
			NameAlg:    tpm2.HashAlgorithmSHA256,
			Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			AuthPolicy: policyDigest,
			Size:       8},
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyNVWithSubPolicyError(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), nil), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	err = s.testPolicyNV(c, &testExecutePolicyNVData{
		nvPub:               nvPub,
		readPolicy:          policy,
		contents:            internal_testutil.DecodeHexString(c, "0000000000001000"),
		operandB:            internal_testutil.DecodeHexString(c, "00001000"),
		offset:              4,
		operation:           tpm2.OpEq,
		expectedCommands:    7,
		expectedAuthorize:   false,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyNV assertion' task in root branch: `+
		`cannot complete assertion with NV index 0x([[:xdigit:]]{8}) \(name: 0x([[:xdigit:]]{68})\): `+
		`cannot authorize resource with name 0x([[:xdigit:]]{68}): `+
		`cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x40000001, policyRef=: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ne *PolicyNVError
	c.Assert(pe, internal_testutil.ErrorAs, &ne)
	c.Check(ne.Index, Equals, nvPub.Index)
	nvPub.Attrs |= tpm2.AttrNVWritten
	c.Check(ne.Name, DeepEquals, nvPub.Name())

	var rae *ResourceAuthorizeError
	c.Assert(ne, internal_testutil.ErrorAs, &rae)
	c.Check(rae.Name, DeepEquals, nvPub.Name())

	c.Assert(rae, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var se *tpm2.TPMSessionError
	c.Assert(pe, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

type testExecutePolicySecretData struct {
	authObject Named
	policyRef  tpm2.Nonce
	resources  *PolicyResourcesData

	expectedFlush       bool
	expectedCommands    int
	expectedSessionType tpm2.HandleType
}

func (s *policySuite) testPolicySecret(c *C, data *testExecutePolicySecretData) error {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(data.authObject, data.policyRef), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	var authObjectHandle tpm2.Handle
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, data.authObject.Name())
			authObjectHandle = resource.Handle()
			return nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, data.resources, authorizer, nil), nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	c.Check(authObjectHandle, Not(Equals), tpm2.Handle(0))

	offsetEnd := 2
	if data.expectedFlush {
		offsetEnd++
	}

	commands := s.CommandLog()

	c.Assert(commands, internal_testutil.LenEquals, data.expectedCommands)
	policyCommand := commands[len(commands)-offsetEnd]
	c.Check(policyCommand.GetCommandCode(c), Equals, tpm2.CommandPolicySecret)
	_, authArea, cpBytes := policyCommand.UnmarshalCommand(c)
	c.Assert(authArea, internal_testutil.LenEquals, 1)
	c.Check(authArea[0].SessionHandle.Type(), Equals, data.expectedSessionType)
	c.Check(s.TPM.DoesHandleExist(authArea[0].SessionHandle), internal_testutil.IsFalse)
	c.Check(s.TPM.DoesSavedSessionExist(authArea[0].SessionHandle), internal_testutil.IsFalse)

	var nonceTPM tpm2.Nonce
	var cpHashA tpm2.Digest
	var policyRef tpm2.Nonce
	var expiration int32
	_, err = mu.UnmarshalFromBytes(cpBytes, &nonceTPM, &cpHashA, &policyRef, &expiration)
	c.Check(err, IsNil)
	c.Check(cpHashA, DeepEquals, tpm2.Digest(nil))
	c.Check(expiration, Equals, int32(0))

	if data.expectedFlush {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsFalse)
	} else {
		c.Check(s.TPM.DoesHandleExist(authObjectHandle), internal_testutil.IsTrue)
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicySecret(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		policyRef:           []byte("foo"),
		expectedCommands:    5,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretNoPolicyRef(c *C) {
	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          s.TPM.OwnerHandleContext(),
		expectedCommands:    5,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithWithTransient(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandLoad), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)

	template := testutil.NewRSAStorageKeyTemplate()
	template.AuthPolicy = policyDigest

	parent := s.CreatePrimary(c, tpm2.HandleOwner, template)
	persistent := s.NextAvailableHandle(c, 0x81000008)
	s.EvictControl(c, tpm2.HandleOwner, parent, persistent)

	priv, pub, _, _, _, err := s.TPM.Create(parent, nil, testutil.NewRSAStorageKeyTemplate(), nil, nil, nil)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: pub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   parent.Name(),
					Handle: persistent,
					Policy: policy,
				},
			},
			Transient: []TransientResource{
				{
					ParentName: parent.Name(),
					Private:    priv,
					Public:     pub,
				},
			},
		},
		expectedFlush:       true,
		expectedCommands:    13,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretFail(c *C) {
	s.TPM.OwnerHandleContext().SetAuthValue([]byte("1234"))

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: s.TPM.OwnerHandleContext(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x40000001, policyRef=0x666f6f: `+
		`TPM returned an error for session 1 whilst executing command TPM_CC_PolicySecret: TPM_RC_BAD_AUTH \(authorization failure without DA implications\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, s.TPM.OwnerHandleContext().Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMSessionError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMSessionError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorBadAuth}, Index: 1})
}

func (s *policySuite) TestPolicySecretMissingResource(c *C) {
	object := s.CreateStoragePrimaryKeyRSA(c)

	err := s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: object.Name(),
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: cannot load resource with name 0x([[:xdigit:]]{68}): resource not found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, object.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var rle *ResourceLoadError
	c.Check(err, internal_testutil.ErrorAs, &rle)
	c.Check(rle.Name, DeepEquals, object.Name())
}

func (s *policySuite) TestPolicySecretWithNV(c *C) {
	nvPub := &tpm2.NVPublic{
		Index:   s.NextAvailableHandle(c, 0x0181f000),
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		Size:    8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err := s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject:          nvPub,
		policyRef:           []byte("foo"),
		expectedCommands:    9,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVPolicySession(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    8,
		expectedSessionType: tpm2.HandleTypePolicySession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVPreferHMACSession(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo"),
		resources: &PolicyResourcesData{
			Persistent: []PersistentResource{
				{
					Name:   nvPub.Name(),
					Handle: nvPub.Index,
					Policy: policy,
				},
			},
		},
		expectedCommands:    7,
		expectedSessionType: tpm2.HandleTypeHMACSession})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySecretWithNVMissingPolicySession(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	policyDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: policyDigest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0}, 0, nil), IsNil)

	nvPub, _, err = s.TPM.NVReadPublic(index)
	c.Assert(err, IsNil)

	err = s.testPolicySecret(c, &testExecutePolicySecretData{
		authObject: nvPub,
		policyRef:  []byte("foo")})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySecret assertion' task in root branch: `+
		`cannot complete authorization with authName=0x000b2ce1bec1b93901ee1e39517612a216fe496c26fa595fd5cf4149ff8f225e6aa9, policyRef=0x666f6f: `+
		`TPM returned an error whilst executing command TPM_CC_PolicySecret: TPM_RC_AUTH_UNAVAILABLE \(authValue or authPolicy is not available for selected entity\)`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, nvPub.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var te *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &te)
	c.Check(te, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicySecret, Code: tpm2.ErrorAuthUnavailable})
}

type testExecutePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	signer          crypto.Signer
	includeNonceTPM bool
	cpHashA         CpHash
	expiration      int32
	signerOpts      crypto.SignerOpts
}

func (s *policySuite) testPolicySigned(c *C, data *testExecutePolicySignedData) error {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(data.authKey, data.policyRef), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionNonce, DeepEquals, session.NonceTPM())
			c.Check(authKey, DeepEquals, data.authKey.Name())
			c.Check(policyRef, DeepEquals, data.policyRef)

			auth, err := NewPolicySignedAuthorization(session.HashAlg(), sessionNonce, data.cpHashA, data.expiration)
			c.Assert(err, IsNil)
			c.Check(auth.Sign(rand.Reader, data.authKey, policyRef, data.signer, data.signerOpts), IsNil)

			return auth, nil
		},
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, nil, nil, authorizer), nil)
	if err != nil {
		return err
	}
	if data.expiration < 0 && err == nil {
		expectedCpHash, err := data.cpHashA.Digest(session.HashAlg())
		c.Check(err, IsNil)

		c.Assert(result.NewTickets, internal_testutil.LenEquals, 1)
		c.Check(result.NewTickets[0].AuthName, DeepEquals, data.authKey.Name())
		c.Check(result.NewTickets[0].PolicyRef, DeepEquals, data.policyRef)
		c.Check(result.NewTickets[0].CpHash, DeepEquals, expectedCpHash)
		c.Check(result.NewTickets[0].Ticket.Tag, Equals, tpm2.TagAuthSigned)
		c.Check(result.NewTickets[0].Ticket.Hierarchy, Equals, tpm2.HandleOwner)
	} else {
		c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	}
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicySigned(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:         pubKey,
		signer:          key,
		includeNonceTPM: true,
		signerOpts:      tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedIncludeTPMNonce(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithCpHash(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithExpiration(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		expiration: 100,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithRequestedTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		cpHashA:    CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expiration: -100,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicySignedWithInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	err = s.testPolicySigned(c, &testExecutePolicySignedData{
		authKey:    pubKey,
		policyRef:  []byte("foo"),
		signer:     key,
		signerOpts: tpm2.HashAlgorithmSHA256})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicySigned assertion' task in root branch: `+
		`cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 5 whilst executing command TPM_CC_PolicySigned: TPM_RC_SIGNATURE \(the signature is not valid\)`)
	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var se *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &se)
	c.Check(se, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicySigned, Code: tpm2.ErrorSignature}, Index: 5})
}

func (s *policySuite) TestPolicySignedWithTicket(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	authKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(authKey, nil), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	authorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionNonce tpm2.Nonce, authKeyName tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			c.Check(sessionNonce, DeepEquals, session.NonceTPM())
			c.Check(authKeyName, DeepEquals, authKey.Name())
			c.Check(policyRef, IsNil)

			auth, err := NewPolicySignedAuthorization(session.HashAlg(), sessionNonce, nil, -100)
			c.Assert(err, IsNil)
			c.Check(auth.Sign(rand.Reader, authKey, policyRef, key, tpm2.HashAlgorithmSHA256), IsNil)

			return auth, nil
		},
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, nil, nil, authorizer), nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 1)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	c.Check(s.TPM.PolicyRestart(session), IsNil)

	params := &PolicyExecuteParams{Tickets: result.NewTickets}

	result, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyAuthorizeData struct {
	keySign                  *tpm2.Public
	policyRef                tpm2.Nonce
	authorizedPolicies       []*Policy
	path                     string
	expectedRequireAuthValue bool
	expectedPath             string
}

func (s *policySuite) testPolicyAuthorize(c *C, data *testExecutePolicyAuthorizeData) error {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthorize(data.policyRef, data.keySign), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	expectedDigest, err := policy.Compute(data.keySign.Name().Algorithm())
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: data.path,
	}
	resources := &PolicyResourcesData{
		AuthorizedPolicies: data.authorizedPolicies,
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, resources, new(mockAuthorizer), nil), params)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyAuthorize(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	approvedPolicy, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizeWithNoPolicyRef(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, nil, key, crypto.SHA256), IsNil)

	approvedPolicy, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		authorizedPolicies:       []*Policy{policy},
		expectedRequireAuthValue: true,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizePolicyNotFound(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("bar"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x626172: no policies`)

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("bar"))
}

func (s *policySuite) TestPolicyAuthorizeInvalidSignature(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:            pubKey,
		policyRef:          []byte("foo"),
		authorizedPolicies: []*Policy{policy}})
	c.Check(err, ErrorMatches, `cannot run 'authorized policy' task in root branch: cannot complete authorization with authName=0x([[:xdigit:]]{68}), policyRef=0x666f6f: `+
		`TPM returned an error for parameter 2 whilst executing command TPM_CC_VerifySignature: TPM_RC_SIGNATURE \(the signature is not valid\)`)

	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandVerifySignature, Code: tpm2.ErrorSignature}, Index: 2})

	var ae *PolicyAuthorizationError
	c.Assert(err, internal_testutil.ErrorAs, &ae)
	c.Check(ae.AuthName, DeepEquals, pubKey.Name())
	c.Check(ae.PolicyRef, DeepEquals, tpm2.Nonce("foo"))

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) testPolicyAuthorizeWithSubPolicyBranches(c *C, path string, expectedRequireAuthValue bool, expectedPath string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	c.Check(policy.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	approvedPolicy, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy},
		path:                     path,
		expectedRequireAuthValue: expectedRequireAuthValue,
		expectedPath:             strings.Join([]string{fmt.Sprintf("%x", approvedPolicy), expectedPath}, "/"),
	})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthorizeWithSubPolicyBranches(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "", true, "branch1")
}

func (s *policySuite) TestPolicyAuthorizeWithSubPolicyBranchesExplicitPath(c *C) {
	s.testPolicyAuthorizeWithSubPolicyBranches(c, "*/branch2", false, "branch2")
}

func (s *policySuite) TestPolicyAuthorizeWithMultiplePolicies(c *C) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	c.Check(builder.RootBranch().PolicyPCR(values), IsNil)
	policy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy1.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	_, values, err = s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0}}})
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(values), IsNil)
	policy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(policy2.Authorize(rand.Reader, pubKey, []byte("foo"), key, crypto.SHA256), IsNil)

	approvedPolicy, err := policy2.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	err = s.testPolicyAuthorize(c, &testExecutePolicyAuthorizeData{
		keySign:                  pubKey,
		policyRef:                []byte("foo"),
		authorizedPolicies:       []*Policy{policy1, policy2},
		expectedRequireAuthValue: false,
		expectedPath:             fmt.Sprintf("%x", approvedPolicy)})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyAuthValue)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) testPolicyCommandCode(c *C, code tpm2.CommandCode) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(code), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCommandCodeNVChangeAuth(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandNVChangeAuth)
}

func (s *policySuite) TestPolicyCommandCodeUnseal(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandUnseal)
}

type testExecutePolicyCounterTimerData struct {
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyCounterTimer(c *C, data *testExecutePolicyCounterTimerData) error {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyCounterTimer1(c *C) {
	c.Skip("test fails in github")

	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedGT})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimer2(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint32(0)))
	binary.BigEndian.PutUint32(operandB, timeInfo.ClockInfo.RestartCount)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    20,
		operation: tpm2.OpEq})
	c.Check(err, IsNil)
}

func (s *policySuite) TestPolicyCounterTimerFails(c *C) {
	timeInfo, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	operandB := make(tpm2.Operand, binary.Size(uint64(0)))
	binary.BigEndian.PutUint64(operandB, timeInfo.ClockInfo.Clock)

	err = s.testPolicyCounterTimer(c, &testExecutePolicyCounterTimerData{
		operandB:  operandB,
		offset:    8,
		operation: tpm2.OpUnsignedLT})
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyCounterTimer assertion' task in root branch: TPM returned an error whilst executing command TPM_CC_PolicyCounterTimer: TPM_RC_POLICY \(policy failure in math operation or an invalid authPolicy value\)`)
	var e *tpm2.TPMError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMError{Command: tpm2.CommandPolicyCounterTimer, Code: tpm2.ErrorPolicy})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyCpHashData struct {
	code    tpm2.CommandCode
	handles []Named
	params  []interface{}
}

func (s *policySuite) testPolicyCpHash(c *C, data *testExecutePolicyCpHashData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCpHash1(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policySuite) TestPolicyCpHash2(c *C) {
	s.testPolicyCpHash(c, &testExecutePolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *policySuite) testPolicyNameHash(c *C, handles ...Named) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(handles...), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Check(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNameHash1(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x01})
}

func (s *policySuite) TestPolicyNameHash2(c *C) {
	s.testPolicyNameHash(c, tpm2.Name{0x40, 0x00, 0x00, 0x0b})
}

type testExecutePolicyBranchesData struct {
	usage                    *PolicySessionUsage
	path                     string
	ignoreAuthorizations     []PolicyAuthorizationID
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
}

func (s *policySuite) testPolicyBranches(c *C, data *testExecutePolicyBranchesData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c.Assert(err, IsNil)

	pubKey, err := objectutil.NewECCPublicKey(&key.PublicKey)
	c.Assert(err, IsNil)

	b3 := node.AddBranch("branch3")
	c.Check(b3.PolicySigned(pubKey, []byte("bar")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage:                data.usage,
		Path:                 data.path,
		IgnoreAuthorizations: data.ignoreAuthorizations,
	}
	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}
	signedAuthorizer := &mockSignedAuthorizer{
		signAuthorization: func(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
			auth, err := NewPolicySignedAuthorization(session.HashAlg(), nil, nil, 0)
			c.Assert(err, IsNil)
			c.Check(auth.Sign(rand.Reader, pubKey, policyRef, key, crypto.SHA256), IsNil)

			return auth, nil
		},
	}

	s.ForgetCommands()

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, nil, authorizer, signedAuthorizer), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		c.Check(log[i].GetCommandCode(c), Equals, data.expectedCommands[i])
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranches(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchesNumericSelector(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "$[0]",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchesDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchesNumericSelectorDifferentBranchIndex(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		path: "$[1]",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchAutoSelectNoUsage(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsage1(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsage2(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")).NoAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2"})
}

func (s *policySuite) TestPolicyBranchAutoSelectWithUsageAndIgnore(c *C) {
	s.testPolicyBranches(c, &testExecutePolicyBranchesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")).NoAuthValue(),
		ignoreAuthorizations: []PolicyAuthorizationID{
			{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
		},
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandLoadExternal,
			tpm2.CommandPolicySigned,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch3"})
}

func (s *policySuite) TestPolicyBranchesMultipleDigests(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "branch1")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

type testExecutePolicyBranchesMultipleNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesMultipleNodes(c *C, data *testExecutePolicyBranchesMultipleNodesData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := builder.RootBranch().AddBranchNode()

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("branch4")
	c.Check(b4.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, nil, authorizer, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesMultipleNodes1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesNumericSelectors(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "$[0]/$[0]",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodes3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch2/branch4",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...), append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...), append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}).NoAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "branch2",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...), append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "*/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")).NoAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch2/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesMultipleNodesAutoSelectWildcard3(c *C) {
	s.testPolicyBranchesMultipleNodes(c, &testExecutePolicyBranchesMultipleNodesData{
		path:  "**/branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch4",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

type testExecutePolicyBranchesEmbeddedNodesData struct {
	usage                    *PolicySessionUsage
	path                     string
	expectedCommands         tpm2.CommandCodeList
	expectedRequireAuthValue bool
	expectedPath             string
	expectedCommandCode      tpm2.CommandCode
}

func (s *policySuite) testPolicyBranchesEmbeddedNodes(c *C, data *testExecutePolicyBranchesEmbeddedNodesData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()

	b1 := node1.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	node2 := b1.AddBranchNode()

	b2 := node2.AddBranch("branch2")
	c.Check(b2.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	b4 := node1.AddBranch("branch4")
	c.Check(b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node3 := b4.AddBranchNode()

	b5 := node3.AddBranch("branch5")
	c.Check(b5.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b6 := node3.AddBranch("branch6")
	c.Check(b6.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Usage: data.usage,
		Path:  data.path,
	}

	authorizer := &mockAuthorizer{
		authorizeFn: func(resource tpm2.ResourceContext) error {
			c.Check(resource.Name(), DeepEquals, tpm2.MakeHandleName(tpm2.HandleOwner))
			return nil
		},
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, nil, authorizer, nil), params)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, Equals, data.expectedRequireAuthValue)
	c.Check(result.Path, Equals, data.expectedPath)

	log := s.CommandLog()
	c.Assert(log, internal_testutil.LenEquals, len(data.expectedCommands))
	for i := range log {
		code := log[i].GetCommandCode(c)
		c.Check(code, Equals, data.expectedCommands[i])
		if code == tpm2.CommandPolicyCommandCode {
			_, _, cpBytes := log[i].UnmarshalCommand(c)

			var commandCode tpm2.CommandCode
			_, err = mu.UnmarshalFromBytes(cpBytes, &commandCode)
			c.Check(err, IsNil)
			c.Check(commandCode, Equals, data.expectedCommandCode)
		}
	}

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch2",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesNumericSelectors(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "$[0]/$[0]",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1/branch3",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch5",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodes4(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch4/branch6",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneNoUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path: "branch1",
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectOneWithUsage(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "branch4",
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...), append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch2",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVWriteLock, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...), append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWithUsage3(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")).NoAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch5",
		expectedCommandCode:      tpm2.CommandNVChangeAuth})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard1(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch3",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandPolicyAuthValue,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: true,
		expectedPath:             "branch1/branch3",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesEmbeddedNodesAutoSelectWildcard2(c *C) {
	s.testPolicyBranchesEmbeddedNodes(c, &testExecutePolicyBranchesEmbeddedNodesData{
		path:  "*/branch6",
		usage: NewPolicySessionUsage(tpm2.CommandNVChangeAuth, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}, tpm2.Auth("foo")).NoAuthValue(),
		expectedCommands: tpm2.CommandCodeList{
			tpm2.CommandPolicyNvWritten,
			tpm2.CommandContextSave,
			tpm2.CommandStartAuthSession,
			tpm2.CommandContextLoad,
			tpm2.CommandPolicySecret,
			tpm2.CommandFlushContext,
			tpm2.CommandPolicyCommandCode,
			tpm2.CommandPolicyOR,
			tpm2.CommandPolicyOR,
		},
		expectedRequireAuthValue: false,
		expectedPath:             "branch4/branch6",
		expectedCommandCode:      tpm2.CommandNVWriteLock})
}

func (s *policySuite) TestPolicyBranchesSelectorOutOfRange(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "$[2]",
	}

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: selected path 2 out of range`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesInvalidSelector(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "$foo",
	}

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: badly formatted path component "\$foo": input does not match format`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesBranchNotFound(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "foo",
	}

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot select branch: no branch with name "foo"`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) TestPolicyBranchesComputeMissingBranchDigests(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	params := &PolicyExecuteParams{
		Path: "branch1",
	}

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, params)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: missing digest for session algorithm`)
	c.Check(err, internal_testutil.ErrorIs, ErrMissingDigest)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

func (s *policySuite) testPolicyPCR(c *C, values tpm2.PCRValues) error {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(values), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	if err != nil {
		return err
	}
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	return nil
}

func (s *policySuite) TestPolicyPCR(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{4, 7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRDifferentDigestAndSelection(c *C) {
	_, values, err := s.TPM.PCRRead(tpm2.PCRSelectionList{
		{Hash: tpm2.HashAlgorithmSHA1, Select: []int{4}},
		{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7}}})
	c.Assert(err, IsNil)

	c.Check(s.testPolicyPCR(c, values), IsNil)
}

func (s *policySuite) TestPolicyPCRFails(c *C) {
	values := tpm2.PCRValues{
		tpm2.HashAlgorithmSHA256: {
			0: internal_testutil.DecodeHexString(c, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")}}
	err := s.testPolicyPCR(c, values)
	c.Check(err, ErrorMatches, `cannot run 'TPM2_PolicyPCR assertion' task in root branch: TPM returned an error for parameter 1 whilst executing command TPM_CC_PolicyPCR: TPM_RC_VALUE \(value is out of range or is not correct for the context\)`)
	var e *tpm2.TPMParameterError
	c.Assert(err, internal_testutil.ErrorAs, &e)
	c.Check(e, DeepEquals, &tpm2.TPMParameterError{TPMError: &tpm2.TPMError{Command: tpm2.CommandPolicyPCR, Code: tpm2.ErrorValue}, Index: 1})

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type testExecutePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool
}

func (s *policySuite) testPolicyDuplicationSelect(c *C, data *testExecutePolicyDuplicationSelectData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: false})
}

func (s *policySuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testExecutePolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *policySuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPassword(), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(result.Path, Equals, "")

	// TPM2_PolicyPassword and TPM2_PolicyAuthValue have the same digest, so make sure
	// we executed the correct command.
	c.Check(s.LastCommand(c).GetCommandCode(c), Equals, tpm2.CommandPolicyPassword)

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) testPolicyNvWritten(c *C, writtenSet bool) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(writtenSet), IsNil)
	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, false)
}

func (s *policySuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, true)
}

func (s *policySuiteNoTPM) TestPolicyDetails(c *C) {
	builder := NewPolicyBuilder()

	nvPub := &tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	c.Check(builder.RootBranch().PolicyNV(nvPub, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, 0, tpm2.OpUnsignedLT), IsNil)

	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	pub, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)
	c.Check(builder.RootBranch().PolicySigned(pub, []byte("bar")), IsNil)

	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandUnseal), IsNil)
	c.Check(builder.RootBranch().PolicyCounterTimer([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}, 0, tpm2.OpUnsignedLT), IsNil)
	c.Check(builder.RootBranch().PolicyCpHash(tpm2.CommandUnseal, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}), IsNil)

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: foo, 7: bar}}
	c.Check(builder.RootBranch().PolicyPCR(pcrValues), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)

	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, "")
	c.Assert(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, exists := details[""]
	c.Assert(exists, internal_testutil.IsTrue)

	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.NV, DeepEquals, []PolicyNVDetails{
		{Auth: nvPub.Index, Index: nvPub.Index, Name: nvPub.Name(), OperandB: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, Offset: 0, Operation: tpm2.OpUnsignedLT},
	})
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})
	c.Check(bd.Signed, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("bar")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandUnseal)

	c.Check(bd.CounterTimer, DeepEquals, []PolicyCounterTimerDetails{
		{OperandB: []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}, Offset: 0, Operation: tpm2.OpUnsignedLT},
	})

	cpHash, set := bd.CpHash()
	c.Check(set, internal_testutil.IsTrue)
	expectedCpHash, err := ComputeCpHash(tpm2.HashAlgorithmSHA256, tpm2.CommandUnseal, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)})
	c.Check(err, IsNil)
	c.Check(cpHash, DeepEquals, expectedCpHash)

	_, set = bd.NameHash()
	c.Check(set, internal_testutil.IsFalse)

	expectedPcrs, expectedPcrDigest, err := ComputePCRDigestFromAllValues(tpm2.HashAlgorithmSHA256, pcrValues)
	c.Check(err, IsNil)
	c.Check(bd.PCR, DeepEquals, []PolicyPCRDetails{{PCRDigest: expectedPcrDigest, PCRs: expectedPcrs}})

	_, set = bd.NvWritten()
	c.Check(set, internal_testutil.IsFalse)

}

func (s *policySuiteNoTPM) testPolicyDetailsWithBranches(c *C, path string) map[string]PolicyBranchDetails {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("branch1")
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, path)
	c.Assert(err, IsNil)
	return details
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithBranches(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "")
	c.Check(details, internal_testutil.LenEquals, 2)

	bd, exists := details["branch1"]
	c.Assert(exists, internal_testutil.IsTrue)

	nvWrittenSet, set := bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(bd.Secret, internal_testutil.LenEquals, 0)

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)

	bd, exists = details["branch2"]
	c.Assert(exists, internal_testutil.IsTrue)

	nvWrittenSet, set = bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})

	code, set = bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
}

func (s *policySuiteNoTPM) TestPolicyDetailsWithBranches2(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "branch2")
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, exists := details["branch2"]
	c.Assert(exists, internal_testutil.IsTrue)

	nvWrittenSet, set := bd.NvWritten()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(nvWrittenSet, internal_testutil.IsTrue)

	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("foo")},
	})

	code, set := bd.CommandCode()
	c.Check(set, internal_testutil.IsTrue)
	c.Check(code, Equals, tpm2.CommandNVChangeAuth)
}

func (s *policySuite) TestPolicyBranchesNVAutoSelected(c *C) {
	builder := NewPolicyBuilder()
	node := builder.RootBranch().AddBranchNode()
	b1 := node.AddBranch("")
	c.Check(b1.PolicyCommandCode(tpm2.CommandNVRead), IsNil)
	b2 := node.AddBranch("")
	c.Check(b2.PolicyCommandCode(tpm2.CommandPolicyNV), IsNil)
	nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := nvPolicy.Compute(tpm2.HashAlgorithmSHA256)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder()
	node = builder.RootBranch().AddBranchNode()
	b1 = node.AddBranch("")
	c.Check(b1.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq), IsNil)
	b2 = node.AddBranch("")
	c.Check(b2.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpEq), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, resources, nil, nil), nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "$[1]")

	digest, err = s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyBranchesNVAutoSelectedFail(c *C) {
	builder := NewPolicyBuilder()
	node := builder.RootBranch().AddBranchNode()
	b1 := node.AddBranch("")
	c.Check(b1.PolicyCommandCode(tpm2.CommandNVRead), IsNil)
	b2 := node.AddBranch("")
	c.Check(b2.PolicyCommandCode(tpm2.CommandPolicyNV), IsNil)
	nvPolicy, err := builder.Policy()
	c.Assert(err, IsNil)
	digest, err := nvPolicy.Compute(tpm2.HashAlgorithmSHA256)

	nvPub := &tpm2.NVPublic{
		Index:      s.NextAvailableHandle(c, 0x0181f000),
		NameAlg:    tpm2.HashAlgorithmSHA256,
		Attrs:      tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVPolicyRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
		AuthPolicy: digest,
		Size:       8}
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, nvPub)
	c.Assert(s.TPM.NVWrite(index, index, []byte{0, 0, 0, 0, 0, 0, 0, 0}, 0, nil), IsNil)

	nvPub.Attrs |= tpm2.AttrNVWritten

	builder = NewPolicyBuilder()
	node = builder.RootBranch().AddBranchNode()
	b1 = node.AddBranch("")
	c.Check(b1.PolicyNV(nvPub, []byte{0}, 0, tpm2.OpNeq), IsNil)
	b2 = node.AddBranch("")
	c.Check(b2.PolicyNV(nvPub, []byte{0}, 10, tpm2.OpEq), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	resources := &PolicyResourcesData{
		Persistent: []PersistentResource{
			{
				Name:   nvPub.Name(),
				Handle: nvPub.Index,
				Policy: nvPolicy,
			},
		},
	}

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, NewTPMPolicyResources(s.TPM, resources, nil, nil), nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}

type policySuitePCR struct {
	testutil.TPMTest
}

func (s *policySuitePCR) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV | testutil.TPMFeaturePCR
}

var _ = Suite(&policySuitePCR{})

func (s *policySuitePCR) TestPolicyBranchesAutoSelected(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	c.Check(b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}}), IsNil)

	b2 := node.AddBranch("")
	c.Check(b2.PolicyPCR(pcrValues), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	expectedDigest, err := policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	result, err := policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Assert(err, IsNil)
	c.Check(result.NewTickets, internal_testutil.LenEquals, 0)
	c.Check(result.InvalidTickets, internal_testutil.LenEquals, 0)
	c.Check(result.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(result.Path, Equals, "$[1]")

	digest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *policySuitePCR) TestPolicyBranchesAutoSelectFail(c *C) {
	_, err := s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	_, pcrValues, err := s.TPM.PCRRead(tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{7, 23}}})
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()

	node := builder.RootBranch().AddBranchNode()

	b1 := node.AddBranch("")
	c.Check(b1.PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: map[int]tpm2.Digest{7: pcrValues[tpm2.HashAlgorithmSHA256][7], 23: make(tpm2.Digest, 32)}}), IsNil)

	b2 := node.AddBranch("")
	c.Check(b2.PolicyPCR(pcrValues), IsNil)

	policy, err := builder.Policy()
	c.Assert(err, IsNil)
	_, err = policy.Compute(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)

	_, err = s.TPM.PCREvent(s.TPM.PCRHandleContext(23), []byte("foo"), nil)
	c.Check(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypePolicy, nil, tpm2.HashAlgorithmSHA256)

	_, err = policy.Execute(NewTPMConnection(s.TPM), session, nil, nil)
	c.Check(err, ErrorMatches, `cannot run 'branch node' task in root branch: cannot automatically select branch: no appropriate paths found`)

	var pe *PolicyError
	c.Assert(err, internal_testutil.ErrorAs, &pe)
	c.Check(pe.Path, Equals, "")
}
