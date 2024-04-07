// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	_ "crypto/sha1"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
	"github.com/canonical/go-tpm2/testutil"
)

type builderSuite struct{}

var _ = Suite(&builderSuite{})

type testBuildPolicyNVData struct {
	nvPub          *tpm2.NVPublic
	operandB       tpm2.Operand
	offset         uint16
	operation      tpm2.ArithmeticOp
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyNV(c *C, data *testBuildPolicyNVData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNV(data.nvPub, data.operandB, data.offset, data.operation), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyNVElement(data.nvPub, data.operandB, data.offset, data.operation))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNV(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
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

func (s *builderSuite) TestPolicyNVDifferentName(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
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

func (s *builderSuite) TestPolicyNVDifferentOperand(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
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

func (s *builderSuite) TestPolicyNVDifferentOffset(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
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

func (s *builderSuite) TestPolicyNVDifferentOperation(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
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

type testBuildPolicySecretData struct {
	authObjectName tpm2.Name
	policyRef      tpm2.Nonce
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicySecret(c *C, data *testBuildPolicySecretData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(data.authObjectName, data.policyRef), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicySecretElement(data.authObjectName, data.policyRef))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicySecret(c *C) {
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		policyRef:      []byte("foo"),
		expectedDigest: internal_testutil.DecodeHexString(c, "62fd94980db2a746545cab626e9df21a1d0f00472f637d4bf567026e40a6ebed")})
}

func (s *builderSuite) TestPolicySecretNoPolicyRef(c *C) {
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		expectedDigest: internal_testutil.DecodeHexString(c, "0d84f55daf6e43ac97966e62c9bb989d3397777d25c5f749868055d65394f952")})
}

func (s *builderSuite) TestPolicySecretDifferentAuthObject(c *C) {
	nv := tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: nv.Name(),
		policyRef:      []byte("foo"),
		expectedDigest: internal_testutil.DecodeHexString(c, "01e965ae5e8858d01355dd9f622b555c1acad6c0f839bb35e1d4bea18bb9837a")})
}

func (s *builderSuite) TestPolicySecretInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.Name{0, 0}, nil), ErrorMatches, `invalid authObject name`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicySecret: invalid authObject name`)
}

type testBuildPolicySignedData struct {
	pubKeyPEM      string
	policyRef      tpm2.Nonce
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicySigned(c *C, data *testBuildPolicySignedData) {
	b, _ := pem.Decode([]byte(data.pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	authKey, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(authKey, data.policyRef), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicySignedElement(authKey, data.policyRef))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicySigned(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM:      pubKeyPEM,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "a427234d360e414f9abd854890b06734a84c3a5663e676ac3041e0d72988b741")})
}

func (s *builderSuite) TestPolicySignedDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM:      pubKeyPEM,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "51fc047473eb0bd181b2c0f06de721e94756f14bf99722e5aee66785d1455f69")})
}

func (s *builderSuite) TestPolicySignedNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM:      pubKeyPEM,
		expectedDigest: internal_testutil.DecodeHexString(c, "f6b5bdee979628699a12ebba3a7befbae9d5f1f69fed98db1a957c6ab3e8bf33")})
}

func (s *builderSuite) TestPolicySignedInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(new(tpm2.Public), nil), ErrorMatches, `invalid authKey`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicySigned: invalid authKey`)
}

type testBuildPolicyAuthorizeData struct {
	pubKeyPEM      string
	policyRef      tpm2.Nonce
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyAuthorize(c *C, data *testBuildPolicyAuthorizeData) {
	b, _ := pem.Decode([]byte(data.pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	keySign, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthorize(data.policyRef, keySign), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyAuthorizeElement(data.policyRef, keySign))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyAuthorize(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM:      pubKeyPEM,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "3e95800218d3f20c23f130503cd8c991dc662bd104ba85ab31519815f33fdc15")})
}

func (s *builderSuite) TestPolicyAuthorizeDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM:      pubKeyPEM,
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "903f9c07e5244f29fec17d24e266012ad41c509de509c39d5d953bccdb52f20e")})
}

func (s *builderSuite) TestPolicyAuthorizeNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM:      pubKeyPEM,
		expectedDigest: internal_testutil.DecodeHexString(c, "79eb5a0b041d2174a08c34c9207ae675aa7fdee856722e9eb85c885c09f0f959")})
}

func (s *builderSuite) TestPolicyAuthorizeInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthorize(nil, new(tpm2.Public)), ErrorMatches, `invalid keySign`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyAuthorize: invalid keySign`)
}

func (s *builderSuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
		NewMockPolicyAuthValueElement())

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

type testBuildPolicyCommandCodeData struct {
	code           tpm2.CommandCode
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyCommandCode(c *C, data *testBuildPolicyCommandCodeData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(data.code), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyCommandCodeElement(data.code))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCommandCode1(c *C) {
	s.testPolicyCommandCode(c, &testBuildPolicyCommandCodeData{
		code:           tpm2.CommandNVChangeAuth,
		expectedDigest: internal_testutil.DecodeHexString(c, "445ed953601a045504550999bf2cbb2992cba2dbb5121bcf03869f65b50c26e5")})
}

func (s *builderSuite) TestPolicyCommandCode2(c *C) {
	s.testPolicyCommandCode(c, &testBuildPolicyCommandCodeData{
		code:           tpm2.CommandDuplicate,
		expectedDigest: internal_testutil.DecodeHexString(c, "bef56b8c1cc84e11edd717528d2cd99356bd2bbf8f015209c3f84aeeaba8e8a2")})
}

type testBuildPolicyCounterTimerData struct {
	operandB       tpm2.Operand
	offset         uint16
	operation      tpm2.ArithmeticOp
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyCounterTimer(c *C, data *testBuildPolicyCounterTimerData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyCounterTimerElement(data.operandB, data.offset, data.operation))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCounterTimer(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "038e1eee9e35e6991d98b4cff4d5a7c4eba13d9693238cdccc3dd11d776ddca9")})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOperand(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:       []byte{0x00, 0x10, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "2c26c1612ea8733ee855e7d29707b7046ecb0a44073561dd45995e69a6b07a06")})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOffset(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         16,
		operation:      tpm2.OpUnsignedGT,
		expectedDigest: internal_testutil.DecodeHexString(c, "50877e50def909d9e34dbade2459ddd88f0c7af1bd7198f6e5dd4fe5b28bb035")})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOperation(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:       []byte{0x00, 0x00, 0xff, 0xff},
		offset:         4,
		operation:      tpm2.OpUnsignedLE,
		expectedDigest: internal_testutil.DecodeHexString(c, "7735b776359160ef57169e0e318da04102cf5eaf0bb316a1a3fe560e1c1a79e7")})
}

type testBuildPolicyCpHashData struct {
	alg            tpm2.HashAlgorithmId
	code           tpm2.CommandCode
	handles        []Named
	params         []interface{}
	expectedCpHash tpm2.Digest
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyCpHash(c *C, data *testBuildPolicyCpHashData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.alg, data.expectedDigest)}, nil,
		NewMockPolicyCpHashElement(data.expectedCpHash))

	digest, policy, err := builder.Build(data.alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "0d5c70236d9181ea6b26fb203d8a45bbb3d982926d6cf4ba60ce0fe5d5717ac3"),
		expectedDigest: internal_testutil.DecodeHexString(c, "79cefecd804486b13ac906b061a6d0faffacb46d7f387d91771b9455242de694")})
}

func (s *builderSuite) TestPolicyCpHashDifferentParams(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "15fc1d7283e0f5f864651602c55f1d1dbebf7e573850bfae5235e94df0ac1fa1"),
		expectedDigest: internal_testutil.DecodeHexString(c, "801e24b6989cfea7a0ec1d885d21aa9311331443d7f21e1bbcb51675b0927475")})
}

func (s *builderSuite) TestPolicyCpHashDifferentHandles(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "4facb677c43722471af5c535353911e4882d26aa58f4859562b6861476f4aca3"),
		expectedDigest: internal_testutil.DecodeHexString(c, "62d74f265639e887956694eb36a4106228a08879ce1ade983cf0b28c2415acbb")})
}

func (s *builderSuite) TestPolicyCpHashDifferentCommand(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoadExternal,
		params:         []interface{}{mu.MakeSizedSource((*tpm2.Sensitive)(nil)), mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate()), tpm2.HandleOwner},
		expectedCpHash: internal_testutil.DecodeHexString(c, "bcbfc6e1846a7f58ed0c05ddf8a0ce7e2b3a50ba3f04e3ac87ee8c940a360f46"),
		expectedDigest: internal_testutil.DecodeHexString(c, "f3d3c11955dd8dc8b45c6b66961cd929bc62a0fd263f5d7336139f30a166f011")})
}

func (s *builderSuite) TestPolicyCpHashSHA1(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA1,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "d98ba8350f71c34132f62f50a6b9f21c4fa54f75"),
		expectedDigest: internal_testutil.DecodeHexString(c, "a59f3e6a358dee7edfd733373d7c8a9851296d26")})
}

func (s *builderSuite) TestPolicyCpHashInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(tpm2.CommandLoad, []Named{tpm2.Name{0, 0}}, tpm2.Private{1, 2, 3, 4}, mu.MakeSizedSource(objectutil.NewRSAStorageKeyTemplate())), ErrorMatches,
		`invalid name at handle 0`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyCpHash: invalid name at handle 0`)
}

type testBuildPolicyNameHashData struct {
	alg              tpm2.HashAlgorithmId
	handles          []Named
	expectedNameHash tpm2.Digest
	expectedDigest   tpm2.Digest
}

func (s *builderSuite) testPolicyNameHash(c *C, data *testBuildPolicyNameHashData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(data.handles...), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.alg, data.expectedDigest)}, nil,
		NewMockPolicyNameHashElement(data.expectedNameHash))

	digest, policy, err := builder.Build(data.alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNameHash(c *C) {
	s.testPolicyNameHash(c, &testBuildPolicyNameHashData{
		alg:              tpm2.HashAlgorithmSHA256,
		handles:          []Named{tpm2.MakeHandleName(tpm2.HandleOwner)},
		expectedNameHash: internal_testutil.DecodeHexString(c, "16a3d3b482bb480394dfac704038a3708db2a77ccaa80ca419e91122406599ec"),
		expectedDigest:   internal_testutil.DecodeHexString(c, "f46ca197c159be2500db41866e2713bd5e25cda9bbd46e2a398550010d7e5e5b")})
}

func (s *builderSuite) TestPolicyNameHashDifferentHandles(c *C) {
	s.testPolicyNameHash(c, &testBuildPolicyNameHashData{
		alg:              tpm2.HashAlgorithmSHA256,
		handles:          []Named{tpm2.MakeHandleName(tpm2.HandleEndorsement)},
		expectedNameHash: internal_testutil.DecodeHexString(c, "c791c5d6c902890a3b91af630b09bc5b04cbe7cc6385708771f25aa6cb334ae3"),
		expectedDigest:   internal_testutil.DecodeHexString(c, "3e3fbf3b3c59ba10ae0f02c691ceb60ba87fd7463c4100c1bb85c143e24e6eab")})
}

func (s *builderSuite) TestPolicyNameHashSHA1(c *C) {
	s.testPolicyNameHash(c, &testBuildPolicyNameHashData{
		alg:              tpm2.HashAlgorithmSHA1,
		handles:          []Named{tpm2.MakeHandleName(tpm2.HandleOwner)},
		expectedNameHash: internal_testutil.DecodeHexString(c, "97d538cbfae3f530b934596ea99c19a9b5c06d03"),
		expectedDigest:   internal_testutil.DecodeHexString(c, "022794dd35419f458603c2c11808dced821078d2")})
}

func (s *builderSuite) TestPolicyNameHashInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(tpm2.Name{0, 0}), ErrorMatches, `invalid name at handle 0`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyNameHash: invalid name at handle 0`)
}

type testBuildPolicyPCRData struct {
	alg            tpm2.HashAlgorithmId
	values         tpm2.PCRValues
	expectedPcrs   PcrValueList
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyPCR(c *C, data *testBuildPolicyPCRData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(data.values), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(data.alg, data.expectedDigest)}, nil,
		NewMockPolicyPCRElement(data.expectedPcrs))

	digest, policy, err := builder.Build(data.alg)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyPCR(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		alg: tpm2.HashAlgorithmSHA256,
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: foo,
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)}},
		expectedDigest: internal_testutil.DecodeHexString(c, "5dedc710ee0e797130756bd024372dfa9a9e3fc5b5c60897304fdda88ec2b887")})
}

func (s *builderSuite) TestPolicyPCRDifferentDigests(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		alg: tpm2.HashAlgorithmSHA256,
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: bar,
				7: foo}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, foo)}},
		expectedDigest: internal_testutil.DecodeHexString(c, "463dc37a6f3a37d7125524a2e6047c4befa650cdbb53369615503ca422f10da1")})
}

func (s *builderSuite) TestPolicyPCRDifferentSelection(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		alg: tpm2.HashAlgorithmSHA256,
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo,
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, bar)}},
		expectedDigest: internal_testutil.DecodeHexString(c, "52ec898cf6a800715e9314c90ba91636970ceeea6416bf2da62b5e633480aa43")})
}

func (s *builderSuite) TestPolicyPCRMultipleBanks(c *C) {
	// Make sure that a selection with multiple banks always produces the same value
	// (the selection is sorted correctly)
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		alg: tpm2.HashAlgorithmSHA256,
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo},
			tpm2.HashAlgorithmSHA256: {
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)}},
		expectedDigest: internal_testutil.DecodeHexString(c, "5079c1d53de12dd44e988d5b0a31cd30701ffb24b7bd5d5b68d5f9f5819163be")})
}

func (s *builderSuite) TestPolicyPCRDifferentAlg(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		alg: tpm2.HashAlgorithmSHA1,
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: foo,
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)}},
		expectedDigest: internal_testutil.DecodeHexString(c, "45e5111828cf66c6c7f805f4e9691f6236892514")})
}

func (s *builderSuite) TestPolicyPCRInvalidBank(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmNull: {4: nil}}), ErrorMatches, `invalid digest algorithm TPM_ALG_NULL`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest algorithm TPM_ALG_NULL`)
}

func (s *builderSuite) TestPolicyPCRInvalidDigest(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: []byte{0}}}), ErrorMatches, `invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
}

func (s *builderSuite) TestPolicyPCRInvalidPCR(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {-1: make([]byte, 32)}}), ErrorMatches, `invalid PCR -1: invalid PCR index \(< 0\)`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid PCR -1: invalid PCR index \(< 0\)`)
}

type testBuildPolicyDuplicationSelectData struct {
	object         Named
	newParent      Named
	includeObject  bool
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyDuplicationSelect(c *C, data *testBuildPolicyDuplicationSelectData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyDuplicationSelectElement(data.object.Name(), data.newParent.Name(), data.includeObject))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "d3b51a457e1ffc76592514a9c754c7111bbb49c872e11a61cb4ae14acd384b4e")})
}

func (s *builderSuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  false,
		expectedDigest: internal_testutil.DecodeHexString(c, "a9ceacb309fb05bdc45784f0647641bcd2f3a05a10ed94c5525413c7da33234e")})
}

func (s *builderSuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.MakeRaw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "df247a269a89dc38ac8d2065abee11d094b66a6b6a7ce984a3d937c584adcebc")})
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidNewParentName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(nil, tpm2.Name{0, 0}, false), ErrorMatches, `invalid newParent name`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid newParent name`)
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidObjectName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(tpm2.Name{0, 0}, nil, true), ErrorMatches, `invalid object name`)
	_, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid object name`)
}

func (s *builderSuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPassword(), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
		NewMockPolicyPasswordElement())

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

type testBuildPolicyNvWrittenData struct {
	writtenSet     bool
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyNvWritten(c *C, data *testBuildPolicyNvWrittenData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(data.writtenSet), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, data.expectedDigest)}, nil,
		NewMockPolicyNvWrittenElement(data.writtenSet))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, &testBuildPolicyNvWrittenData{
		writtenSet:     false,
		expectedDigest: internal_testutil.DecodeHexString(c, "3c326323670e28ad37bd57f63b4cc34d26ab205ef22f275c58d47fab2485466e")})
}

func (s *builderSuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, &testBuildPolicyNvWrittenData{
		writtenSet:     true,
		expectedDigest: internal_testutil.DecodeHexString(c, "f7887d158ae8d38be0ac5319f37a9e07618bf54885453c7a54ddb0c6a6193beb")})
}

func (s *builderSuite) TestModifyFailedBranch(c *C) {
	// XXX: Note that this only tests one method - this should be expanded to test all
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(tpm2.Name{0, 0}), ErrorMatches, `invalid name at handle 0`)
	c.Check(builder.RootBranch().PolicyAuthValue(), ErrorMatches, `encountered an error when calling PolicyNameHash: invalid name at handle 0`)
}

func (s *builderSuite) TestPolicyMixed(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "426df7ddd07dbfaa400237f773da801e464ef2766084966b04d8b4dfc0feeee5"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyMixedSHA1(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "abdce83ab50f4d5fd378181e21de9486559612d3"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, expectedDigest)}, nil,
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranches(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList tpm2.DigestList
	var policies []*Policy

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList = append(pHashList, digest)
	policies = append(policies, policy)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList = append(pHashList, digest)
	policies = append(policies, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies...)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	expectedDigest, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
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

	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesMultipleDigests(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashListSHA1 tpm2.DigestList
	var pHashListSHA256 tpm2.DigestList
	var policies []*Policy

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)
	policies = append(policies, policy)
	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashListSHA256 = append(pHashListSHA256, digest)
	policies = append(policies, policy)
	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)
	pHashListSHA1 = append(pHashListSHA1, digest)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies...)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	expectedDigestSHA256, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA1, policies...)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	expectedDigestSHA1, _, err := builder.Build(tpm2.HashAlgorithmSHA1)
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, expectedDigestSHA1),
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigestSHA256),
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

	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA1)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigestSHA1)

	digest, err = policy.AddDigest(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigestSHA256)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBuildCommitsCurrentBranchNode(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "a3b2cc44e50ad0ca14d18bb5264942a549301778cf208e8b3989a8f9f2b058cd"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "a74dbbf45ebe6b3c8328e37f878fbdff69cc1ca1a593faa5ffcd43f69c859c05"))},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "6ac7131551a9e815f71c4cb52c3a5202ad3281cfcadf5bc8b908ffcfbdf4f57e"))},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
	)

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestEmptyBranchNodeIsElided(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "fe9bbb331494a468c52d1fa63b890b2c073a006a13abadf7bb07fc1412e2cdb3"))
	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesMultipleNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList1 tpm2.DigestList
	var policies1 []*Policy

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	var pHashList2 tpm2.DigestList
	var policies2 []*Policy

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies2...)
	expectedDigest, _, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()
	c.Assert(node1, NotNil)

	b1 := node1.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node1.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node2 := builder.RootBranch().AddBranchNode()
	c.Assert(node2, NotNil)

	b3 := node2.AddBranch("branch3")
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b4 := node2.AddBranch("branch4")
	c.Check(b4.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
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

	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesEmbeddedNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList2 tpm2.DigestList
	var policies2 []*Policy

	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	digest, policy, err := builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	var pHashList3 tpm2.DigestList
	var policies3 []*Policy

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList3 = append(pHashList3, digest)
	policies3 = append(policies3, policy)

	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList3 = append(pHashList3, digest)
	policies3 = append(policies3, policy)

	var pHashList1 tpm2.DigestList
	var policies1 []*Policy

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies2...)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies3...)
	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	expectedDigest, _, err := builder.Build(tpm2.HashAlgorithmSHA256)

	// Now build a policy with branches
	builder = NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node1 := builder.RootBranch().AddBranchNode()
	c.Assert(node1, NotNil)

	b1 := node1.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	node2 := b1.AddBranchNode()
	c.Assert(node2, NotNil)

	b2 := node2.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b3 := node2.AddBranch("branch3")
	c.Assert(b3, NotNil)
	c.Check(b3.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	b4 := node1.AddBranch("branch4")
	c.Assert(b4, NotNil)
	c.Check(b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	node3 := b4.AddBranchNode()
	c.Assert(node3, NotNil)

	b5 := node3.AddBranch("branch5")
	c.Assert(b5, NotNil)
	c.Check(b5.PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	b6 := node3.AddBranch("branch6")
	c.Assert(b6, NotNil)
	c.Check(b6.PolicyCommandCode(tpm2.CommandNVWriteLock), IsNil)

	expectedPolicy := NewMockPolicy(
		tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, expectedDigest)}, nil,
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

	digest, policy, err = builder.Build(tpm2.HashAlgorithmSHA256)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}
