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
	"fmt"
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyNV(data.nvPub, data.operandB, data.offset, data.operation)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyNVElement(data.nvPub, data.operandB, data.offset, data.operation))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyNV(index:%#x, operandB:%#x, offset:%d, operation:%v)
}`, data.expectedDigest, data.nvPub.Name(), data.operandB, data.offset, data.operation))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicySecret(data.authObjectName, data.policyRef)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicySecretElement(data.authObjectName, data.policyRef))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicySecret(authObject:%#x, policyRef:%#x)
}`, data.expectedDigest, data.authObjectName, data.policyRef))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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

func (s *builderSuite) TestPolicySecretDifferentPolicyRef(c *C) {
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		policyRef:      []byte("bar"),
		expectedDigest: internal_testutil.DecodeHexString(c, "27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b")})
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicySecret(tpm2.Name{0, 0}, nil)
	c.Check(err, ErrorMatches, `invalid authObject name`)
	_, _, err = builder.Policy()
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

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicySigned(authKey, data.policyRef)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicySignedElement(authKey, data.policyRef))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicySigned(authKey:%#x, policyRef:%#x)
}`, data.expectedDigest, authKey.Name(), data.policyRef))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicySigned(new(tpm2.Public), nil)
	c.Check(err, ErrorMatches, `invalid authKey`)
	_, _, err = builder.Policy()
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

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyAuthorize(data.policyRef, keySign)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyAuthorizeElement(data.policyRef, keySign))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 AuthorizedPolicies {
 }
 PolicyAuthorize(policyRef:%#x, keySign:%#x)
}`, data.expectedDigest, data.policyRef, keySign.Name()))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyAuthorize(nil, new(tpm2.Public))
	c.Check(err, ErrorMatches, `invalid keySign`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyAuthorize: invalid keySign`)
}

func (s *builderSuite) TestPolicyAuthorizeNotFirst(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	_, err := builder.RootBranch().PolicyAuthorize(nil, new(tpm2.Public))
	c.Check(err, ErrorMatches, `must be before any other assertions`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyAuthorize: must be before any other assertions`)
}

func (s *builderSuite) TestPolicyAuthorizeNotFirst2(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	node := builder.RootBranch().AddBranchNode()
	_, err := node.AddBranch("").PolicyAuthorize(nil, new(tpm2.Public))
	c.Check(err, ErrorMatches, `must be before any other assertions`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyAuthorize: must be before any other assertions`)
}

func (s *builderSuite) TestPolicyAuthorizeInBranch(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	keySign, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "fdcbcfa9e7d38cd29fc2be62a1ae496e793f4bc4bd7f66ee92196e70bbedd1af"))
	expectedBranchDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "79eb5a0b041d2174a08c34c9207ae675aa7fdee856722e9eb85c885c09f0f959"))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	node := builder.RootBranch().AddBranchNode()
	digest, err := node.AddBranch("").PolicyAuthorize(nil, keySign)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedBranchDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigest}},
				NewMockPolicyAuthorizeElement(nil, keySign),
			),
		),
	)

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 BranchNode {
   Branch 0 {
    # digest TPM_ALG_SHA256:%#[2]x
    AuthorizedPolicies {
    }
    PolicyAuthorize(policyRef:, keySign:%#[3]x)
   }
 }
 PolicyOR(
  %#[2]x
  %#[2]x
 )
}`, expectedDigest, expectedBranchDigest, keySign.Name()))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyAuthValue(c *C) {
	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyAuthValue()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyAuthValueElement())

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyAuthValue()
}`, expectedDigest))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

type testBuildPolicyCommandCodeData struct {
	code           tpm2.CommandCode
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyCommandCode(c *C, data *testBuildPolicyCommandCodeData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyCommandCode(data.code)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyCommandCodeElement(data.code))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyCommandCode(%v)
}`, data.expectedDigest, data.code))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyCounterTimerElement(data.operandB, data.offset, data.operation))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyCounterTimer(operandB:%#x, offset:%d, operation:%v)
}`, data.expectedDigest, data.operandB, data.offset, data.operation))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(data.alg)
	digest, err := builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: data.alg, Digest: data.expectedDigest}}, nil,
		NewMockPolicyCpHashElement(data.expectedCpHash))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest %v:%#x
 PolicyCpHash(%#x)
}`, data.alg, data.expectedDigest, data.expectedCpHash))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *builderSuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "0d5c70236d9181ea6b26fb203d8a45bbb3d982926d6cf4ba60ce0fe5d5717ac3"),
		expectedDigest: internal_testutil.DecodeHexString(c, "79cefecd804486b13ac906b061a6d0faffacb46d7f387d91771b9455242de694")})
}

func (s *builderSuite) TestPolicyCpHashDifferentParams(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "15fc1d7283e0f5f864651602c55f1d1dbebf7e573850bfae5235e94df0ac1fa1"),
		expectedDigest: internal_testutil.DecodeHexString(c, "801e24b6989cfea7a0ec1d885d21aa9311331443d7f21e1bbcb51675b0927475")})
}

func (s *builderSuite) TestPolicyCpHashDifferentHandles(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "4facb677c43722471af5c535353911e4882d26aa58f4859562b6861476f4aca3"),
		expectedDigest: internal_testutil.DecodeHexString(c, "62d74f265639e887956694eb36a4106228a08879ce1ade983cf0b28c2415acbb")})
}

func (s *builderSuite) TestPolicyCpHashDifferentCommand(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA256,
		code:           tpm2.CommandLoadExternal,
		params:         []interface{}{mu.Sized((*tpm2.Sensitive)(nil)), mu.Sized(objectutil.NewRSAStorageKeyTemplate()), tpm2.HandleOwner},
		expectedCpHash: internal_testutil.DecodeHexString(c, "bcbfc6e1846a7f58ed0c05ddf8a0ce7e2b3a50ba3f04e3ac87ee8c940a360f46"),
		expectedDigest: internal_testutil.DecodeHexString(c, "f3d3c11955dd8dc8b45c6b66961cd929bc62a0fd263f5d7336139f30a166f011")})
}

func (s *builderSuite) TestPolicyCpHashSHA1(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		alg:            tpm2.HashAlgorithmSHA1,
		code:           tpm2.CommandLoad,
		handles:        []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:         []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())},
		expectedCpHash: internal_testutil.DecodeHexString(c, "d98ba8350f71c34132f62f50a6b9f21c4fa54f75"),
		expectedDigest: internal_testutil.DecodeHexString(c, "a59f3e6a358dee7edfd733373d7c8a9851296d26")})
}

func (s *builderSuite) TestPolicyCpHashInvalidName(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyCpHash(tpm2.CommandLoad, []Named{tpm2.Name{0, 0}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate()))
	c.Check(err, ErrorMatches, `cannot compute cpHashA: invalid name for handle 0`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyCpHash: cannot compute cpHashA: invalid name for handle 0`)
}

type testBuildPolicyNameHashData struct {
	alg              tpm2.HashAlgorithmId
	handles          []Named
	expectedNameHash tpm2.Digest
	expectedDigest   tpm2.Digest
}

func (s *builderSuite) testPolicyNameHash(c *C, data *testBuildPolicyNameHashData) {
	builder := NewPolicyBuilder(data.alg)
	digest, err := builder.RootBranch().PolicyNameHash(data.handles...)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: data.alg, Digest: data.expectedDigest}}, nil,
		NewMockPolicyNameHashElement(data.expectedNameHash))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest %v:%#x
 PolicyNameHash(%#x)
}`, data.alg, data.expectedDigest, data.expectedNameHash))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyNameHash(tpm2.Name{0, 0})
	c.Check(err, ErrorMatches, `cannot compute nameHash: invalid name for handle 0`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyNameHash: cannot compute nameHash: invalid name for handle 0`)
}

type testBuildPolicyPCRData struct {
	alg            tpm2.HashAlgorithmId
	values         tpm2.PCRValues
	expectedPcrs   PcrValueList
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyPCR(c *C, data *testBuildPolicyPCRData) {
	builder := NewPolicyBuilder(data.alg)
	digest, err := builder.RootBranch().PolicyPCR(data.values)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: data.alg, Digest: data.expectedDigest}}, nil,
		NewMockPolicyPCRElement(data.expectedPcrs))

	expectedPcrs, expectedPcrDigest, err := ComputePCRDigestFromAllValues(data.alg, data.values)
	c.Assert(err, IsNil)

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest %v:%#x
 PolicyPCR(pcrDigest:%#x, pcrs:%v)
}`, data.alg, data.expectedDigest, expectedPcrDigest, expectedPcrs))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}}},
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
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: foo}}},
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
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: bar}}},
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
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}}},
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
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}}},
		expectedDigest: internal_testutil.DecodeHexString(c, "45e5111828cf66c6c7f805f4e9691f6236892514")})
}

func (s *builderSuite) TestPolicyPCRInvalidBank(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmNull: {4: nil}})
	c.Check(err, ErrorMatches, `invalid digest algorithm TPM_ALG_NULL`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest algorithm TPM_ALG_NULL`)
}

func (s *builderSuite) TestPolicyPCRInvalidDigest(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: []byte{0}}})
	c.Check(err, ErrorMatches, `invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
}

func (s *builderSuite) TestPolicyPCRInvalidPCR(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {-1: make([]byte, 32)}})
	c.Check(err, ErrorMatches, `invalid PCR -1: invalid PCR index \(< 0\)`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid PCR -1: invalid PCR index \(< 0\)`)
}

type testBuildPolicyDuplicationSelectData struct {
	object         Named
	newParent      Named
	includeObject  bool
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyDuplicationSelect(c *C, data *testBuildPolicyDuplicationSelectData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	var objectName tpm2.Name
	if data.object != nil {
		objectName = data.object.Name()
	}
	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyDuplicationSelectElement(objectName, data.newParent.Name(), data.includeObject))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyDuplicationSelect(objectName:%#x, newParentName:%#x, includeObject:%t)
}`, data.expectedDigest, objectName, data.newParent.Name(), data.includeObject))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
}

func (s *builderSuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "d3b51a457e1ffc76592514a9c754c7111bbb49c872e11a61cb4ae14acd384b4e")})
}

func (s *builderSuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  false,
		expectedDigest: internal_testutil.DecodeHexString(c, "a9ceacb309fb05bdc45784f0647641bcd2f3a05a10ed94c5525413c7da33234e")})
}

func (s *builderSuite) TestPolicyDuplicationSelectNoIncludeObjectName(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		newParent:      newParent,
		includeObject:  false,
		expectedDigest: internal_testutil.DecodeHexString(c, "a9ceacb309fb05bdc45784f0647641bcd2f3a05a10ed94c5525413c7da33234e")})
}

func (s *builderSuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:         object,
		newParent:      newParent,
		includeObject:  true,
		expectedDigest: internal_testutil.DecodeHexString(c, "df247a269a89dc38ac8d2065abee11d094b66a6b6a7ce984a3d937c584adcebc")})
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidNewParentName(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyDuplicationSelect(nil, tpm2.Name{0, 0}, false)
	c.Check(err, ErrorMatches, `invalid newParent name`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid newParent name`)
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidObjectName(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyDuplicationSelect(tpm2.Name{0, 0}, newParent, true)
	c.Check(err, ErrorMatches, `invalid object name`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid object name`)
}

func (s *builderSuite) TestPolicyDuplicationSelectMissingObjectName(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyDuplicationSelect(nil, newParent, true)
	c.Check(err, ErrorMatches, `invalid object name`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid object name`)
}

func (s *builderSuite) TestPolicyPassword(c *C) {
	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyPassword()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyPasswordElement())

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyPassword()
}`, expectedDigest))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

type testBuildPolicyNvWrittenData struct {
	writtenSet     bool
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyNvWritten(c *C, data *testBuildPolicyNvWrittenData) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicyNvWritten(data.writtenSet)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: data.expectedDigest}}, nil,
		NewMockPolicyNvWrittenElement(data.writtenSet))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicyNvWritten(%t)
}`, data.expectedDigest, data.writtenSet))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
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

type testBuildPolicyORData struct {
	alg            tpm2.HashAlgorithmId
	pHashList      tpm2.DigestList
	expectedDigest tpm2.Digest
}

func (s *builderSuite) testPolicyOR(c *C, data *testBuildPolicyORData) {
	builder := NewPolicyBuilder(data.alg)
	digest, err := builder.RootBranch().PolicyOR(data.pHashList...)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: data.alg, Digest: data.expectedDigest}}, nil,
		NewMockPolicyRawORElement(data.pHashList))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)

	var orDigests string
	for _, digest := range data.pHashList {
		orDigests += fmt.Sprintf("\n  %#x", digest)
	}
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest %v:%#x
 PolicyOR(%s
 )
}`, data.alg, data.expectedDigest, orDigests))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, data.expectedDigest)
	c.Logf("%x", digest)
}

func (s *builderSuite) TestPolicyOR(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testBuildPolicyORData{
		alg:            tpm2.HashAlgorithmSHA256,
		pHashList:      tpm2.DigestList{digest1, digest2},
		expectedDigest: internal_testutil.DecodeHexString(c, "c00c6d95b4a744adc22a95ea83771a700464423ce66ff64733469eb6da324085"),
	})
}

func (s *builderSuite) TestPolicyORDifferentDigests(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo2")
	digest1 := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar2")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testBuildPolicyORData{
		alg:            tpm2.HashAlgorithmSHA256,
		pHashList:      tpm2.DigestList{digest1, digest2},
		expectedDigest: internal_testutil.DecodeHexString(c, "20b175204dcda0f1bc6eea7687e7c90821e4dd991ea9d906b7f9628c476b06b6"),
	})
}

func (s *builderSuite) TestPolicyORNotEnoughDigests(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyOR(make(tpm2.Digest, 32))
	c.Check(err, ErrorMatches, `invalid number of digests`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyOR: invalid number of digests`)
}

func (s *builderSuite) TestPolicyORTooManyDigests(c *C) {
	digest := make(tpm2.Digest, 32)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyOR(digest, digest, digest, digest, digest, digest, digest, digest, digest)
	c.Check(err, ErrorMatches, `invalid number of digests`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyOR: invalid number of digests`)
}

func (s *builderSuite) TestPolicyORInvalidDigestSize(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyOR(digest1, digest2)
	c.Check(err, ErrorMatches, `digest at index 1 has the wrong size`)
	_, _, err = builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyOR: digest at index 1 has the wrong size`)
}

func (s *builderSuite) TestPolicyORSHA1(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	digest1 := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "bar")
	digest2 := h.Sum(nil)

	s.testPolicyOR(c, &testBuildPolicyORData{
		alg:            tpm2.HashAlgorithmSHA1,
		pHashList:      tpm2.DigestList{digest1, digest2},
		expectedDigest: internal_testutil.DecodeHexString(c, "790924ef04397586334d3d315f26fd6a8e105710"),
	})
}

func (s *builderSuite) TestModifyFailedBranch(c *C) {
	// XXX: Note that this only tests one method - this should be expanded to test all
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	_, err := builder.RootBranch().PolicyNameHash(tpm2.Name{0, 0})
	c.Check(err, ErrorMatches, `cannot compute nameHash: invalid name for handle 0`)
	_, err = builder.RootBranch().PolicyAuthValue()
	c.Check(err, ErrorMatches, `encountered an error when calling PolicyNameHash: cannot compute nameHash: invalid name for handle 0`)
}

func (s *builderSuite) TestPolicyMixed(c *C) {
	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "426df7ddd07dbfaa400237f773da801e464ef2766084966b04d8b4dfc0feeee5"))

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	digest, err := builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b")))
	c.Logf("%x", digest)
	digest, err = builder.RootBranch().PolicyAuthValue()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "6e896f81d416d6a8476927f968bf1ec93111fa5fed24d006968028df5a5801f5")))
	c.Logf("%x", digest)
	digest, err = builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#x
 PolicySecret(authObject:0x40000001, policyRef:0x626172)
 PolicyAuthValue()
 PolicyCommandCode(TPM_CC_NV_ChangeAuth)
}`, expectedDigest))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyMixedSHA1(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA1)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	builder.RootBranch().PolicyAuthValue()
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "abdce83ab50f4d5fd378181e21de9486559612d3"))
	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA1, Digest: expectedDigest}}, nil,
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA1:%#x
 PolicySecret(authObject:0x40000001, policyRef:0x626172)
 PolicyAuthValue()
 PolicyCommandCode(TPM_CC_NV_ChangeAuth)
}`, expectedDigest))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyBranches(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList tpm2.DigestList
	var policies []*Policy

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyAuthValue()
	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	pHashList = append(pHashList, digest)
	policies = append(policies, policy)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList = append(pHashList, digest)
	policies = append(policies, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies...)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	expectedDigest, err := builder.Digest()
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	digest, err = b1.PolicyAuthValue()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList[0])

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	digest, err = b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList[1])

	digest, err = builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[0]}},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[1]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	digest, policy, err = builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 PolicyNvWritten(true)
 BranchNode {
   Branch 0 (branch1) {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
   }
   Branch 1 (branch2) {
    # digest TPM_ALG_SHA256:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
   }
 }
 PolicyOR(
  %#[2]x
  %#[3]x
 )
 PolicyCommandCode(TPM_CC_NV_ChangeAuth)
}`, expectedDigest, pHashList[0], pHashList[1]))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyPolicyCommitsCurrentBranchNode(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "a3b2cc44e50ad0ca14d18bb5264942a549301778cf208e8b3989a8f9f2b058cd"))
	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: internal_testutil.DecodeHexString(c, "a74dbbf45ebe6b3c8328e37f878fbdff69cc1ca1a593faa5ffcd43f69c859c05")}},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: internal_testutil.DecodeHexString(c, "6ac7131551a9e815f71c4cb52c3a5202ad3281cfcadf5bc8b908ffcfbdf4f57e")}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
	)

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyDigestCommitsCurrentBranchNode(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	b1.PolicyAuthValue()

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "a3b2cc44e50ad0ca14d18bb5264942a549301778cf208e8b3989a8f9f2b058cd"))
	digest, err := builder.Digest()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestEmptyBranchNodeIsElided(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "fe9bbb331494a468c52d1fa63b890b2c073a006a13abadf7bb07fc1412e2cdb3"))
	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestEmptyBranchesAreOmitted(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	node.AddBranch("").PolicyAuthValue()
	c.Check(node.AddBranch(""), NotNil)

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "ddca4f883da6ad2dc88e838cdceec7ae14a2993c3a8883c696e927e780c3910a"))
	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: internal_testutil.DecodeHexString(c, "636ac47c3f990024d504fdcc720b6fc40df5d63a5df47acb33c8e157b08f672c")}},
				NewMockPolicyAuthValueElement(),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesMultipleNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList1 tpm2.DigestList
	var policies1 []*Policy

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyAuthValue()
	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	var pHashList2 tpm2.DigestList
	var policies2 []*Policy

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies2...)
	expectedDigest, err := builder.Digest()
	c.Assert(err, IsNil)

	// Now build a policy with branches
	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()
	c.Assert(node1, NotNil)

	b1 := node1.AddBranch("branch1")
	c.Assert(b1, NotNil)
	digest, err = b1.PolicyAuthValue()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList1[0])

	b2 := node1.AddBranch("branch2")
	c.Assert(b2, NotNil)
	digest, err = b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList1[1])

	node2 := builder.RootBranch().AddBranchNode()
	c.Assert(node2, NotNil)

	b3 := node2.AddBranch("branch3")
	digest, err = b3.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList2[0])

	b4 := node2.AddBranch("branch4")
	digest, err = b4.PolicyCommandCode(tpm2.CommandNVWriteLock)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList2[1])

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList1[0]},
				},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList1[1]},
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch3", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList2[0]},
				},
				NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
			),
			NewMockPolicyBranch(
				"branch4", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList2[1]},
				},
				NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
			),
		),
	)

	digest, policy, err = builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 PolicyNvWritten(true)
 BranchNode {
   Branch 0 (branch1) {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
   }
   Branch 1 (branch2) {
    # digest TPM_ALG_SHA256:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
   }
 }
 PolicyOR(
  %#[2]x
  %#[3]x
 )
 BranchNode {
   Branch 0 (branch3) {
    # digest TPM_ALG_SHA256:%#[4]x
    PolicyCommandCode(TPM_CC_NV_ChangeAuth)
   }
   Branch 1 (branch4) {
    # digest TPM_ALG_SHA256:%#[5]x
    PolicyCommandCode(TPM_CC_NV_WriteLock)
   }
 }
 PolicyOR(
  %#[4]x
  %#[5]x
 )
}`, expectedDigest, pHashList1[0], pHashList1[1], pHashList2[0], pHashList2[1]))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyBranchesEmbeddedNodes(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList2 tpm2.DigestList
	var policies2 []*Policy

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyAuthValue()
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicyAuthValue()
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList2 = append(pHashList2, digest)
	policies2 = append(policies2, policy)

	var pHashList3 tpm2.DigestList
	var policies3 []*Policy

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList3 = append(pHashList3, digest)
	policies3 = append(policies3, policy)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVWriteLock)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList3 = append(pHashList3, digest)
	policies3 = append(policies3, policy)

	var pHashList1 tpm2.DigestList
	var policies1 []*Policy

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies2...)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies3...)
	digest, policy, err = builder.Policy()
	c.Assert(err, IsNil)
	pHashList1 = append(pHashList1, digest)
	policies1 = append(policies1, policy)

	builder = NewPolicyBuilderOR(tpm2.HashAlgorithmSHA256, policies1...)
	expectedDigest, _, err := builder.Policy()

	// Now build a policy with branches
	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	node1 := builder.RootBranch().AddBranchNode()
	c.Assert(node1, NotNil)

	b1 := node1.AddBranch("branch1")
	c.Assert(b1, NotNil)
	b1.PolicyAuthValue()

	node2 := b1.AddBranchNode()
	c.Assert(node2, NotNil)

	b2 := node2.AddBranch("branch2")
	c.Assert(b2, NotNil)
	digest, err = b2.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList2[0])

	b3 := node2.AddBranch("branch3")
	c.Assert(b3, NotNil)
	digest, err = b3.PolicyCommandCode(tpm2.CommandNVWriteLock)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList2[1])

	b4 := node1.AddBranch("branch4")
	c.Assert(b4, NotNil)
	b4.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

	node3 := b4.AddBranchNode()
	c.Assert(node3, NotNil)

	b5 := node3.AddBranch("branch5")
	c.Assert(b5, NotNil)
	digest, err = b5.PolicyCommandCode(tpm2.CommandNVChangeAuth)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList3[0])

	b6 := node3.AddBranch("branch6")
	c.Assert(b6, NotNil)
	digest, err = b6.PolicyCommandCode(tpm2.CommandNVWriteLock)
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, pHashList3[1])

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}},
		nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList1[0]},
				},
				NewMockPolicyAuthValueElement(),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch2", TaggedHashList{
							{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList2[0]},
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch3", TaggedHashList{
							{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList2[1]},
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
					),
				),
			),
			NewMockPolicyBranch(
				"branch4", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList1[1]},
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch5", TaggedHashList{
							{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList3[0]},
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch6", TaggedHashList{
							{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList3[1]},
						},
						NewMockPolicyCommandCodeElement(tpm2.CommandNVWriteLock),
					),
				),
			),
		),
	)

	digest, policy, err = builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 PolicyNvWritten(true)
 BranchNode {
   Branch 0 (branch1) {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
    BranchNode {
      Branch 0 (branch2) {
       # digest TPM_ALG_SHA256:%#[3]x
       PolicyCommandCode(TPM_CC_NV_ChangeAuth)
      }
      Branch 1 (branch3) {
       # digest TPM_ALG_SHA256:%#[4]x
       PolicyCommandCode(TPM_CC_NV_WriteLock)
      }
    }
    PolicyOR(
     %#[3]x
     %#[4]x
    )
   }
   Branch 1 (branch4) {
    # digest TPM_ALG_SHA256:%#[5]x
    PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
    BranchNode {
      Branch 0 (branch5) {
       # digest TPM_ALG_SHA256:%#[6]x
       PolicyCommandCode(TPM_CC_NV_ChangeAuth)
      }
      Branch 1 (branch6) {
       # digest TPM_ALG_SHA256:%#[7]x
       PolicyCommandCode(TPM_CC_NV_WriteLock)
      }
    }
    PolicyOR(
     %#[6]x
     %#[7]x
    )
   }
 }
 PolicyOR(
  %#[2]x
  %#[5]x
 )
}`, expectedDigest, pHashList1[0], pHashList2[0], pHashList2[1], pHashList1[1], pHashList3[0], pHashList3[1]))
	digest, err = builder.Digest()
	c.Check(digest, DeepEquals, expectedDigest)
}

func (s *builderSuite) TestPolicyBranchesMoreThanEight(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	b, _ := pem.Decode([]byte(pubKeyPEM))
	pubKey, err := x509.ParsePKIXPublicKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(pubKey, internal_testutil.ConvertibleTo, &ecdsa.PublicKey{})

	authKey, err := objectutil.NewECCPublicKey(pubKey.(*ecdsa.PublicKey))
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	node.AddBranch("").PolicyAuthValue()
	node.AddBranch("").PolicyPassword()
	node.AddBranch("").PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
	node.AddBranch("").PolicySecret(tpm2.MakeHandleName(tpm2.HandleEndorsement), []byte("foo"))
	node.AddBranch("").PolicySecret(tpm2.MakeHandleName(tpm2.HandlePlatform), []byte("foo"))
	node.AddBranch("").PolicySecret(tpm2.MakeHandleName(tpm2.HandleLockout), []byte("foo"))
	node.AddBranch("").PolicyCommandCode(tpm2.CommandNVRead)
	node.AddBranch("").PolicyCommandCode(tpm2.CommandPolicyNV)
	node.AddBranch("").PolicyAuthorize([]byte("foo"), authKey)

	expectedDigest := tpm2.Digest(internal_testutil.DecodeHexString(c, "357ff2e053e2e5869fd96d9f063e00d61c740802332fd1e44e67ab443c6d1fdb"))
	expectedBranchDigests := tpm2.DigestList{
		internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"),
		internal_testutil.DecodeHexString(c, "62fd94980db2a746545cab626e9df21a1d0f00472f637d4bf567026e40a6ebed"),
		internal_testutil.DecodeHexString(c, "2c5b145496a4c18c7c93c9cf1143396d18167dcc18affa07ae0a98c0a80c5a82"),
		internal_testutil.DecodeHexString(c, "43aeb5b5951cbdc33ae50185870b1cf8576abcb3ec51aa92bda92880a3219054"),
		internal_testutil.DecodeHexString(c, "97ab4c24a2a7b67ffdaf69433118adb27edfeabc3bfb152ae7bb07362977ff00"),
		internal_testutil.DecodeHexString(c, "47ce3032d8bad1f3089cb0c09088de43501491d460402b90cd1b7fc0b68ca92f"),
		internal_testutil.DecodeHexString(c, "203e4bd5d0448c9615cc13fa18e8d39222441cc40204d99a77262068dbd55a43"),
		internal_testutil.DecodeHexString(c, "3c8876f373f0ca06738973156ca12d324f382990fda581027a1b557048c83dd0"),
	}

	expectedPolicy := NewMockPolicy(
		TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedDigest}}, nil,
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[0]}},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[1]}},
				NewMockPolicyPasswordElement(),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[2]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[3]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleEndorsement), []byte("foo")),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[4]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandlePlatform), []byte("foo")),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[5]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleLockout), []byte("foo")),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[6]}},
				NewMockPolicyCommandCodeElement(tpm2.CommandNVRead),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[7]}},
				NewMockPolicyCommandCodeElement(tpm2.CommandPolicyNV),
			),
			NewMockPolicyBranch(
				"", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: expectedBranchDigests[8]}},
				NewMockPolicyAuthorizeElement([]byte("foo"), authKey),
			),
		),
	)
	digest, policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(digest, DeepEquals, expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
	c.Check(policy.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 BranchNode {
    {
       {
         Branch 0 {
          # digest TPM_ALG_SHA256:%#[2]x
          PolicyAuthValue()
         }
         Branch 1 {
          # digest TPM_ALG_SHA256:%#[3]x
          PolicyPassword()
         }
         Branch 2 {
          # digest TPM_ALG_SHA256:%#[4]x
          PolicySecret(authObject:0x40000001, policyRef:0x666f6f)
         }
         Branch 3 {
          # digest TPM_ALG_SHA256:%#[5]x
          PolicySecret(authObject:0x4000000b, policyRef:0x666f6f)
         }
         Branch 4 {
          # digest TPM_ALG_SHA256:%#[6]x
          PolicySecret(authObject:0x4000000c, policyRef:0x666f6f)
         }
         Branch 5 {
          # digest TPM_ALG_SHA256:%#[7]x
          PolicySecret(authObject:0x4000000a, policyRef:0x666f6f)
         }
         Branch 6 {
          # digest TPM_ALG_SHA256:%#[8]x
          PolicyCommandCode(TPM_CC_NV_Read)
         }
         Branch 7 {
          # digest TPM_ALG_SHA256:%#[9]x
          PolicyCommandCode(TPM_CC_PolicyNV)
         }
       }
       PolicyOR(
        %#[2]x
        %#[3]x
        %#[4]x
        %#[5]x
        %#[6]x
        %#[7]x
        %#[8]x
        %#[9]x
       )
    }
    {
       {
         Branch 8 {
          # digest TPM_ALG_SHA256:%#[10]x
          AuthorizedPolicies {
          }
          PolicyAuthorize(policyRef:0x666f6f, keySign:%#[11]x)
         }
       }
       PolicyOR(
        %#[10]x
        %#[10]x
       )
    }
 }
 PolicyOR(
  0x04534b013d88e1b9fa41d631a62d99539cb0182c31be15110f7d5073f2ddb46e
  0x8395a82161cdfd3f7ff0e663270f19d59a55fb3d9a9f6c7168e3a78d42ad47cc
 )
}`, expectedDigest, expectedBranchDigests[0], expectedBranchDigests[1], expectedBranchDigests[2], expectedBranchDigests[3], expectedBranchDigests[4], expectedBranchDigests[5], expectedBranchDigests[6], expectedBranchDigests[7], expectedBranchDigests[8], authKey.Name()))
}
