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
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNV(data.nvPub, data.operandB, data.offset, data.operation), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyNVElement(data.nvPub.Index, data.operandB, data.offset, data.operation))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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

func (s *computeSuite) TestPolicyNVInvalidName(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNV(&tpm2.NVPublic{Index: 0x01000000}, nil, 0, tpm2.OpEq), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyNV assertion: invalid index name`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyNV: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyNV assertion: invalid index name`)
}

func (s *computeSuite) TestPolicyNVInvalidIndex(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNV(new(tpm2.NVPublic), nil, 0, tpm2.OpEq), ErrorMatches, `nvIndex has invalid handle type`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyNV: nvIndex has invalid handle type`)
}

func (s *computeSuite) TestPolicyNVMismatchedNames(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNV(&tpm2.NVPublic{NameAlg: tpm2.HashAlgorithmSHA256, Index: 0x01000000}, nil, 0, tpm2.OpEq), IsNil)
	c.Check(pc.RootBranch().PolicyNV(&tpm2.NVPublic{NameAlg: tpm2.HashAlgorithmSHA1, Index: 0x01000000}, nil, 0, tpm2.OpEq), ErrorMatches, `nvIndex already exists in this profile but with a different name`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyNV: nvIndex already exists in this profile but with a different name`)
}

type testComputePolicySecretData struct {
	authObjectName tpm2.Name
	policyRef      tpm2.Nonce

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicySecret(c *C, data *testComputePolicySecretData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicySecret(data.authObjectName, data.policyRef), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicySecretElement(data.authObjectName, data.policyRef))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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

func (s *computeSuite) TestPolicySecretInvalidName(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicySecret(tpm2.Name{0, 0}, nil), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicySecret assertion: invalid authObject name`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicySecret: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicySecret assertion: invalid authObject name`)
}

type testComputePolicySignedData struct {
	authKey   *tpm2.Public
	policyRef tpm2.Nonce

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicySigned(c *C, data *testComputePolicySignedData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicySigned(data.authKey, data.policyRef), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicySignedElement(data.authKey, data.policyRef))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
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

func (s *computeSuite) TestPolicyAuthValue(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyAuthValueElement())

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e")))
	c.Check(policy, DeepEquals, expectedPolicy)
}

type testComputePolicyCommandCodeData struct {
	code           tpm2.CommandCode
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyCommandCode(c *C, data *testComputePolicyCommandCodeData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyCommandCode(data.code), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyCommandCodeElement(data.code))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyCounterTimer(data.operandB, data.offset, data.operation), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyCounterTimerElement(data.operandB, data.offset, data.operation))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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
	algs    []tpm2.HashAlgorithmId
	cpHashA CpHash

	expectedDigests tpm2.TaggedHashList
}

func (s *computeSuite) testPolicyCpHash(c *C, data *testComputePolicyCpHashData) {
	var cpHashes TaggedHashList
	for _, alg := range data.algs {
		cpHashA, err := data.cpHashA.Digest(alg)
		c.Assert(err, IsNil)
		cpHashes = append(cpHashes, TaggedHash{HashAlg: alg, Digest: cpHashA})
	}

	pc := ComputePolicy(data.algs...)
	c.Check(pc.RootBranch().PolicyCpHash(data.cpHashA), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyCpHashElement(cpHashes))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, data.expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		cpHashA:         CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "79cefecd804486b13ac906b061a6d0faffacb46d7f387d91771b9455242de694"))}})
}

func (s *computeSuite) TestPolicyCpHashDifferentParams(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		cpHashA:         CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "801e24b6989cfea7a0ec1d885d21aa9311331443d7f21e1bbcb51675b0927475"))}})
}

func (s *computeSuite) TestPolicyCpHashDifferentHandles(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		cpHashA:         CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "62d74f265639e887956694eb36a4106228a08879ce1ade983cf0b28c2415acbb"))}})
}

func (s *computeSuite) TestPolicyCpHashSHA1(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		cpHashA:         CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "a59f3e6a358dee7edfd733373d7c8a9851296d26"))}})
}

func (s *computeSuite) TestPolicyCpHashMultipleDigests(c *C) {
	s.testPolicyCpHash(c, &testComputePolicyCpHashData{
		algs:    []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256},
		cpHashA: CommandParameters(tpm2.CommandLoad, []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())),
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "a59f3e6a358dee7edfd733373d7c8a9851296d26")),
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "79cefecd804486b13ac906b061a6d0faffacb46d7f387d91771b9455242de694"))}})
}

func (s *computeSuite) TestPolicyCpHashInvalidDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyCpHash(CommandParameterDigest(tpm2.HashAlgorithmSHA1, nil)), ErrorMatches, `cannot compute cpHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyCpHash: cannot compute cpHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
}

type testComputePolicyNameHashData struct {
	algs []tpm2.HashAlgorithmId

	nameHash NameHash

	expectedDigests tpm2.TaggedHashList
}

func (s *computeSuite) testPolicyNameHash(c *C, data *testComputePolicyNameHashData) {
	var nameHashes TaggedHashList
	for _, alg := range data.algs {
		nameHash, err := data.nameHash.Digest(alg)
		c.Assert(err, IsNil)
		nameHashes = append(nameHashes, TaggedHash{HashAlg: alg, Digest: nameHash})
	}

	pc := ComputePolicy(data.algs...)
	c.Check(pc.RootBranch().PolicyNameHash(data.nameHash), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyNameHashElement(nameHashes))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, data.expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyNameHash(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		nameHash:        CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner)),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "f46ca197c159be2500db41866e2713bd5e25cda9bbd46e2a398550010d7e5e5b"))}})
}

func (s *computeSuite) TestPolicyNameHashDifferentHandles(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		nameHash:        CommandHandles(tpm2.MakeHandleName(tpm2.HandleEndorsement)),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "3e3fbf3b3c59ba10ae0f02c691ceb60ba87fd7463c4100c1bb85c143e24e6eab"))}})
}

func (s *computeSuite) TestPolicyNameHashSHA1(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		algs:            []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		nameHash:        CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner)),
		expectedDigests: tpm2.TaggedHashList{tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "022794dd35419f458603c2c11808dced821078d2"))}})
}

func (s *computeSuite) TestPolicyNameHashMultipleDigests(c *C) {
	s.testPolicyNameHash(c, &testComputePolicyNameHashData{
		algs:     []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256},
		nameHash: CommandHandles(tpm2.MakeHandleName(tpm2.HandleOwner)),
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "022794dd35419f458603c2c11808dced821078d2")),
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "f46ca197c159be2500db41866e2713bd5e25cda9bbd46e2a398550010d7e5e5b"))}})
}

func (s *computeSuite) TestPolicyNameHashInvalidDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNameHash(CommandHandleDigest(tpm2.HashAlgorithmSHA1, nil)), ErrorMatches, `cannot compute nameHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyNameHash: cannot compute nameHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
}

type testPolicyORData struct {
	algs             []tpm2.HashAlgorithmId
	hashLists        []*PolicyORHashList
	expectedHashList []TaggedHashList
	expectedDigests  tpm2.TaggedHashList
}

func (s *computeSuite) testPolicyOR(c *C, data *testPolicyORData) {
	pc := ComputePolicy(data.algs...)
	c.Check(pc.RootBranch().PolicyOR(data.hashLists...), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyORElement(data.expectedHashList))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, data.expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyOR(c *C) {
	var pHashList tpm2.DigestList
	for _, data := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA256.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		algs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		hashLists: []*PolicyORHashList{NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)},
		expectedHashList: []TaggedHashList{
			{
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[0]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[1]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[2]},
			},
		},
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "279c72a6141f45135f7d0667ef67ae3c59adb521493678b00b9d93ed9cc7888c")),
		},
	})
}

func (s *computeSuite) TestPolicyORDifferentDigests(c *C) {
	var pHashList tpm2.DigestList
	for _, data := range []string{"foo1", "bar1"} {
		h := crypto.SHA256.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		algs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256},
		hashLists: []*PolicyORHashList{NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)},
		expectedHashList: []TaggedHashList{
			{
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[0]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[1]},
			},
		},
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "30083090cb942a839859e7653e40dcb462e47a86ddbaa3d9fc6ecf9aee45529a")),
		},
	})
}

func (s *computeSuite) TestPolicyORSHA1(c *C) {
	var pHashList tpm2.DigestList
	for _, data := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA1.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		algs:      []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA1},
		hashLists: []*PolicyORHashList{NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashList)},
		expectedHashList: []TaggedHashList{
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashList[0]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashList[1]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashList[2]},
			},
		},
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "622390ea33e3f878c1979d70348072072bb51757")),
		},
	})
}

func (s *computeSuite) TestPolicyORMultipleAlgorithms(c *C) {
	var pHashListSHA1 tpm2.DigestList
	var pHashListSHA256 tpm2.DigestList
	for _, data := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA1.New()
		io.WriteString(h, data)
		pHashListSHA1 = append(pHashListSHA1, h.Sum(nil))

		h = crypto.SHA256.New()
		io.WriteString(h, data)
		pHashListSHA256 = append(pHashListSHA256, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		algs: []tpm2.HashAlgorithmId{tpm2.HashAlgorithmSHA256, tpm2.HashAlgorithmSHA1},
		hashLists: []*PolicyORHashList{
			NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashListSHA1),
			NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashListSHA256),
		},
		expectedHashList: []TaggedHashList{
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[0]},
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[0]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[1]},
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[1]},
			},
			{
				{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[2]},
				{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[2]},
			},
		},
		expectedDigests: tpm2.TaggedHashList{
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, internal_testutil.DecodeHexString(c, "279c72a6141f45135f7d0667ef67ae3c59adb521493678b00b9d93ed9cc7888c")),
			tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, internal_testutil.DecodeHexString(c, "622390ea33e3f878c1979d70348072072bb51757")),
		},
	})
}

func (s *computeSuite) TestPolicyORMissingDigests(c *C) {
	var pHashList tpm2.DigestList
	for _, data := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA1.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashList)), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: cannot process digest at index 0: missing digest for session algorithm`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyOR: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: cannot process digest at index 0: missing digest for session algorithm`)
}

func (s *computeSuite) TestPolicyORInvalidNumberOfBranches(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	digest := h.Sum(nil)

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, tpm2.DigestList{digest})), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: invalid number of branches`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyOR: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: invalid number of branches`)
}

func (s *computeSuite) TestPolicyORInvalidDigestLength(c *C) {
	var pHashList tpm2.DigestList
	for _, data := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA1.New()
		io.WriteString(h, data)
		pHashList = append(pHashList, h.Sum(nil))
	}

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: invalid digest length at branch 0`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyOR: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyOR assertion: invalid digest length at branch 0`)
}

type testComputePolicyPCRData struct {
	values         tpm2.PCRValues
	expectedPcrs   PcrValueList
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyPCR(c *C, data *testComputePolicyPCRData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyPCR(data.values), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyPCRElement(data.expectedPcrs))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}}},
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
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: foo}}},
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
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: bar}}},
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
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA1, Digest: foo}},
			{PCR: 0x00000007, Digest: TaggedHash{HashAlg: tpm2.HashAlgorithmSHA256, Digest: bar}}},
		expectedDigest: internal_testutil.DecodeHexString(c, "5079c1d53de12dd44e988d5b0a31cd30701ffb24b7bd5d5b68d5f9f5819163be")})
}

func (s *computeSuite) TestPolicyPCRInvalidAlg(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmNull: {4: nil}}), ErrorMatches, `invalid digest algorithm TPM_ALG_NULL`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyPCR: invalid digest algorithm TPM_ALG_NULL`)
}

func (s *computeSuite) TestPolicyPCRInvalidDigest(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: []byte{0}}}), ErrorMatches, `invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyPCR: invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
}

type testComputePolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool

	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyDuplicationSelect(c *C, data *testComputePolicyDuplicationSelectData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyDuplicationSelectElement(data.object.Name(), data.newParent.Name(), data.includeObject))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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

func (s *computeSuite) TestPolicyDuplicationSelectInvalidNewParentName(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyDuplicationSelect(nil, tpm2.Name{0, 0}, false), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyDuplicationSelect assertion: invalid newParent name`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyDuplicationSelect: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyDuplicationSelect assertion: invalid newParent name`)
}

func (s *computeSuite) TestPolicyDuplicationSelectInvalidObjectName(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyDuplicationSelect(tpm2.Name{0, 0}, nil, true), ErrorMatches, `cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyDuplicationSelect assertion: invalid object name`)
	_, _, err := pc.Policy()
	c.Check(err, ErrorMatches, `could not compute policy: encountered an error when calling PolicyDuplicationSelect: cannot update context for algorithm TPM_ALG_SHA256: cannot process TPM2_PolicyDuplicationSelect assertion: invalid object name`)
}

func (s *computeSuite) TestPolicyPassword(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyPassword(), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyPasswordElement())

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e")))
	c.Check(policy, DeepEquals, expectedPolicy)
}

type testComputePolicyNvWrittenData struct {
	writtenSet     bool
	expectedDigest tpm2.Digest
}

func (s *computeSuite) testPolicyNvWritten(c *C, data *testComputePolicyNvWrittenData) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(data.writtenSet), IsNil)

	expectedPolicy := NewMockPolicy(NewMockPolicyNvWrittenElement(data.writtenSet))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, data.expectedDigest)
	c.Check(policy, DeepEquals, expectedPolicy)
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

func (s *computeSuite) TestComputeLocksRoot(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	_, _, err := pc.Policy()
	c.Check(err, IsNil)

	c.Check(pc.RootBranch().PolicyAuthValue(), ErrorMatches, `cannot modify locked branch`)
}

func (s *computeSuite) TestModifyFailedBranch(c *C) {
	// XXX: Note that this only tests one method - this should be expanded to test all
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyCpHash(CommandParameterDigest(tpm2.HashAlgorithmSHA1, nil)), ErrorMatches, `cannot compute cpHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
	c.Check(pc.RootBranch().PolicyAuthValue(), ErrorMatches, `encountered an error when calling PolicyCpHash: cannot compute cpHash for algorithm TPM_ALG_SHA256: no digest for algorithm`)
}

func (s *computeSuite) TestPolicyMixed(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "426df7ddd07dbfaa400237f773da801e464ef2766084966b04d8b4dfc0feeee5")))
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyMixedSHA1(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA1)
	c.Check(pc.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")), IsNil)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA1)
	c.Check(digests[0].Digest(), DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "abdce83ab50f4d5fd378181e21de9486559612d3")))
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyBranches(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList tpm2.DigestList

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digests[0].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digests, _, err = pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digests[0].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	expectedDigests, _, err := pc.Policy()

	// Now build a profile with branches
	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyBranchNodeElement(
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
	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestLockBranchCommitCurrentBranchNode(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashList tpm2.DigestList

	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digests[0].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	c.Check(pc.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digests, _, err = pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashList = append(pHashList, digests[0].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashList)), IsNil)
	expectedDigests, _, err := pc.Policy()

	// Now build a profile with branches
	pc = ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	node := pc.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
		NewMockPolicyBranchNodeElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[0]}},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashList[1]}},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
	)
	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestEmptyBranchNodeIsElided(c *C) {
	pc := ComputePolicy(tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)
	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Assert(digests, internal_testutil.LenEquals, 1)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	c.Check(digests[0].Digest(), DeepEquals, tpm2.Digest(internal_testutil.DecodeHexString(c, "fe9bbb331494a468c52d1fa63b890b2c073a006a13abadf7bb07fc1412e2cdb3")))
	c.Check(policy, DeepEquals, expectedPolicy)
}

func (s *computeSuite) TestPolicyBranchesMultipleDigests(c *C) {
	// Compute the expected digests using the low-level PolicyOR
	var pHashListSHA1 tpm2.DigestList
	var pHashListSHA256 tpm2.DigestList

	pc := ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicyAuthValue(), IsNil)
	digests, _, err := pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 2)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA1)
	pHashListSHA1 = append(pHashListSHA1, digests[0].Digest())
	c.Check(digests[1].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashListSHA256 = append(pHashListSHA256, digests[1].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)
	c.Check(pc.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)
	digests, _, err = pc.Policy()
	c.Assert(digests, internal_testutil.LenEquals, 2)
	c.Check(digests[0].HashAlg, Equals, tpm2.HashAlgorithmSHA1)
	pHashListSHA1 = append(pHashListSHA1, digests[0].Digest())
	c.Check(digests[1].HashAlg, Equals, tpm2.HashAlgorithmSHA256)
	pHashListSHA256 = append(pHashListSHA256, digests[1].Digest())

	pc = ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyOR(NewPolicyORHashList(tpm2.HashAlgorithmSHA1, pHashListSHA1), NewPolicyORHashList(tpm2.HashAlgorithmSHA256, pHashListSHA256)), IsNil)
	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)
	expectedDigests, _, err := pc.Policy()

	// Now build a profile with branches
	pc = ComputePolicy(tpm2.HashAlgorithmSHA1, tpm2.HashAlgorithmSHA256)
	c.Check(pc.RootBranch().PolicyNvWritten(true), IsNil)

	node := pc.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	b1 := node.AddBranch("branch1")
	c.Assert(b1, NotNil)
	c.Check(b1.PolicyAuthValue(), IsNil)

	b2 := node.AddBranch("branch2")
	c.Assert(b2, NotNil)
	c.Check(b2.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")), IsNil)

	c.Check(pc.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyBranchNodeElement(
			NewMockPolicyBranch(
				"branch1", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[0]},
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[0]},
				},
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", TaggedHashList{
					{HashAlg: tpm2.HashAlgorithmSHA1, Digest: pHashListSHA1[1]},
					{HashAlg: tpm2.HashAlgorithmSHA256, Digest: pHashListSHA256[1]},
				},
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)
	digests, policy, err := pc.Policy()
	c.Check(err, IsNil)
	c.Check(digests, DeepEquals, expectedDigests)
	c.Check(policy, DeepEquals, expectedPolicy)
}
