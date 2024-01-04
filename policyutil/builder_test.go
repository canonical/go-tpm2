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
	nvPub     *tpm2.NVPublic
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *builderSuite) testPolicyNV(c *C, data *testBuildPolicyNVData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNV(data.nvPub, data.operandB, data.offset, data.operation), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyNVElement(data.nvPub, data.operandB, data.offset, data.operation))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNV(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *builderSuite) TestPolicyNVDifferentName(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *builderSuite) TestPolicyNVDifferentOperand(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:  []byte{0x00, 0x00, 0x00, 0xff},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *builderSuite) TestPolicyNVDifferentOffset(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:  []byte{0x00, 0x10},
		offset:    6,
		operation: tpm2.OpUnsignedLT})
}

func (s *builderSuite) TestPolicyNVDifferentOperation(c *C) {
	s.testPolicyNV(c, &testBuildPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   0x0181f000,
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
			Size:    8},
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedGE})
}

type testBuildPolicySecretData struct {
	authObjectName tpm2.Name
	policyRef      tpm2.Nonce
}

func (s *builderSuite) testPolicySecret(c *C, data *testBuildPolicySecretData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(data.authObjectName, data.policyRef), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicySecretElement(data.authObjectName, data.policyRef))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicySecret(c *C) {
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner),
		policyRef:      []byte("foo")})
}

func (s *builderSuite) TestPolicySecretNoPolicyRef(c *C) {
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: tpm2.MakeHandleName(tpm2.HandleOwner)})
}

func (s *builderSuite) TestPolicySecretDifferentAuthObject(c *C) {
	nv := tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	s.testPolicySecret(c, &testBuildPolicySecretData{
		authObjectName: nv.Name(),
		policyRef:      []byte("foo")})
}

func (s *builderSuite) TestPolicySecretInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySecret(tpm2.Name{0, 0}, nil), ErrorMatches, `invalid authObject name`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicySecret: invalid authObject name`)
}

type testBuildPolicySignedData struct {
	pubKeyPEM string
	policyRef tpm2.Nonce
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

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicySignedElement(authKey, data.policyRef))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicySigned(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM: pubKeyPEM,
		policyRef: []byte("bar")})
}

func (s *builderSuite) TestPolicySignedDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM: pubKeyPEM,
		policyRef: []byte("bar")})
}

func (s *builderSuite) TestPolicySignedNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicySigned(c, &testBuildPolicySignedData{
		pubKeyPEM: pubKeyPEM})
}

func (s *builderSuite) TestPolicySignedInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicySigned(new(tpm2.Public), nil), ErrorMatches, `invalid authKey`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicySigned: invalid authKey`)
}

type testBuildPolicyAuthorizeData struct {
	pubKeyPEM string
	policyRef tpm2.Nonce
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

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyAuthorizeElement(data.policyRef, keySign))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyAuthorize(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM: pubKeyPEM,
		policyRef: []byte("bar")})
}

func (s *builderSuite) TestPolicyAuthorizeDifferentKey(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEr9MP/Y5/bMFGJBcSKMJsSTzgZvCi
E8A+q89Clanh7nR5sP0IfBXN1gMsamxgdnklZ7FXEr1c1cZkFhTA9URaTQ==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM: pubKeyPEM,
		policyRef: []byte("bar")})
}

func (s *builderSuite) TestPolicyAuthorizeNoPolicyRef(c *C) {
	pubKeyPEM := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAErK42Zv5/ZKY0aAtfe6hFpPEsHgu1
EK/T+zGscRZtl/3PtcUxX5w+5bjPWyQqtxp683o14Cw1JRv3s+UYs7cj6Q==
-----END PUBLIC KEY-----`

	s.testPolicyAuthorize(c, &testBuildPolicyAuthorizeData{
		pubKeyPEM: pubKeyPEM})
}

func (s *builderSuite) TestPolicyAuthorizeInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthorize(nil, new(tpm2.Public)), ErrorMatches, `invalid keySign`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyAuthorize: invalid keySign`)
}

func (s *builderSuite) TestPolicyAuthValue(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyAuthValue(), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyAuthValueElement())

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) testPolicyCommandCode(c *C, code tpm2.CommandCode) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCommandCode(code), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyCommandCodeElement(code))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCommandCode1(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandNVChangeAuth)
}

func (s *builderSuite) TestPolicyCommandCode2(c *C) {
	s.testPolicyCommandCode(c, tpm2.CommandDuplicate)
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

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyCounterTimerElement(data.operandB, data.offset, data.operation))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCounterTimer(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedGT})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOperand(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:  []byte{0x00, 0x10, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedGT})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOffset(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    16,
		operation: tpm2.OpUnsignedGT})
}

func (s *builderSuite) TestPolicyCounterTimerDifferentOperation(c *C) {
	s.testPolicyCounterTimer(c, &testBuildPolicyCounterTimerData{
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedLE})
}

type testBuildPolicyCpHashData struct {
	code    tpm2.CommandCode
	handles []Named
	params  []interface{}
}

func (s *builderSuite) testPolicyCpHash(c *C, data *testBuildPolicyCpHashData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(data.code, data.handles, data.params...), IsNil)

	var handles []tpm2.Name
	for _, handle := range data.handles {
		handles = append(handles, handle.Name())
	}

	cpBytes, err := mu.MarshalToBytes(data.params...)
	c.Check(err, IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyCpHashElement(&CpHashParams{CommandCode: data.code, Handles: handles, CpBytes: cpBytes}, nil))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *builderSuite) TestPolicyCpHashDifferentParams(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x01}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4, 5}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *builderSuite) TestPolicyCpHashDifferentHandles(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		code:    tpm2.CommandLoad,
		handles: []Named{tpm2.Name{0x40, 0x00, 0x00, 0x0b}},
		params:  []interface{}{tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())}})
}

func (s *builderSuite) TestPolicyCpHashDifferentCommand(c *C) {
	s.testPolicyCpHash(c, &testBuildPolicyCpHashData{
		code:   tpm2.CommandLoadExternal,
		params: []interface{}{mu.Sized((*tpm2.Sensitive)(nil)), mu.Sized(objectutil.NewRSAStorageKeyTemplate()), tpm2.HandleOwner}})
}

func (s *builderSuite) TestPolicyCpHashInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyCpHash(tpm2.CommandLoad, []Named{tpm2.Name{0, 0}}, tpm2.Private{1, 2, 3, 4}, mu.Sized(objectutil.NewRSAStorageKeyTemplate())), ErrorMatches,
		`invalid name at handle 0`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyCpHash: invalid name at handle 0`)
}

func (s *builderSuite) testPolicyNameHash(c *C, handles ...Named) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(handles...), IsNil)

	var handleNames []tpm2.Name
	for _, handle := range handles {
		handleNames = append(handleNames, handle.Name())
	}
	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyNameHashElement(&NameHashParams{Handles: handleNames}, nil))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNameHash(c *C) {
	s.testPolicyNameHash(c, tpm2.MakeHandleName(tpm2.HandleOwner))
}

func (s *builderSuite) TestPolicyNameHashDifferentHandles(c *C) {
	s.testPolicyNameHash(c, tpm2.MakeHandleName(tpm2.HandleEndorsement))
}

func (s *builderSuite) TestPolicyNameHashInvalidName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNameHash(tpm2.Name{0, 0}), ErrorMatches, `invalid name at handle 0`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches,
		`could not build policy: encountered an error when calling PolicyNameHash: invalid name at handle 0`)
}

type testBuildPolicyPCRData struct {
	values       tpm2.PCRValues
	expectedPcrs PcrValueList
}

func (s *builderSuite) testPolicyPCR(c *C, data *testBuildPolicyPCRData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(data.values), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyPCRElement(data.expectedPcrs))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
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
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: foo,
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)}}})
}

func (s *builderSuite) TestPolicyPCRDifferentDigests(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA256: {
				4: bar,
				7: foo}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, foo)}}})
}

func (s *builderSuite) TestPolicyPCRDifferentSelection(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA1.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	s.testPolicyPCR(c, &testBuildPolicyPCRData{
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo,
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, bar)}}})
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
		values: tpm2.PCRValues{
			tpm2.HashAlgorithmSHA1: {
				4: foo},
			tpm2.HashAlgorithmSHA256: {
				7: bar}},
		expectedPcrs: PcrValueList{
			{PCR: 0x00000004, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA1, foo)},
			{PCR: 0x00000007, Digest: tpm2.MakeTaggedHash(tpm2.HashAlgorithmSHA256, bar)}}})
}

func (s *builderSuite) TestPolicyPCRInvalidAlg(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmNull: {4: nil}}), ErrorMatches, `invalid digest algorithm TPM_ALG_NULL`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest algorithm TPM_ALG_NULL`)
}

func (s *builderSuite) TestPolicyPCRInvalidDigest(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: []byte{0}}}), ErrorMatches, `invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid digest size for PCR 4, algorithm TPM_ALG_SHA256`)
}

func (s *builderSuite) TestPolicyPCRInvalidPCR(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPCR(tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {-1: make([]byte, 32)}}), ErrorMatches, `invalid PCR -1: invalid PCR index \(< 0\)`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyPCR: invalid PCR -1: invalid PCR index \(< 0\)`)
}

type testBuildPolicyDuplicationSelectData struct {
	object        Named
	newParent     Named
	includeObject bool
}

func (s *builderSuite) testPolicyDuplicationSelect(c *C, data *testBuildPolicyDuplicationSelectData) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(data.object, data.newParent, data.includeObject), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyDuplicationSelectElement(data.object.Name(), data.newParent.Name(), data.includeObject))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyDuplicationSelect(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *builderSuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: false})
}

func (s *builderSuite) TestPolicyDuplicationSelectDifferentNames(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "bar")
	object := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	h = crypto.SHA256.New()
	io.WriteString(h, "foo")
	newParent := tpm2.Name(mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.Raw(h.Sum(nil))))

	s.testPolicyDuplicationSelect(c, &testBuildPolicyDuplicationSelectData{
		object:        object,
		newParent:     newParent,
		includeObject: true})
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidNewParentName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(nil, tpm2.Name{0, 0}, false), ErrorMatches, `invalid newParent name`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid newParent name`)
}

func (s *builderSuite) TestPolicyDuplicationSelectInvalidObjectName(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyDuplicationSelect(tpm2.Name{0, 0}, nil, true), ErrorMatches, `invalid object name`)
	_, err := builder.Policy()
	c.Check(err, ErrorMatches, `could not build policy: encountered an error when calling PolicyDuplicationSelect: invalid object name`)
}

func (s *builderSuite) TestPolicyPassword(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyPassword(), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyPasswordElement())

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) testPolicyNvWritten(c *C, writtenSet bool) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(writtenSet), IsNil)

	expectedPolicy := NewMockPolicy(nil, nil, NewMockPolicyNvWrittenElement(writtenSet))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyNvWrittenFalse(c *C) {
	s.testPolicyNvWritten(c, false)
}

func (s *builderSuite) TestPolicyNvWrittenTrue(c *C) {
	s.testPolicyNvWritten(c, true)
}

func (s *builderSuite) TestPolicyLocksRoot(c *C) {
	builder := NewPolicyBuilder()
	_, err := builder.Policy()
	c.Check(err, IsNil)

	c.Check(builder.RootBranch().PolicyAuthValue(), ErrorMatches, `cannot modify locked branch`)
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

	expectedPolicy := NewMockPolicy(
		nil, nil,
		NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar")),
		NewMockPolicyAuthValueElement(),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth))

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranches(c *C) {
	builder := NewPolicyBuilder()
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
		nil, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", nil,
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", nil,
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestLockBranchCommitCurrentBranchNode(c *C) {
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

	expectedPolicy := NewMockPolicy(
		nil, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", nil,
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", nil,
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
	)

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestEmptyBranchNodeIsElided(c *C) {
	builder := NewPolicyBuilder()
	c.Check(builder.RootBranch().PolicyNvWritten(true), IsNil)

	node := builder.RootBranch().AddBranchNode()
	c.Assert(node, NotNil)

	c.Check(builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		nil, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
	)

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesMultipleNodes(c *C) {
	builder := NewPolicyBuilder()
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
	c.Check(b4.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		nil, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", nil,
				NewMockPolicyAuthValueElement(),
			),
			NewMockPolicyBranch(
				"branch2", nil,
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
			),
		),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch3", nil,
				NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
			),
			NewMockPolicyBranch(
				"branch4", nil,
				NewMockPolicyCommandCodeElement(tpm2.CommandHierarchyChangeAuth),
			),
		),
	)

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}

func (s *builderSuite) TestPolicyBranchesEmbeddedNodes(c *C) {
	builder := NewPolicyBuilder()
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
	c.Check(b3.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

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
	c.Check(b6.PolicyCommandCode(tpm2.CommandHierarchyChangeAuth), IsNil)

	expectedPolicy := NewMockPolicy(
		nil, nil,
		NewMockPolicyNvWrittenElement(true),
		NewMockPolicyORElement(
			NewMockPolicyBranch(
				"branch1", nil,
				NewMockPolicyAuthValueElement(),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch2", nil,
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch3", nil,
						NewMockPolicyCommandCodeElement(tpm2.CommandHierarchyChangeAuth),
					),
				),
			),
			NewMockPolicyBranch(
				"branch4", nil,
				NewMockPolicySecretElement(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo")),
				NewMockPolicyORElement(
					NewMockPolicyBranch(
						"branch5", nil,
						NewMockPolicyCommandCodeElement(tpm2.CommandNVChangeAuth),
					),
					NewMockPolicyBranch(
						"branch6", nil,
						NewMockPolicyCommandCodeElement(tpm2.CommandHierarchyChangeAuth),
					),
				),
			),
		),
	)

	policy, err := builder.Policy()
	c.Check(err, IsNil)
	c.Check(policy, testutil.TPMValueDeepEquals, expectedPolicy)
}
