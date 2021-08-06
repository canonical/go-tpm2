// Copyright 2019-2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package util_test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
	. "github.com/canonical/go-tpm2/util"
)

type policySuite struct {
	testutil.TPMTest
}

func (s *policySuite) SetUpSuite(c *C) {
	s.TPMFeatures = testutil.TPMFeatureOwnerHierarchy | testutil.TPMFeatureNV
}

var _ = Suite(&policySuite{})

type testPolicySignedData struct {
	alg       tpm2.HashAlgorithmId
	policyRef tpm2.Nonce
}

func (s *policySuite) testPolicySigned(c *C, data *testPolicySignedData) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	c.Assert(err, IsNil)

	h := crypto.SHA256.New()
	binary.Write(h, binary.BigEndian, uint32(0))
	h.Write(data.policyRef)
	digest := h.Sum(nil)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	c.Check(err, IsNil)

	signature := &tpm2.Signature{
		SigAlg: tpm2.SigSchemeAlgRSASSA,
		Signature: &tpm2.SignatureU{
			RSASSA: &tpm2.SignatureRSASSA{
				Hash: tpm2.HashAlgorithmSHA256,
				Sig:  sig}}}

	pub := &tpm2.Public{
		Type:    tpm2.ObjectTypeRSA,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.AttrSign,
		Params: &tpm2.PublicParamsU{
			RSADetail: &tpm2.RSAParams{
				Symmetric: tpm2.SymDefObject{Algorithm: tpm2.SymObjectAlgorithmNull},
				Scheme:    tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
				KeyBits:   2048,
				Exponent:  0}},
		Unique: &tpm2.PublicIDU{RSA: key.N.Bytes()}}
	pubKey, err := s.TPM.LoadExternal(nil, pub, tpm2.HandleOwner)
	c.Assert(err, IsNil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	_, _, err = s.TPM.PolicySigned(pubKey, session, false, nil, data.policyRef, 0, signature)
	c.Check(err, IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicySigned(pubKey.Name(), data.policyRef)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicySignedNoPolicyRef(c *C) {
	s.testPolicySigned(c, &testPolicySignedData{
		alg: tpm2.HashAlgorithmSHA256})
}

func (s *policySuite) TestPolicySignedWithPolicyRef(c *C) {
	s.testPolicySigned(c, &testPolicySignedData{
		alg:       tpm2.HashAlgorithmSHA256,
		policyRef: []byte("bar")})
}

func (s *policySuite) TestPolicyRefSHA1(c *C) {
	s.testPolicySigned(c, &testPolicySignedData{
		alg: tpm2.HashAlgorithmSHA1})
}

type testPolicySecretData struct {
	alg       tpm2.HashAlgorithmId
	policyRef tpm2.Nonce
}

func (s *policySuite) testPolicySecret(c *C, data *testPolicySecretData) {
	primary := s.CreateStoragePrimaryKeyRSA(c)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	_, _, err := s.TPM.PolicySecret(primary, session, nil, data.policyRef, 0, nil)
	c.Check(err, IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicySecret(primary.Name(), data.policyRef)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicySecretNoPolicyRef(c *C) {
	s.testPolicySecret(c, &testPolicySecretData{
		alg: tpm2.HashAlgorithmSHA256})
}

func (s *policySuite) TestPolicySecretWithPolicyRef(c *C) {
	s.testPolicySecret(c, &testPolicySecretData{
		alg:       tpm2.HashAlgorithmSHA256,
		policyRef: []byte("foo")})
}

func (s *policySuite) TestPolicySecretSHA1(c *C) {
	s.testPolicySecret(c, &testPolicySecretData{
		alg: tpm2.HashAlgorithmSHA1})
}

type testPolicyORData struct {
	alg       tpm2.HashAlgorithmId
	pHashList tpm2.DigestList
}

func (s *policySuite) testPolicyOR(c *C, data *testPolicyORData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyOR(session, data.pHashList), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyOR(data.pHashList)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyOR(c *C) {
	var pHashList tpm2.DigestList
	for _, s := range []string{"foo", "bar", "xyz"} {
		h := crypto.SHA256.New()
		io.WriteString(h, s)
		pHashList = append(pHashList, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		alg:       tpm2.HashAlgorithmSHA256,
		pHashList: pHashList})
}

func (s *policySuite) TestPolicyORSHA1(c *C) {
	var pHashList tpm2.DigestList
	for _, s := range []string{"foo", "bar"} {
		h := crypto.SHA1.New()
		io.WriteString(h, s)
		pHashList = append(pHashList, h.Sum(nil))
	}

	s.testPolicyOR(c, &testPolicyORData{
		alg:       tpm2.HashAlgorithmSHA1,
		pHashList: pHashList})
}

type testPolicyPCRData struct {
	alg       tpm2.HashAlgorithmId
	pcrDigest tpm2.Digest
	pcrs      tpm2.PCRSelectionList
}

func (s *policySuite) testPolicyPCR(c *C, data *testPolicyPCRData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyPCR(session, data.pcrDigest, data.pcrs), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyPCR(data.pcrDigest, data.pcrs)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyPCR(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")

	s.testPolicyPCR(c, &testPolicyPCRData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrDigest: h.Sum(nil),
		pcrs:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}}})
}

func (s *policySuite) TestPolicyPCRSHA1(c *C) {
	h := crypto.SHA1.New()
	io.WriteString(h, "foo")

	s.testPolicyPCR(c, &testPolicyPCRData{
		alg:       tpm2.HashAlgorithmSHA1,
		pcrDigest: h.Sum(nil),
		pcrs:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA256, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}}})
}

func (s *policySuite) TestPolicyPCRDifferentPCRs(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "foo")

	s.testPolicyPCR(c, &testPolicyPCRData{
		alg:       tpm2.HashAlgorithmSHA256,
		pcrDigest: h.Sum(nil),
		pcrs:      tpm2.PCRSelectionList{{Hash: tpm2.HashAlgorithmSHA1, Select: []int{0, 1, 2, 3, 4, 5, 6, 7}}}})
}

type testPolicyNVData struct {
	nvPub     *tpm2.NVPublic
	alg       tpm2.HashAlgorithmId
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyNV(c *C, data *testPolicyNVData) {
	index := s.NVDefineSpace(c, tpm2.HandleOwner, nil, data.nvPub)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyNV(index, index, session, data.operandB, data.offset, data.operation, nil), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyNV(index.Name(), data.operandB, data.offset, data.operation)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNV(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *policySuite) TestPolicyNVSHA1(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA1,
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *policySuite) TestPolicyNVDifferentName(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA1,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *policySuite) TestPolicyNVDiffrentOperand(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0x00, 0xff},
		offset:    0,
		operation: tpm2.OpUnsignedLT})
}

func (s *policySuite) TestPolicyNVDifferentOffset(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x10},
		offset:    6,
		operation: tpm2.OpUnsignedLT})
}

func (s *policySuite) TestPolicyNVDifferentOperation(c *C) {
	s.testPolicyNV(c, &testPolicyNVData{
		nvPub: &tpm2.NVPublic{
			Index:   s.NextAvailableHandle(c, 0x0181f000),
			NameAlg: tpm2.HashAlgorithmSHA256,
			Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVNoDA),
			Size:    8},
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10},
		offset:    0,
		operation: tpm2.OpUnsignedGE})
}

type testPolicyCounterTimerData struct {
	alg       tpm2.HashAlgorithmId
	operandB  tpm2.Operand
	offset    uint16
	operation tpm2.ArithmeticOp
}

func (s *policySuite) testPolicyCounterTimer(c *C, data *testPolicyCounterTimerData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyCounterTimer(session, data.operandB, data.offset, data.operation, nil), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyCounterTimer(data.operandB, data.offset, data.operation)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCounterTimer(c *C) {
	s.testPolicyCounterTimer(c, &testPolicyCounterTimerData{
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedGT})
}

func (s *policySuite) TestPolicyCounterTimerSHA1(c *C) {
	s.testPolicyCounterTimer(c, &testPolicyCounterTimerData{
		alg:       tpm2.HashAlgorithmSHA1,
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedGT})
}

func (s *policySuite) TestPolicyCounterTimerDifferentOperand(c *C) {
	s.testPolicyCounterTimer(c, &testPolicyCounterTimerData{
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x10, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedGT})
}

func (s *policySuite) TestPolicyCounterTimerDifferentOffset(c *C) {
	s.testPolicyCounterTimer(c, &testPolicyCounterTimerData{
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    16,
		operation: tpm2.OpUnsignedGT})
}

func (s *policySuite) TestPolicyCounterTimerDifferentOperation(c *C) {
	s.testPolicyCounterTimer(c, &testPolicyCounterTimerData{
		alg:       tpm2.HashAlgorithmSHA256,
		operandB:  []byte{0x00, 0x00, 0xff, 0xff},
		offset:    4,
		operation: tpm2.OpUnsignedLE})
}

type testPolicyCommandCode struct {
	alg  tpm2.HashAlgorithmId
	code tpm2.CommandCode
}

func (s *policySuite) testPolicyCommandCode(c *C, data *testPolicyCommandCode) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyCommandCode(session, data.code), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyCommandCode(data.code)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCommandCode(c *C) {
	s.testPolicyCommandCode(c, &testPolicyCommandCode{
		alg:  tpm2.HashAlgorithmSHA256,
		code: tpm2.CommandDuplicate})
}

func (s *policySuite) TestPolicyCommandCodeSHA1(c *C) {
	s.testPolicyCommandCode(c, &testPolicyCommandCode{
		alg:  tpm2.HashAlgorithmSHA1,
		code: tpm2.CommandDuplicate})
}

func (s *policySuite) TestPolicyCommandCodeDifferentCommand(c *C) {
	s.testPolicyCommandCode(c, &testPolicyCommandCode{
		alg:  tpm2.HashAlgorithmSHA256,
		code: tpm2.CommandNVChangeAuth})
}

func (s *policySuite) testPolicyCpHash(c *C, alg tpm2.HashAlgorithmId) {
	h := alg.NewHash()
	io.WriteString(h, "12345")
	cpHashA := h.Sum(nil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, alg)
	c.Check(s.TPM.PolicyCpHash(session, cpHashA), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(alg.GetHash())
	trial.PolicyCpHash(cpHashA)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyCpHash(c *C) {
	s.testPolicyCpHash(c, tpm2.HashAlgorithmSHA256)
}

func (s *policySuite) TestPolicyCpHashSHA1(c *C) {
	s.testPolicyCpHash(c, tpm2.HashAlgorithmSHA1)
}

func (s *policySuite) testPolicyNameHash(c *C, alg tpm2.HashAlgorithmId) {
	h := alg.NewHash()
	io.WriteString(h, "foobar")
	nameHash := h.Sum(nil)

	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, alg)
	c.Check(s.TPM.PolicyNameHash(session, nameHash), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(alg.GetHash())
	trial.PolicyNameHash(nameHash)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNameHash(c *C) {
	s.testPolicyNameHash(c, tpm2.HashAlgorithmSHA256)
}

func (s *policySuite) TestPolicyNameHashSHA1(c *C) {
	s.testPolicyNameHash(c, tpm2.HashAlgorithmSHA1)
}

type testPolicyDuplicationSelectData struct {
	alg           tpm2.HashAlgorithmId
	objectName    tpm2.Name
	newParentName tpm2.Name
	includeObject bool
}

func (s *policySuite) testPolicyDuplicationSelect(c *C, data *testPolicyDuplicationSelectData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyDuplicationSelect(session, data.objectName, data.newParentName, data.includeObject), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyDuplicationSelect(data.objectName, data.newParentName, data.includeObject)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyDuplicationSelect(c *C) {
	h1 := crypto.SHA256.New()
	io.WriteString(h1, "object")
	h2 := crypto.SHA256.New()
	io.WriteString(h2, "newParent")

	s.testPolicyDuplicationSelect(c, &testPolicyDuplicationSelectData{
		alg:           tpm2.HashAlgorithmSHA256,
		objectName:    mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h1.Sum(nil))),
		newParentName: mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h2.Sum(nil))),
		includeObject: true})
}

func (s *policySuite) TestPolicyDuplicationSelectNoIncludeObject(c *C) {
	h1 := crypto.SHA256.New()
	io.WriteString(h1, "object")
	h2 := crypto.SHA256.New()
	io.WriteString(h2, "newParent")

	s.testPolicyDuplicationSelect(c, &testPolicyDuplicationSelectData{
		alg:           tpm2.HashAlgorithmSHA256,
		objectName:    mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h1.Sum(nil))),
		newParentName: mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h2.Sum(nil))),
		includeObject: false})
}

func (s *policySuite) TestPolicyDuplicationSelectSHA1(c *C) {
	h1 := crypto.SHA256.New()
	io.WriteString(h1, "object")
	h2 := crypto.SHA256.New()
	io.WriteString(h2, "newParent")

	s.testPolicyDuplicationSelect(c, &testPolicyDuplicationSelectData{
		alg:           tpm2.HashAlgorithmSHA1,
		objectName:    mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h1.Sum(nil))),
		newParentName: mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h2.Sum(nil))),
		includeObject: true})
}

func (s *policySuite) TestPolicyDuplicationSelectDifferentObjects(c *C) {
	h1 := crypto.SHA256.New()
	io.WriteString(h1, "object2")
	h2 := crypto.SHA256.New()
	io.WriteString(h2, "newParent2")

	s.testPolicyDuplicationSelect(c, &testPolicyDuplicationSelectData{
		alg:           tpm2.HashAlgorithmSHA256,
		objectName:    mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h1.Sum(nil))),
		newParentName: mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h2.Sum(nil))),
		includeObject: true})
}

type testPolicyAuthorizeData struct {
	alg       tpm2.HashAlgorithmId
	policyRef tpm2.Nonce
	keySign   tpm2.Name
}

func (s *policySuite) testPolicyAuthorize(c *C, data *testPolicyAuthorizeData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyAuthorize(session, make(tpm2.Digest, data.alg.Size()), data.policyRef, data.keySign, nil), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyAuthorize(data.policyRef, data.keySign)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyAuthorize(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "key")

	s.testPolicyAuthorize(c, &testPolicyAuthorizeData{
		alg:       tpm2.HashAlgorithmSHA256,
		policyRef: []byte("foo"),
		keySign:   mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))})
}

func (s *policySuite) TestPolicyAuthorizeNoPolicyRef(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "key")

	s.testPolicyAuthorize(c, &testPolicyAuthorizeData{
		alg:     tpm2.HashAlgorithmSHA256,
		keySign: mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))})
}

func (s *policySuite) TestPolicyAuthorizeSHA1(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "key")

	s.testPolicyAuthorize(c, &testPolicyAuthorizeData{
		alg:       tpm2.HashAlgorithmSHA1,
		policyRef: []byte("foo"),
		keySign:   mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))})
}

func (s *policySuite) TestPolicyAuthorizeDifferentKey(c *C) {
	h := crypto.SHA256.New()
	io.WriteString(h, "key2")

	s.testPolicyAuthorize(c, &testPolicyAuthorizeData{
		alg:       tpm2.HashAlgorithmSHA256,
		policyRef: []byte("foo"),
		keySign:   mu.MustMarshalToBytes(tpm2.HashAlgorithmSHA256, mu.RawBytes(h.Sum(nil)))})
}

func (s *policySuite) testPolicyAuthValue(c *C, alg tpm2.HashAlgorithmId) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, alg)
	c.Check(s.TPM.PolicyAuthValue(session), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(alg.GetHash())
	trial.PolicyAuthValue()

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyAuthValue(c *C) {
	s.testPolicyAuthValue(c, tpm2.HashAlgorithmSHA256)
}

func (s *policySuite) TestPolicyAuthValueSHA1(c *C) {
	s.testPolicyAuthValue(c, tpm2.HashAlgorithmSHA1)
}

func (s *policySuite) testPolicyPassword(c *C, alg tpm2.HashAlgorithmId) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, alg)
	c.Check(s.TPM.PolicyPassword(session), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(alg.GetHash())
	trial.PolicyPassword()

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyPassword(c *C) {
	s.testPolicyPassword(c, tpm2.HashAlgorithmSHA256)
}

func (s *policySuite) TestPolicyPasswordSHA1(c *C) {
	s.testPolicyPassword(c, tpm2.HashAlgorithmSHA1)
}

type testPolicyNvWrittenData struct {
	alg        tpm2.HashAlgorithmId
	writtenSet bool
}

func (s *policySuite) testPolicyNvWritten(c *C, data *testPolicyNvWrittenData) {
	session := s.StartAuthSession(c, nil, nil, tpm2.SessionTypeTrial, nil, data.alg)
	c.Check(s.TPM.PolicyNvWritten(session, data.writtenSet), IsNil)

	expectedDigest, err := s.TPM.PolicyGetDigest(session)
	c.Check(err, IsNil)

	trial := ComputeAuthPolicy(data.alg.GetHash())
	trial.PolicyNvWritten(data.writtenSet)

	c.Check(trial.GetDigest(), DeepEquals, expectedDigest)
}

func (s *policySuite) TestPolicyNvWritten(c *C) {
	s.testPolicyNvWritten(c, &testPolicyNvWrittenData{
		alg:        tpm2.HashAlgorithmSHA256,
		writtenSet: true})
}

func (s *policySuite) TestPolicyNvWrittenSHA1(c *C) {
	s.testPolicyNvWritten(c, &testPolicyNvWrittenData{
		alg:        tpm2.HashAlgorithmSHA1,
		writtenSet: true})
}

func (s *policySuite) TestPolicyNvWrittenNotWritten(c *C) {
	s.testPolicyNvWritten(c, &testPolicyNvWrittenData{
		alg:        tpm2.HashAlgorithmSHA256,
		writtenSet: false})
}
