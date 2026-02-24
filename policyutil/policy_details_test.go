// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"

	. "gopkg.in/check.v1"
)

type policyDetailsSuite struct{}

var _ = Suite(&policyDetailsSuite{})

func (s *policyDetailsSuite) TestPolicyDetails(c *C) {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)

	nvPub := &tpm2.NVPublic{
		Index:   0x0181f000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthRead | tpm2.AttrNVAuthWrite | tpm2.AttrNVWritten),
		Size:    8}
	builder.RootBranch().PolicyNV(nvPub, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10}, 0, tpm2.OpUnsignedLT)

	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))

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
	builder.RootBranch().PolicySigned(pub, []byte("bar"))

	builder.RootBranch().PolicyAuthValue()
	builder.RootBranch().PolicyCommandCode(tpm2.CommandUnseal)
	builder.RootBranch().PolicyCounterTimer([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff}, 0, tpm2.OpUnsignedLT)
	builder.RootBranch().PolicyCpHash(CommandParameters(tpm2.CommandUnseal, []Named{append(tpm2.Name{0x00, 0x0b}, make(tpm2.Name, 32)...)}))

	h := crypto.SHA256.New()
	io.WriteString(h, "foo")
	foo := h.Sum(nil)

	h = crypto.SHA256.New()
	io.WriteString(h, "bar")
	bar := h.Sum(nil)

	pcrValues := tpm2.PCRValues{tpm2.HashAlgorithmSHA256: {4: foo, 7: bar}}
	builder.RootBranch().PolicyPCRValues(pcrValues)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, "", nil)
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

func (s *policyDetailsSuite) testPolicyDetailsWithBranches(c *C, path string) map[string]PolicyBranchDetails {
	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyNvWritten(true)

	builder.RootBranch().AddBranchNode(func(n *PolicyBuilderBranchNode) {
		n.AddBranch("branch1", func(b *PolicyBuilderBranch) {
			b.PolicyAuthValue()
		})

		n.AddBranch("branch2", func(b *PolicyBuilderBranch) {
			b.PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("foo"))
		})
	})

	builder.RootBranch().PolicyCommandCode(tpm2.CommandNVChangeAuth)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmSHA256, path, nil)
	c.Assert(err, IsNil)
	return details
}

func (s *policyDetailsSuite) TestPolicyDetailsWithBranches(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "")
	c.Check(details, internal_testutil.LenEquals, 2)

	bd, exists := details["branch1"]
	c.Assert(exists, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)

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

func (s *policyDetailsSuite) TestPolicyDetailsWithBranches2(c *C) {
	details := s.testPolicyDetailsWithBranches(c, "branch2")
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, exists := details["branch2"]
	c.Assert(exists, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)

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

func (s *policyDetailsSuite) TestPolicyDetailsWithAuthorize(c *C) {
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

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmNull, "", nil)
	c.Check(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 1)

	bd, ok := details["<authorize:key:0x000b64dc4ba32a23deb5f2dfa58c03da0c3900ecd6f1409976e863009f42ab876ea1,ref:0x666f6f>"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
}

func (s *policyDetailsSuite) TestPolicyDetailsWithAuthorize2(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	b, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, internal_testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	pub, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	_, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	_, authPolicy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy1.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	_, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	details, err := policy.Details(tpm2.HashAlgorithmNull, "", NewPolicyAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(err, IsNil)
	c.Check(details, internal_testutil.LenEquals, 2)

	bd, ok := details["8fcd2169ab92694e0c633f1ab772842b8241bbc20288981fc7ac1eddc1fddb0e"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsTrue)
	c.Check(bd.Secret, internal_testutil.LenEquals, 0)

	bd, ok = details["27f33f7496da106954207c4bc322b0cccb96516dfbf53f82b28e2c069905558b"]
	c.Assert(ok, internal_testutil.IsTrue)
	c.Check(bd.IsValid(), internal_testutil.IsTrue)
	c.Check(bd.Authorize, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: pub.Name(), PolicyRef: []byte("foo")},
	})
	c.Check(bd.AuthValueNeeded, internal_testutil.IsFalse)
	c.Check(bd.Secret, DeepEquals, []PolicyAuthorizationDetails{
		{AuthName: tpm2.MakeHandleName(tpm2.HandleOwner), PolicyRef: []byte("bar")},
	})
}
