// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/testutil"
	"github.com/canonical/go-tpm2/util"

	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

var (
	dummyAuth = []byte("dummy")
	testAuth  = []byte("1234")
)

type mockResourceContext struct {
	handle    Handle
	name      Name
	authValue []byte
}

func (r *mockResourceContext) Handle() Handle                      { return r.handle }
func (r *mockResourceContext) Name() Name                          { return r.name }
func (r *mockResourceContext) SerializeToBytes() []byte            { return nil }
func (r *mockResourceContext) SerializeToWriter(w io.Writer) error { return nil }
func (r *mockResourceContext) SetAuthValue(authValue []byte)       { r.authValue = authValue }
func (r *mockResourceContext) AuthValue() []byte                   { return r.authValue }
func (r *mockResourceContext) SetHandle(handle Handle)             { r.handle = handle }
func (r *mockResourceContext) Dispose()                            {}

type mockSessionContext struct {
	handle  Handle
	data    SessionContextData
	attrs   SessionAttributes
	limited bool
}

func (s *mockSessionContext) Handle() Handle { return s.handle }

func (s *mockSessionContext) Name() Name {
	var name Name
	mu.MustMarshalToBytes(name, s.handle)
	return name
}

func (s *mockSessionContext) SerializeToBytes() []byte            { return nil }
func (s *mockSessionContext) SerializeToWriter(w io.Writer) error { return nil }
func (s *mockSessionContext) Params() SessionContextParams        { return s.data.Params }
func (s *mockSessionContext) State() *SessionContextState {
	if s.limited {
		return nil
	}
	return &s.data.State
}
func (s *mockSessionContext) HashAlg() HashAlgorithmId         { return s.data.Params.HashAlg }
func (s *mockSessionContext) NonceTPM() Nonce                  { return s.data.State.NonceTPM }
func (s *mockSessionContext) IsAudit() bool                    { return s.data.State.IsAudit }
func (s *mockSessionContext) IsExclusive() bool                { return s.data.State.IsExclusive }
func (s *mockSessionContext) Attrs() SessionAttributes         { return s.attrs }
func (s *mockSessionContext) SetAttrs(attrs SessionAttributes) { s.attrs = attrs }

func (s *mockSessionContext) WithAttrs(attrs SessionAttributes) SessionContext {
	return &mockSessionContext{handle: s.handle, data: s.data, attrs: attrs}
}

func (s *mockSessionContext) IncludeAttrs(attrs SessionAttributes) SessionContext {
	return &mockSessionContext{handle: s.handle, data: s.data, attrs: s.attrs | attrs}
}

func (s *mockSessionContext) ExcludeAttrs(attrs SessionAttributes) SessionContext {
	return &mockSessionContext{handle: s.handle, data: s.data, attrs: s.attrs &^ attrs}
}

func (s *mockSessionContext) Dispose() { s.handle = HandleUnassigned }

func authSessionHandle(sc SessionContext) Handle {
	if sc == nil {
		return HandlePW
	}
	return sc.Handle()
}

// Set the hierarchy auth to testAuth. Fatal on failure
func setHierarchyAuthForTest(t *testing.T, tpm *TPMContext, hierarchy ResourceContext) {
	if err := tpm.HierarchyChangeAuth(hierarchy, Auth(testAuth), nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
}

// Reset the hierarchy auth to nil.
func resetHierarchyAuth(t *testing.T, tpm *TPMContext, hierarchy ResourceContext) {
	if err := tpm.HierarchyChangeAuth(hierarchy, nil, nil); err != nil {
		t.Errorf("HierarchyChangeAuth failed: %v", err)
	}
}

// Undefine a NV index set by a test. Fails the test if it doesn't succeed.
func undefineNVSpace(t *testing.T, tpm *TPMContext, context, authHandle ResourceContext) {
	if err := tpm.NVUndefineSpace(authHandle, context, nil); err != nil {
		t.Errorf("NVUndefineSpace failed: %v", err)
	}
}

func computePCRDigestFromTPM(t *testing.T, tpm *TPMContext, alg HashAlgorithmId, pcrs PCRSelectionList) Digest {
	_, pcrValues, err := tpm.PCRRead(pcrs)
	if err != nil {
		t.Fatalf("PCRRead failed: %v", err)
	}

	digest, err := util.ComputePCRDigest(alg, pcrs, pcrValues)
	if err != nil {
		t.Fatalf("ComputePCRDigest failed: %v", err)
	}

	return digest
}

func verifySignature(t *testing.T, pub *Public, digest []byte, signature *Signature) {
	switch pub.Type {
	case ObjectTypeRSA:
		exp := int(pub.Params.RSADetail.Exponent)
		if exp == 0 {
			exp = DefaultRSAExponent
		}
		pubKey := rsa.PublicKey{N: new(big.Int).SetBytes(pub.Unique.RSA), E: exp}

		switch signature.SigAlg {
		case SigSchemeAlgRSASSA:
			sig := (*SignatureRSA)(signature.Signature.RSASSA)
			if !sig.Hash.Available() {
				t.Fatalf("Signature has unavailable digest")
			}
			if err := rsa.VerifyPKCS1v15(&pubKey, sig.Hash.GetHash(), digest, sig.Sig); err != nil {
				t.Errorf("Signature is invalid")
			}
		case SigSchemeAlgRSAPSS:
			sig := (*SignatureRSA)(signature.Signature.RSAPSS)
			if !sig.Hash.Available() {
				t.Fatalf("Signature has unavailable digest")
			}
			if err := rsa.VerifyPSS(&pubKey, sig.Hash.GetHash(), digest, sig.Sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Signature is invalid")
			}
		default:
			t.Errorf("Unknown signature algorithm")
		}
	case ObjectTypeECC:
		pubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub.Unique.ECC.X), Y: new(big.Int).SetBytes(pub.Unique.ECC.Y)}

		switch signature.SigAlg {
		case SigSchemeAlgECDSA:
			sig := signature.Signature.ECDSA
			if !ecdsa.Verify(&pubKey, digest, new(big.Int).SetBytes(sig.SignatureR), new(big.Int).SetBytes(sig.SignatureS)) {
				t.Errorf("Signature is invalid")
			}
		default:
			t.Errorf("Unknown signature algorithm")
		}
	default:
		t.Errorf("Unknown public type")
	}
}

func createRSASrkForTesting(t *testing.T, tpm *TPMContext, userAuth Auth) ResourceContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	objectHandle, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), &sensitiveCreate, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createECCSrkForTesting(t *testing.T, tpm *TPMContext, userAuth Auth) ResourceContext {
	template := Public{
		Type:    ObjectTypeECC,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: &PublicParamsU{
			ECCDetail: &ECCParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:  ECCScheme{Scheme: ECCSchemeNull},
				CurveID: ECCCurveNIST_P256,
				KDF:     KDFScheme{Scheme: KDFAlgorithmNull}}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	objectHandle, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), &sensitiveCreate, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createAndLoadRSAPSSKeyForTesting(t *testing.T, tpm *TPMContext, parent ResourceContext) ResourceContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign | AttrNoDA,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme: RSAScheme{
					Scheme: RSASchemeRSAPSS,
					Details: &AsymSchemeU{
						RSAPSS: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	priv, pub, _, _, _, err := tpm.Create(parent, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, err := tpm.Load(parent, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	return key
}

// Flush a resource context. Fails the test if the resource context is valid but the flush doesn't succeed.
func flushContext(t *testing.T, tpm *TPMContext, context HandleContext) {
	if err := tpm.FlushContext(context); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

// Fail the test if the resource context hasn't been invalidated. Will attempt to flush a valid resource context.
func verifyContextFlushed(t *testing.T, tpm *TPMContext, context HandleContext) {
	if context.Handle() == HandleUnassigned {
		return
	}
	t.Errorf("Context is still live")
	flushContext(t, tpm, context)
}

func requirePCRBank(t *testing.T, tpm *TPMContext, alg HashAlgorithmId) {
	pcrs, err := tpm.GetCapabilityPCRs()
	if err != nil {
		t.Fatalf("GetCapabilityPCRs failed: %v", err)
	}

	for _, pcr := range pcrs {
		if pcr.Hash == alg && len(pcr.Select) > 0 {
			return
		}
	}

	t.Skip(fmt.Sprintf("unsupported PCR bank %v", alg))
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
