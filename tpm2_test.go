// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"flag"
	"fmt"
	"math/big"
	"os"
	"reflect"
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

func verifyPublicAgainstTemplate(t *testing.T, public, template *Public) {
	if public.Type != template.Type {
		t.Errorf("public object has wrong type: %v", public.Type)
	}
	if public.NameAlg != template.NameAlg {
		t.Errorf("public object has wrong name alg: %v", public.NameAlg)
	}
	if public.Attrs != template.Attrs {
		t.Errorf("public object has wrong name attrs: %v", public.Attrs)
	}
	if !bytes.Equal(public.AuthPolicy, template.AuthPolicy) {
		t.Errorf("public object has wrong auth policy")
	}
	pp, err := mu.MarshalToBytes(public.Params.Select(reflect.ValueOf(public.Type)))
	if err != nil {
		t.Errorf("cannot marshal public params: %v", err)
	}
	tp, err := mu.MarshalToBytes(template.Params.Select(reflect.ValueOf(template.Type)))
	if err != nil {
		t.Errorf("cannot marshal template params: %v", err)
	}
	if !bytes.Equal(pp, tp) {
		t.Errorf("public object has wrong params")
	}
}

func verifyRSAAgainstTemplate(t *testing.T, public, template *Public) {
	if len(public.Unique.RSA) != int(template.Params.RSADetail.KeyBits)/8 {
		t.Errorf("public object has wrong public key length (got %d bytes)", len(public.Unique.RSA))
	}
}

func verifyCreationData(t *testing.T, tpm *TPMContext, creationData *CreationData, creationHash Digest, template *Public, outsideInfo Data, creationPCR PCRSelectionList, parent ResourceContext) {
	{
		var tmp PCRSelectionList
		mu.MustCopyValue(&tmp, creationPCR)
		creationPCR = tmp
	}
	v, err := tpm.GetCapabilityTPMProperty(PropertyPCRSelectMin)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}
	for i := range creationPCR {
		if creationPCR[i].SizeOfSelect < uint8(v) {
			creationPCR[i].SizeOfSelect = uint8(v)
		}
	}

	var parentQualifiedName Name
	if parent.Handle().Type() == HandleTypePermanent {
		parentQualifiedName = parent.Name()
	} else {
		var err error
		_, _, parentQualifiedName, err = tpm.ReadPublic(parent)
		if err != nil {
			t.Fatalf("ReadPublic failed: %v", err)
		}
	}

	if !creationData.PCRSelect.Equal(creationPCR) {
		t.Errorf("creation data has invalid pcrSelect")
	}
	if len(creationData.PCRDigest) != template.NameAlg.Size() {
		t.Errorf("creation data has a pcrDigest of the wrong length (got %d)", len(creationData.PCRDigest))
	}
	if creationData.ParentNameAlg != AlgorithmId(parent.Name().Algorithm()) {
		t.Errorf("creation data has the wrong parentNameAlg (got %v)", creationData.ParentNameAlg)
	}
	if !bytes.Equal(creationData.ParentName, parent.Name()) {
		t.Errorf("creation data has the wrong parentName")
	}
	if !bytes.Equal(creationData.ParentQualifiedName, parentQualifiedName) {
		t.Errorf("creation data has the wrong parentQualifiedName")
	}
	if !bytes.Equal(creationData.OutsideInfo, outsideInfo) {
		t.Errorf("creation data has the wrong outsideInfo (got %x)", creationData.OutsideInfo)
	}

	hasher := template.NameAlg.NewHash()
	if _, err := mu.MarshalToWriter(hasher, creationData); err != nil {
		t.Fatalf("Failed to marshal creation data: %v", err)
	}

	if !bytes.Equal(hasher.Sum(nil), creationHash) {
		t.Errorf("Invalid creation hash")
	}
}

func verifyCreationTicket(t *testing.T, creationTicket *TkCreation, hierarchy HandleContext) {
	if creationTicket.Tag != TagCreation {
		t.Errorf("creation ticket has the wrong tag")
	}
	if creationTicket.Hierarchy != hierarchy.Handle() {
		t.Errorf("creation ticket has the wrong hierarchy (got 0x%08x)", creationTicket.Hierarchy)
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

func createRSAEkForTesting(t *testing.T, tpm *TPMContext) ResourceContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
		AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
			0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   &SymKeyBitsU{Sym: 128},
					Mode:      &SymModeU{Sym: SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	objectHandle, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createAndLoadRSAAkForTesting(t *testing.T, tpm *TPMContext, ek ResourceContext, userAuth Auth) ResourceContext {
	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionContext)

	endorsement := tpm.EndorsementHandleContext()
	sessionContext.SetAttrs(AttrContinueSession)

	if _, _, err := tpm.PolicySecret(endorsement, sessionContext, nil, nil, 0, nil); err != nil {
		t.Fatalf("PolicySecret failed: %v", err)
	}

	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrSign,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme: RSAScheme{
					Scheme:  RSASchemeRSASSA,
					Details: &AsymSchemeU{RSASSA: &SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	priv, pub, _, _, _, err := tpm.Create(ek, &sensitiveCreate, &template, nil, nil, sessionContext)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if _, _, err := tpm.PolicySecret(endorsement, sessionContext, nil, nil, 0, nil); err != nil {
		t.Fatalf("PolicySecret failed: %v", err)
	}

	akContext, err := tpm.Load(ek, priv, pub, sessionContext)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	akContext.SetAuthValue(userAuth)
	return akContext
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

// Persist a transient object for testing. If the persistent handle is already in use, it tries to evict the
// existing resource first. Fatal if persisting the transient object fails.
func persistObjectForTesting(t *testing.T, tpm *TPMContext, auth, transient ResourceContext, persist Handle) ResourceContext {
	if context, err := tpm.CreateResourceContextFromTPM(persist); err == nil {
		_, err := tpm.EvictControl(auth, context, persist, nil)
		if err != nil {
			t.Logf("EvictControl failed whilst trying to remove a persistent handle that has previously been leaked: %v", err)
		}
	}
	persistentContext, err := tpm.EvictControl(auth, transient, persist, nil)
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}
	return persistentContext
}

// Evict a persistent object. Fails the test if the resource context is valid but the eviction doesn't succeed.
func evictPersistentObject(t *testing.T, tpm *TPMContext, auth, context ResourceContext) {
	if _, err := tpm.EvictControl(auth, context, context.Handle(), nil); err != nil {
		t.Errorf("EvictControl failed: %v", err)
	}
}

func verifyPersistentObjectEvicted(t *testing.T, tpm *TPMContext, auth, context ResourceContext) {
	if context.Handle() == HandleUnassigned {
		return
	}
	t.Errorf("Context is still live")
	evictPersistentObject(t, tpm, auth, context)
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
