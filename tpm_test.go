// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

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
)

var useTpm = flag.Bool("use-tpm", false, "")
var tpmPath = flag.String("tpm-path", "/dev/tpm0", "")

var useMssim = flag.Bool("use-mssim", false, "")
var mssimHost = flag.String("mssim-host", "localhost", "")
var mssimTpmPort = flag.Uint("mssim-tpm-port", 2321, "")
var mssimPlatformPort = flag.Uint("mssim-platform-port", 2322, "")

var (
	dummyAuth = []byte("dummy")
	testAuth  = []byte("1234")
)

// Set the hierarchy auth to testAuth. Fatal on failure
func setHierarchyAuthForTest(t *testing.T, tpm *TPMContext, hierarchy Handle) {
	h, _ := tpm.WrapHandle(hierarchy)
	if err := tpm.HierarchyChangeAuth(h, Auth(testAuth), nil); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
}

// Reset the hierarchy auth from testAuth to nil. Will succeed if HierarchyChangeAuth succeeds, or if it fails
// because the hierarchy auth has already been reset by another action in the test. Otherwise it causes the test
// to fail.
func resetHierarchyAuth(t *testing.T, tpm *TPMContext, hierarchy Handle) {
	if hierarchy == HandleLockout {
		// Lockout auth is DA protected, so don't attempt to reset if it has already been done by the test
		if props, err := tpm.GetCapabilityTPMProperties(PropertyPermanent, 1); err != nil {
			t.Errorf("GetCapability failed: %v", err)
		} else if PermanentAttributes(props[0].Value)&AttrLockoutAuthSet == 0 {
			return
		}
	}
	h, _ := tpm.WrapHandle(hierarchy)
	if err := tpm.HierarchyChangeAuth(h, nil, testAuth); err != nil {
		switch hierarchy {
		case HandleLockout:
		case HandlePlatform:
			if err := tpm.HierarchyChangeAuth(h, nil, nil); err == nil {
				return
			}
		default:
			var attr PermanentAttributes
			switch hierarchy {
			case HandleOwner:
				attr = AttrOwnerAuthSet
			case HandleEndorsement:
				attr = AttrEndorsementAuthSet
			}
			if props, err := tpm.GetCapabilityTPMProperties(PropertyPermanent, 1); err != nil {
				t.Errorf("GetCapability failed: %v", err)
			} else if PermanentAttributes(props[0].Value)&attr == 0 {
				return
			}
		}
		t.Errorf("HierarchyChangeAuth failed: %v", err)
	}
}

// Undefine a NV index set by a test. Fails the test if it doesn't succeed.
func undefineNVSpace(t *testing.T, tpm *TPMContext, context, authHandle HandleContext, auth interface{}) {
	if err := tpm.NVUndefineSpace(authHandle, context, auth); err != nil {
		t.Errorf("NVUndefineSpace failed: %v", err)
	}
}

func verifyNVSpaceUndefined(t *testing.T, tpm *TPMContext, context, authHandle HandleContext, auth interface{}) {
	if context.Handle() == HandleUnassigned {
		return
	}
	t.Errorf("Context is still live")
	undefineNVSpace(t, tpm, context, authHandle, auth)
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
	if !reflect.DeepEqual(public.Params, template.Params) {
		t.Errorf("public object has wrong params")
	}
}

func verifyRSAAgainstTemplate(t *testing.T, public, template *Public) {
	if len(public.Unique.RSA()) != int(template.Params.RSADetail().KeyBits)/8 {
		t.Errorf("public object has wrong public key length (got %d bytes)", len(public.Unique.RSA()))
	}
}

func verifyCreationData(t *testing.T, tpm *TPMContext, creationData *CreationData, creationHash Digest,
	template *Public, outsideInfo Data, creationPCR PCRSelectionList, parent HandleContext) {
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

	if !reflect.DeepEqual(creationData.PCRSelect, creationPCR) {
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
	if err := MarshalToWriter(hasher, creationData); err != nil {
		t.Fatalf("Failed to marshal creation data: %v", err)
	}

	if !bytes.Equal(hasher.Sum(nil), creationHash) {
		t.Errorf("Invalid creation hash")
	}
}

func verifyCreationTicket(t *testing.T, creationTicket *TkCreation, hierarchy Handle) {
	if creationTicket.Tag != TagCreation {
		t.Errorf("creation ticket has the wrong tag")
	}
	if creationTicket.Hierarchy != hierarchy {
		t.Errorf("creation ticket has the wrong hierarchy (got 0x%08x)", creationTicket.Hierarchy)
	}
}

func computePCRDigestFromTPM(t *testing.T, tpm *TPMContext, alg HashAlgorithmId, pcrs PCRSelectionList) Digest {
	_, pcrValues, err := tpm.PCRRead(pcrs)
	if err != nil {
		t.Fatalf("PCRRead failed: %v", err)
	}

	digest, err := ComputePCRDigest(alg, pcrs, pcrValues)
	if err != nil {
		t.Fatalf("ComputePCRDigest failed: %v", err)
	}

	return digest
}

func verifySignature(t *testing.T, pub *Public, digest []byte, signature *Signature) {
	switch pub.Type {
	case ObjectTypeRSA:
		exp := int(pub.Params.RSADetail().Exponent)
		if exp == 0 {
			exp = defaultRSAExponent
		}
		pubKey := rsa.PublicKey{N: new(big.Int).SetBytes(pub.Unique.RSA()), E: exp}

		switch signature.SigAlg {
		case SigSchemeAlgRSASSA:
			sig := (*SignatureRSA)(signature.Signature.RSASSA())
			if !sig.Hash.Supported() {
				t.Fatalf("Signature has unknown digest")
			}
			if err := rsa.VerifyPKCS1v15(&pubKey, sig.Hash.GetHash(), digest, sig.Sig); err != nil {
				t.Errorf("Signature is invalid")
			}
		case SigSchemeAlgRSAPSS:
			sig := (*SignatureRSA)(signature.Signature.RSAPSS())
			if !sig.Hash.Supported() {
				t.Fatalf("Signature has unknown digest")
			}
			if err := rsa.VerifyPSS(&pubKey, sig.Hash.GetHash(), digest, sig.Sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
				t.Errorf("Signature is invalid")
			}
		default:
			t.Errorf("Unknown signature algorithm")
		}
	case ObjectTypeECC:
		pubKey := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(pub.Unique.ECC().X), Y: new(big.Int).SetBytes(pub.Unique.ECC().Y)}

		switch signature.SigAlg {
		case SigSchemeAlgECDSA:
			sig := signature.Signature.ECDSA()
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

func createRSASrkForTesting(t *testing.T, tpm *TPMContext, userAuth Auth) HandleContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			&RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   SymKeyBitsU{uint16(128)},
					Mode:      SymModeU{SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	owner, _ := tpm.WrapHandle(HandleOwner)
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(owner, &sensitiveCreate, &template, nil,
		nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createECCSrkForTesting(t *testing.T, tpm *TPMContext, userAuth Auth) HandleContext {
	template := Public{
		Type:    ObjectTypeECC,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrNoDA | AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			&ECCParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   SymKeyBitsU{uint16(128)},
					Mode:      SymModeU{SymModeCFB}},
				Scheme:  ECCScheme{Scheme: ECCSchemeNull},
				CurveID: ECCCurveNIST_P256,
				KDF:     KDFScheme{Scheme: KDFAlgorithmNull}}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	owner, _ := tpm.WrapHandle(HandleOwner)
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(owner, &sensitiveCreate, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createRSAEkForTesting(t *testing.T, tpm *TPMContext) HandleContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
		AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
			0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
		Params: PublicParamsU{
			&RSAParams{
				Symmetric: SymDefObject{
					Algorithm: SymObjectAlgorithmAES,
					KeyBits:   SymKeyBitsU{uint16(128)},
					Mode:      SymModeU{SymModeCFB}},
				Scheme:   RSAScheme{Scheme: RSASchemeNull},
				KeyBits:  2048,
				Exponent: 0}}}
	endorsement, _ := tpm.WrapHandle(HandleEndorsement)
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(endorsement, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createAndLoadRSAAkForTesting(t *testing.T, tpm *TPMContext, ek HandleContext, userAuth Auth) HandleContext {
	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, HashAlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionContext)

	endorsement, _ := tpm.WrapHandle(HandleEndorsement)
	session := Session{Context: sessionContext, Attrs: AttrContinueSession}

	if _, _, err := tpm.PolicySecret(endorsement, sessionContext, nil, nil, 0, nil); err != nil {
		t.Fatalf("PolicySecret failed: %v", err)
	}

	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrSign,
		Params: PublicParamsU{
			&RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme: RSAScheme{
					Scheme:  RSASchemeRSASSA,
					Details: AsymSchemeU{&SigSchemeRSASSA{HashAlg: HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	priv, pub, _, _, _, err := tpm.Create(ek, &sensitiveCreate, &template, nil, nil, &session)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if _, _, err := tpm.PolicySecret(endorsement, sessionContext, nil, nil, 0, nil); err != nil {
		t.Fatalf("PolicySecret failed: %v", err)
	}

	akContext, _, err := tpm.Load(ek, priv, pub, &session)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	return akContext
}

func createAndLoadRSAPSSKeyForTesting(t *testing.T, tpm *TPMContext, parent HandleContext) HandleContext {
	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme: RSAScheme{
					Scheme: RSASchemeRSAPSS,
					Details: AsymSchemeU{
						Data: &SigSchemeRSAPSS{HashAlg: HashAlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	priv, pub, _, _, _, err := tpm.Create(parent, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, _, err := tpm.Load(parent, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	return key
}

// Persist a transient object for testing. If the persistent handle is already in use, it tries to evict the
// existing resource first. Fatal if persisting the transient object fails.
func persistObjectForTesting(t *testing.T, tpm *TPMContext, auth, transient HandleContext, persist Handle) HandleContext {
	if context, err := tpm.WrapHandle(persist); err == nil {
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
func evictPersistentObject(t *testing.T, tpm *TPMContext, auth, context HandleContext) {
	if _, err := tpm.EvictControl(auth, context, context.Handle(), nil); err != nil {
		t.Errorf("EvictControl failed: %v", err)
	}
}

func verifyPersistentObjectEvicted(t *testing.T, tpm *TPMContext, auth, context HandleContext) {
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

func openTPMSimulatorForTesting(t *testing.T) (*TPMContext, *TctiMssim) {
	if !*useMssim {
		t.SkipNow()
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	tcti, err := OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
	if err != nil {
		t.Fatalf("Failed to open mssim connection: %v", err)
	}

	tpm, _ := NewTPMContext(tcti)
	return tpm, tcti
}

func resetTPMSimulator(t *testing.T, tpm *TPMContext, tcti *TctiMssim) {
	if err := tpm.Shutdown(StartupClear); err != nil {
		t.Fatalf("Shutdown failed: %v", err)
	}
	if err := tcti.Reset(); err != nil {
		t.Fatalf("Resetting the TPM simulator failed: %v", err)
	}
	if err := tpm.Startup(StartupClear); err != nil {
		t.Fatalf("Startup failed: %v", err)
	}
}

func openTPMForTesting(t *testing.T) *TPMContext {
	if !*useTpm {
		tpm, _ := openTPMSimulatorForTesting(t)
		return tpm
	}

	if *useTpm && *useMssim {
		t.Fatalf("Cannot specify both -use-tpm and -use-mssim")
	}

	tcti, err := OpenTPMDevice(*tpmPath)
	if err != nil {
		t.Fatalf("Failed to open the TPM device: %v", err)
	}

	tpm, _ := NewTPMContext(tcti)
	return tpm
}

func closeTPM(t *testing.T, tpm *TPMContext) {
	if err := tpm.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}

type mockContext struct{}

func (*mockContext) Handle() Handle { return HandleNull }
func (*mockContext) Name() Name     { return nil }

func TestSession(t *testing.T) {
	auth1 := []byte("foo")
	auth2 := []byte("bar")

	c := &mockContext{}
	s := Session{Context: c, AuthValue: auth1, Attrs: AttrContinueSession}

	s2 := s.WithAuthValue(auth2)
	if s.Context != s2.Context {
		t.Errorf("Wrong context")
	}
	if s.Attrs != s2.Attrs {
		t.Errorf("Wrong attrs")
	}
	if !bytes.Equal(s2.AuthValue, auth2) {
		t.Errorf("Wrong auth value")
	}

	s3 := s2.WithAttrs(AttrResponseEncrypt)
	if s.Context != s3.Context {
		t.Errorf("Wrong context")
	}
	if s3.Attrs != AttrResponseEncrypt {
		t.Errorf("Wrong attrs")
	}
	if !bytes.Equal(s2.AuthValue, s3.AuthValue) {
		t.Errorf("Wrong auth value")
	}

	s4 := s3.AddAttrs(AttrCommandEncrypt)
	if s.Context != s4.Context {
		t.Errorf("Wrong context")
	}
	if s4.Attrs != AttrResponseEncrypt|AttrCommandEncrypt {
		t.Errorf("Wrong attrs")
	}
	if !bytes.Equal(s2.AuthValue, s4.AuthValue) {
		t.Errorf("Wrong auth value")
	}

	s5 := s4.RemoveAttrs(AttrResponseEncrypt)
	if s.Context != s5.Context {
		t.Errorf("Wrong context")
	}
	if s5.Attrs != AttrCommandEncrypt {
		t.Errorf("Wrong attrs")
	}
	if !bytes.Equal(s2.AuthValue, s5.AuthValue) {
		t.Errorf("Wrong auth value")
	}
}

func TestMain(m *testing.M) {
	flag.Parse()
	os.Exit(func() int {
		if *useMssim {
			tcti, err := OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open mssim connection: %v", err)
				return 1
			}

			tpm, _ := NewTPMContext(tcti)
			if err := func() error {
				defer tpm.Close()
				return tpm.Startup(StartupClear)
			}(); err != nil {
				fmt.Fprintf(os.Stderr, "Simulator startup failed: %v\n", err)
				return 1
			}
		}

		defer func() {
			if !*useMssim {
				return
			}

			tcti, err := OpenMssim(*mssimHost, *mssimTpmPort, *mssimPlatformPort)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to open mssim connection: %v\n", err)
				return
			}

			tpm, _ := NewTPMContext(tcti)
			if err := tpm.Shutdown(StartupClear); err != nil {
				fmt.Fprintf(os.Stderr, "TPM simulator shutdown failed: %v\n", err)
			}
			if err := tcti.Stop(); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to stop TPM simulator: %v\n", err)
			}
			tpm.Close()
		}()

		return m.Run()
	}())
}
