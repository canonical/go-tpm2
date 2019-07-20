package tpm2

import (
	"bytes"
	"flag"
	"reflect"
	"testing"
)

var tpmPath = flag.String("tpm-path", "", "")

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
	if len(public.Unique.RSA) != int(template.Params.RSADetail.KeyBits)/8 {
		t.Errorf("public object has wrong public key length (got %d bytes)", len(public.Unique.RSA))
	}
}

func verifyCreationData(t *testing.T, tpm TPM, creationData *CreationData, template *Public, outsideInfo Data,
	creationPCR PCRSelectionList, parent ResourceContext) {
	nameAlgSize, _ := digestSizes[template.NameAlg]
	var parentQualifiedName Name
	if parent.Handle()&HandleTypePermanent == HandleTypePermanent {
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
	if len(creationData.PCRDigest) != int(nameAlgSize) {
		t.Errorf("creation data has a pcrDigest of the wrong length (got %d)",
			len(creationData.PCRDigest))
	}
	if creationData.ParentNameAlg != nameAlgorithm(parent.Name()) {
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
}

func verifyCreationHash(t *testing.T, creationHash Digest, template *Public) {
	nameAlgSize, _ := digestSizes[template.NameAlg]
	if len(creationHash) != int(nameAlgSize) {
		t.Errorf("creation hash is the wrong length (%d bytes)", len(creationHash))
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

func createRSASrkForTesting(t *testing.T, tpm TPM, userAuth Auth) ResourceContext {
	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, &sensitiveCreate, &template, nil,
		nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func createECCSrkForTesting(t *testing.T, tpm TPM, userAuth Auth) (ResourceContext, Name) {
	template := Public{
		Type:    AlgorithmECC,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			ECCDetail: &ECCParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:  ECCScheme{Scheme: AlgorithmNull},
				CurveID: ECCCurveNIST_P256,
				KDF:     KDFScheme{Scheme: AlgorithmNull}}},
		Unique: PublicIDU{ECC: &ECCPoint{}}}
	sensitiveCreate := SensitiveCreate{UserAuth: userAuth}
	objectHandle, _, _, _, _, name, err := tpm.CreatePrimary(HandleOwner, &sensitiveCreate, &template, nil,
		nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle, name
}

func createRSAEkForTesting(t *testing.T, tpm TPM) ResourceContext {
	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy |
			AttrRestricted | AttrDecrypt,
		AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46,
			0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b,
			0x33, 0x14, 0x69, 0xaa},
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   SymKeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleEndorsement, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	return objectHandle
}

func nameAlgorithm(n Name) AlgorithmId {
	if len(n) == 4 {
		return AlgorithmNull
	}
	var alg AlgorithmId
	UnmarshalFromBytes([]byte(n), &alg)
	return alg
}

func openTPMForTesting(t *testing.T) TPM {
	if *tpmPath == "" {
		t.SkipNow()
	}
	tpm, err := OpenTPM(&TctiConfig{Backend: TctiBackendDevice, Conf: *tpmPath})
	if err != nil {
		t.Fatalf("Failed to open the TPM device: %v", err)
	}
	return tpm
}

func flushContext(t *testing.T, tpm TPM, handle ResourceContext) {
	if err := tpm.FlushContext(handle); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
}

func verifySessionFlushed(t *testing.T, tpm TPM, handle ResourceContext) {
	context, isSession := handle.(*sessionContext)
	if !isSession {
		t.Errorf("handle is not a session context")
	}
	if context.tpm == nil {
		return
	}
	t.Errorf("Session is still live")
	flushContext(t, tpm, handle)
}
