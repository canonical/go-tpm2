package tpm2

import (
	"reflect"
	"testing"
)

func verifyCreatePrimaryCommon(t *testing.T, objectHandle ResourceContext, nameAlgSize int, template,
	outPublic *Public, creationPCR PCRSelectionList, creationData *CreationData, creationHash Digest,
	creationTicket *TkCreation, name Name) {
	if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectHandle.Handle())
	}
	verifyPublicAgainstTemplate(t, template, outPublic)

	if !reflect.DeepEqual(creationData.PCRSelect, creationPCR) {
		t.Errorf("CreatePrimary returned invalid creationData.pcrSelect")
	}
	if len(creationData.PCRDigest) != nameAlgSize {
		t.Errorf("CreatePrimary returned a creationData.pcrDigest of the wrong length %d",
			len(creationData.PCRDigest))
	}
	if creationData.ParentNameAlg != AlgorithmNull {
		t.Errorf("CreatePrimary should return a null creationData.parentNameAlg")
	}
	if !creationData.ParentName.IsHandle() {
		t.Errorf("CreatePrimary returned a creationData.parentName that isn't a handle")
	} else if creationData.ParentName.Handle() != HandleOwner {
		t.Errorf("CreatePrimary returned a creationData.parentName with the wrong handle 0x%08x",
			creationData.ParentName.Handle())
	}
	if !creationData.ParentQualifiedName.IsHandle() {
		t.Errorf("CreatePrimary returned a creationData.parentQualifiedName that isn't a handle")
	} else if creationData.ParentQualifiedName.Handle() != HandleOwner {
		t.Errorf("CreatePrimary returned a creationData.parentQualifiedName with the wrong handle 0x%08x",
			creationData.ParentQualifiedName.Handle())
	}

	if len(creationHash) != nameAlgSize {
		t.Errorf("CreatePrimary returned a creation hash of the wrong length %d", len(creationHash))
	}

	if creationTicket.Tag != TagCreation {
		t.Errorf("CreatePrimary returned an invalid creationTicket.tag value")
	}
	if creationTicket.Hierarchy != HandleOwner {
		t.Errorf("CreatePrimary returned an invalid creationTicket.hierarchy value")
	}

	if len(name) != nameAlgSize+2 {
		t.Errorf("CreatePrimary returned a name of the wrong length %d", len(name))
	}
}

func TestCreateStoragePrimaryRSA(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

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

	creationPCR := PCRSelectionList{
		PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1}},
		PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

	objectHandle, outPublic, creationData, creationHash, creationTicket, name, err := tpm.CreatePrimary(
		HandleOwner, nil, &template, nil, creationPCR, "")
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	verifyCreatePrimaryCommon(t, objectHandle, 32, &template, outPublic, creationPCR, creationData,
		creationHash, creationTicket, name)
	if len(outPublic.Unique.RSA) != 2048/8 {
		t.Errorf("CreatePrimary returned object with wrong public key length %d",
			len(outPublic.Unique.RSA))
	}
}

func TestCreateStoragePrimaryECC(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	template := Public{
		Type:    AlgorithmECC,
		NameAlg: AlgorithmSHA1,
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

	creationPCR := PCRSelectionList{
		PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1}},
		PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

	objectHandle, outPublic, creationData, creationHash, creationTicket, name, err := tpm.CreatePrimary(
		HandleOwner, nil, &template, nil, creationPCR, "")
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	verifyCreatePrimaryCommon(t, objectHandle, 20, &template, outPublic, creationPCR, creationData,
		creationHash, creationTicket, name)
	if len(outPublic.Unique.ECC.X) != 32 || len(outPublic.Unique.ECC.Y) != 32 {
		t.Errorf("CreatePrimary returned object with invalid ECC coords")
	}
}

func TestHierarchyChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth("1234"), ""); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth := true
	defer func() {
		if !resetAuth {
			return
		}
		if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, "1234"); err != nil {
			t.Errorf("Failed to reset hierarchy auth: %v", err)
		}
	}()

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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(
		HandleOwner, &SensitiveCreate{}, &template, nil, PCRSelectionList{}, "1234")
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	persistHandle, err := tpm.EvictControl(HandleOwner, objectHandle, Handle(0x81020000), "1234")
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, "1234"); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false

	_, err = tpm.EvictControl(HandleOwner, persistHandle, persistHandle.Handle(), "")
	if err != nil {
		t.Errorf("EvictControl failed: %v", err)
	}
}
