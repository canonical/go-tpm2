package tpm2

import (
	"bytes"
	"reflect"
	"testing"
)

func verifyPublicAgainstTemplate(t *testing.T, template, public *Public) {
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

func createPrimary(t *testing.T, tpm TPM) (Resource, Name) {
	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrRestricted | AttrDecrypt,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{
					Algorithm: AlgorithmAES,
					KeyBits:   KeyBitsU{Sym: 128},
					Mode:      SymModeU{Sym: AlgorithmCFB}},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	objectHandle, _, _, _, _, name, err := tpm.CreatePrimary(HandleOwner, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Failed to create primary object: %v", err)
	}
	return objectHandle, name
}

func TestCreate(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary, primaryName := createPrimary(t, tpm)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrDecrypt | AttrSign,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	creationPCR := PCRSelectionList{
		PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1}},
		PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

	outPrivate, outPublic, creationData, creationHash, creationTicket, err := tpm.Create(primary,
		&SensitiveCreate{}, &template, nil, creationPCR, "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	if len(outPrivate) == 0 {
		t.Errorf("Create returned a zero sized private part")
	}

	verifyPublicAgainstTemplate(t, &template, outPublic)

	if !reflect.DeepEqual(creationData.PCRSelect, creationPCR) {
		t.Errorf("Create returned invalid creationData.pcrSelect")
	}
	if len(creationData.PCRDigest) != 32 {
		t.Errorf("Create returned a creationData.pcrDigest of the wrong length %d",
			len(creationData.PCRDigest))
	}
	if creationData.ParentNameAlg != AlgorithmSHA256 {
		t.Errorf("Create returned the wrong creationData.parentNameAlg")
	}
	if !bytes.Equal(creationData.ParentName, primaryName) {
		t.Errorf("Create returned the wrong creationData.parentName")
	}
	if len(creationData.ParentQualifiedName) != 34 {
		t.Errorf("Create returned the a creationData.parentQualifiedName of the wrong length")
	}

	if len(creationHash) != 32 {
		t.Errorf("Create returned a creation hash of the wrong length %d", len(creationHash))
	}

	if creationTicket.Tag != TagCreation {
		t.Errorf("Create returned an invalid creationTicket.tag value")
	}
	if creationTicket.Hierarchy != HandleOwner {
		t.Errorf("Create returned an invalid creationTicket.hierarchy value")
	}
}

func TestLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary, _ := createPrimary(t, tpm)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrDecrypt | AttrSign,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectHandle, name, err := tpm.Load(primary, outPrivate, outPublic, "")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("Create returned an invalid handle 0x%08x", objectHandle.Handle())
	}
	if len(name) != 34 {
		t.Errorf("Create returned a name of the wrong length %d", len(name))
	}
}

func TestReadPublic(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary, _ := createPrimary(t, tpm)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
			AttrDecrypt | AttrSign,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectHandle, name1, err := tpm.Load(primary, outPrivate, outPublic, "")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	public, name2, qualifiedName, err := tpm.ReadPublic(objectHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	verifyPublicAgainstTemplate(t, &template, public)

	if !bytes.Equal(name1, name2) {
		t.Errorf("ReadPublic returned an unexpected name")
	}
	if len(qualifiedName) != 34 {
		t.Errorf("ReadPublic returned a qualifiedName of the wrong length")
	}
}

func TestLoadExternal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary, _ := createPrimary(t, tpm)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs: AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
		Params: PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme:   RSAScheme{Scheme: AlgorithmNull},
				KeyBits:  2048,
				Exponent: 0}}}
	_, outPublic, _, _, _, err := tpm.Create(primary, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectHandle, name, err := tpm.LoadExternal(nil, outPublic, HandleOwner)
	if err != nil {
		t.Fatalf("LoadExternal failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("LoadExternal returned an invalid handle 0x%08x", objectHandle.Handle())
	}
	if len(name) != 34 {
		t.Errorf("LoadExternal returned a name of the wrong length")
	}
}
