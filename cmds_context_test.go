package tpm2

import (
	"testing"
)

func TestEvictControl(t *testing.T) {
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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Failed to create primary object: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectHandle.Handle())
	}

	persist := Handle(0x81020000)
	outHandle, err := tpm.EvictControl(HandleOwner, objectHandle, persist, "")
	if err != nil {
		t.Fatalf("EvictControl failed: %v", err)
	}

	if outHandle.Handle() != persist {
		t.Errorf("outHandle has the wrong id (0x%08x)", outHandle.Handle())
	}

	outHandle2, err := tpm.EvictControl(HandleOwner, outHandle, outHandle.Handle(), "")
	if err != nil {
		t.Errorf("EvictControl failed: %v", err)
	}
	if outHandle2 != nil {
		t.Errorf("EvictControl should return a nil handle when evicting a persistent object")
	}

	_, err = tpm.EvictControl(HandleOwner, outHandle, outHandle.Handle(), "")
	if err == nil {
		t.Fatalf("EvictControl should return an error when called with a dead resource")
	}
	if err.Error() != "invalid resource object supplied: resource has been closed" {
		t.Errorf("EvictControl returned an unexpected error: %v", err)
	}
}

func TestFlushContext(t *testing.T) {
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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, &SensitiveCreate{}, &template, nil,
		PCRSelectionList{}, "")
	if err != nil {
		t.Fatalf("Failed to create primary object: %v", err)
	}

	h := objectHandle.Handle()

	if err := tpm.FlushContext(objectHandle); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}

	handles, err := tpm.GetCapabilityHandles(h, 1)
	if err != nil {
		t.Errorf("GetCapability failed: %v", err)
	}
	if len(handles) != 0 {
		t.Errorf("FlushContext didn't flush the transient handle")
	}

	err = tpm.FlushContext(objectHandle)
	if err == nil {
		t.Errorf("Calling FlushContext on a dead resource context should fail")
	}
	if err.Error() != "invalid resource object supplied: resource has been closed" {
		t.Errorf("FlushContext returned an unexpected error: %v", err)
	}
}
