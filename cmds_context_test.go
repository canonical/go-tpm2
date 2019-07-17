package tpm2

import (
	"bytes"
	"testing"
)

func TestContextSaveTransient(t *testing.T) {
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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, "")
	if err != nil {
		t.Fatalf("Failed to create primary object: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	context, err := tpm.ContextSave(objectHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}
	if context.SavedHandle != objectHandle.Handle() {
		t.Errorf("context has an unexpected handle (0x%08x)", context.SavedHandle)
	}
	if context.Hierarchy != HandleOwner {
		t.Errorf("context specifies the wrong hierarchy (0x%08x)", context.Hierarchy)
	}
}

func TestContextLoadTransient(t *testing.T) {
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
	objectHandle, _, _, _, _, name, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, "")
	if err != nil {
		t.Fatalf("Failed to create primary object: %v", err)
	}
	flushed := false
	defer func() {
		if flushed {
			return
		}
		flushContext(t, tpm, objectHandle)
	}()

	context, err := tpm.ContextSave(objectHandle)
	if err != nil {
		t.Fatalf("ContextSave failed: %v", err)
	}

	if err := tpm.FlushContext(objectHandle); err != nil {
		t.Fatalf("FlushContext failed: %v", err)
	}
	flushed = true

	restoredHandle, err := tpm.ContextLoad(context)
	if err != nil {
		t.Fatalf("ContextLoad failed: %v", err)
	}
	defer flushContext(t, tpm, restoredHandle)

	if restoredHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
		t.Errorf("ContextLoad returned an invalid handle 0x%08x", restoredHandle.Handle())
	}

	_, restoredName, _, err := tpm.ReadPublic(restoredHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	if !bytes.Equal(name, restoredName) {
		t.Errorf("Name of restored object doesn't match that of the saved object")
	}
}

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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, "")
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
	if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
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
	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, "")
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

	_, _, _, err = tpm.ReadPublic(objectHandle)
	if err == nil {
		t.Errorf("Calling ReadPublic on a dead resource context should fail")
	}
	if err.Error() != "invalid resource context for objectHandle: resource has been closed" {
		t.Errorf("ReadPublic returned an unexpected error: %v", err)
	}
}
