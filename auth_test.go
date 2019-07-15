package tpm2

import (
	"testing"
)

func TestHMACUnboundSession(t *testing.T) {
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

	sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

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

	session := &Session{Handle: sessionHandle, AuthValue: []byte("1234"), Attributes: AttrContinueSession}

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, session)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	// TODO: The response HMAC is calculated with the new auth value, and this currently fails
	//if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
	//	t.Fatalf("HierarchyChangeAuth failed: %v", err)
	//}
	//resetAuth = false
}

func TestHMACBoundSession(t *testing.T) {
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

	owner, err := tpm.WrapHandle(HandleOwner)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}

	sessionHandle, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, "1234")
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

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

	session := &Session{Handle: sessionHandle, Attributes: AttrContinueSession}

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, session)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false
}

func TestHMACBoundUncontinuedSession(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth("1234"), ""); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	defer func() {
		if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, "1234"); err != nil {
			t.Errorf("Failed to reset hierarchy auth: %v", err)
		}
	}()

	owner, err := tpm.WrapHandle(HandleOwner)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}

	sessionHandle, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, "1234")
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	sessionConsumed := false
	defer func() {
		if sessionConsumed {
			return
		}
		flushContext(t, tpm, sessionHandle)
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

	session := &Session{Handle: sessionHandle}

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, session)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	err = tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session)
	if err == nil {
		t.Fatalf("Subsequent use of the session should fail")
	}
	if err.Error() != "TPM returned warning code: 0x18" {
		t.Errorf("Subsequent use of the session failed with an unexpected error: %v", err)
	}
	sessionConsumed = true
}
