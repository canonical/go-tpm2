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

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false
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
	warning, isWarning := err.(TPMWarning)
	if !isWarning || warning.Code != WarningReferenceS0 {
		t.Errorf("Subsequent use of the session failed with an unexpected error: %v", err)
	}
	sessionConsumed = true
}

func TestHMACBoundSessionOnOtherResource(t *testing.T) {
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

	endorsement, err := tpm.WrapHandle(HandleEndorsement)
	if err != nil {
		t.Fatalf("WrapHandle failed: %v", err)
	}

	sessionHandle, err := tpm.StartAuthSession(nil, endorsement, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	srkTemplate := Public{
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

	srkHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &srkTemplate, nil, nil, session)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, srkHandle)

	ekTemplate := Public{
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

	ekHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleEndorsement, nil, &ekTemplate, nil, nil,
		&Session{Handle: sessionHandle, Attributes: AttrContinueSession})
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, ekHandle)

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false
}

func TestHMACUnboundSaltedSessionRSA(t *testing.T) {
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

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

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

	sessionHandle, err := tpm.StartAuthSession(objectHandle, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	session := &Session{Handle: sessionHandle, AuthValue: []byte("1234"), Attributes: AttrContinueSession}

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false
}

func TestHMACUnboundSaltedSessionECC(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

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

	objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("CreatePrimary failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

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

	sessionHandle, err := tpm.StartAuthSession(objectHandle, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	session := &Session{Handle: sessionHandle, AuthValue: []byte("1234"), Attributes: AttrContinueSession}

	if err := tpm.HierarchyChangeAuth(HandleOwner, Auth{}, session); err != nil {
		t.Fatalf("HierarchyChangeAuth failed: %v", err)
	}
	resetAuth = false
}
