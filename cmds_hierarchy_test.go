// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestCreatePrimary(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, hierarchy Handle, sensitive *SensitiveCreate, template *Public,
		outsideInfo Data, creationPCR PCRSelectionList, session interface{}) (ResourceContext, *Public) {
		objectContext, outPublic, creationData, creationHash, creationTicket, name, err :=
			tpm.CreatePrimary(hierarchy, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}

		if objectContext.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectContext.Handle())
		}
		verifyPublicAgainstTemplate(t, outPublic, template)
		h, _ := tpm.WrapHandle(hierarchy)
		verifyCreationData(t, tpm, creationData, creationHash, template, outsideInfo, creationPCR, h)
		verifyCreationTicket(t, creationTicket, hierarchy)

		nameAlgSize, _ := cryptGetDigestSize(template.NameAlg)
		if len(name) != int(nameAlgSize)+2 {
			t.Errorf("CreatePrimary returned a name of the wrong length %d", len(name))
		}

		return objectContext, outPublic
	}

	t.Run("RSASrk", func(t *testing.T) {
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

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("ECCSrk", func(t *testing.T) {
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

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		if len(pub.Unique.ECC.X) != 32 || len(pub.Unique.ECC.Y) != 32 {
			t.Errorf("CreatePrimary returned object with invalid ECC coords")
		}
	})

	t.Run("Ek", func(t *testing.T) {
		template := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy |
				AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
				0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
				0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{Sym: 128},
						Mode:      SymModeU{Sym: AlgorithmCFB}},
					Scheme:   RSAScheme{Scheme: AlgorithmNull},
					KeyBits:  2048,
					Exponent: 0}}}

		objectContext, pub := run(t, HandleEndorsement, nil, &template, Data{}, PCRSelectionList{}, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("WithAuth", func(t *testing.T) {
		sensitive := SensitiveCreate{UserAuth: Auth(testAuth)}
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

		objectContext, pub := run(t, HandleOwner, &sensitive, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)

		childTemplate := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
				AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    RSAScheme{Scheme: AlgorithmNull},
					KeyBits:   2048,
					Exponent:  0}}}

		_, _, _, _, _, err := tpm.Create(objectContext, nil, &childTemplate, nil, nil, testAuth)
		if err != nil {
			t.Errorf("Use of authorization on primary key failed: %v", err)
		}
	})

	t.Run("RequireAuthPW", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

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

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, testAuth)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("RequireAuthSession", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleOwner)
		defer resetHierarchyAuth(t, tpm, HandleOwner)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil,
			AlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		session := Session{Context: sessionContext, AuthValue: testAuth}

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

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, &session)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("WithOutsideInfo", func(t *testing.T) {
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
		data := Data("foo")

		objectContext, pub := run(t, HandleOwner, nil, &template, data, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("InvalidTemplate", func(t *testing.T) {
		template := Public{
			Type:    AlgorithmECC,
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

		_, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
		if err == nil {
			t.Fatalf("CreatePrimary should fail with an invalid template")
		}
		if err.Error() != "cannot marshal command parameters for command TPM_CC_CreatePrimary: cannot "+
			"marshal pointer type *tpm2.Public2B: cannot marshal struct type tpm2.Public2B: cannot "+
			"marshal sized struct: cannot marshal field Params: cannot marshal struct type "+
			"tpm2.PublicParamsU: error marshalling union struct: cannot marshal pointer type "+
			"*tpm2.ECCParams: nil pointer" {
			t.Errorf("CreatePrimary returned an unexpected error: %v", err)
		}
	})
}

func TestClear(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, auth interface{}) {
		cleared := false

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
		platformPrimary, _, _, _, _, _, err :=
			tpm.CreatePrimary(HandlePlatform, nil, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		defer flushContext(t, tpm, platformPrimary)

		primary := createRSASrkForTesting(t, tpm, nil)
		defer func() {
			if cleared {
				return
			}
			flushContext(t, tpm, primary)
		}()

		platform := platformPrimary.Handle()
		transient := primary.Handle()
		persist := Handle(0x81020000)

		if context, err := tpm.WrapHandle(persist); err == nil {
			_, err := tpm.EvictControl(HandleOwner, context, persist, nil)
			if err != nil {
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of "+
					"the test: %v", err)
			}
		}
		persistentPrimary, err := tpm.EvictControl(HandleOwner, primary, persist, nil)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		defer func() {
			if cleared {
				return
			}
			if _, err := tpm.EvictControl(HandleOwner, persistentPrimary, persist, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()

		setHierarchyAuthForTest(t, tpm, HandleEndorsement)
		defer func() {
			if cleared {
				return
			}
			resetHierarchyAuth(t, tpm, HandleEndorsement)
		}()

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		if err := tpm.Clear(HandleLockout, auth); err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		cleared = true

		handles, err := tpm.GetCapabilityHandles(platform, 1)
		if err != nil {
			t.Errorf("GetCapability failed: %v", err)
		}
		if len(handles) != 1 {
			t.Errorf("Platform transient handle was cleared")
		}

		handles, err = tpm.GetCapabilityHandles(persist, 1)
		if err != nil {
			t.Errorf("GetCapability failed: %v", err)
		}
		if len(handles) != 0 {
			t.Errorf("Persistent handle was not cleared")
		}

		handles, err = tpm.GetCapabilityHandles(transient, 1)
		if err != nil {
			t.Errorf("GetCapability failed: %v", err)
		}
		if len(handles) != 0 {
			t.Errorf("Transient handle was not cleared")
		}

		if platformPrimary.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("Platform transient handle should not have been invalidated")
		}
		if primary.Handle() != HandleNull {
			t.Errorf("Transient handle should have been invalidated")
		}
		if persistentPrimary.Handle() != HandleNull {
			t.Errorf("Persistent handle should have been invalidated")
		}
		if owner.Handle() != HandleOwner {
			t.Errorf("Permanent handle should not have been invalidated")
		}
		if sessionContext.Handle()&HandleTypePolicySession != HandleTypePolicySession {
			t.Errorf("Session handle should not have been invalidated")
		}
		props, err := tpm.GetCapabilityTPMProperties(PropertyPermanent, 1)
		if err != nil {
			t.Fatalf("GetCapability failed: %v", err)
		}
		if PermanentAttributes(props[0].Value)&AttrEndorsementAuthSet > 0 {
			t.Errorf("Clear did not clear the EH auth")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("RequirePW", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		cleared := false
		defer func() {
			if cleared {
				return
			}
			resetHierarchyAuth(t, tpm, HandleLockout)
		}()
		run(t, testAuth)
		cleared = true
	})
	t.Run("RequireSession", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		cleared := false
		defer func() {
			if cleared {
				return
			}
			resetHierarchyAuth(t, tpm, HandleLockout)
		}()
		lockout, _ := tpm.WrapHandle(HandleLockout)
		sessionContext, err := tpm.StartAuthSession(nil, lockout, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, AuthValue: testAuth})
		cleared = true
	})
	t.Run("RequireUnboundSession", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		cleared := false
		defer func() {
			if cleared {
				return
			}
			resetHierarchyAuth(t, tpm, HandleLockout)
		}()
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, AuthValue: testAuth})
		cleared = true
	})
}

func TestHierarchyChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run1 := func(t *testing.T, hierarchy Handle, session interface{}) {
		if err := tpm.HierarchyChangeAuth(hierarchy, Auth(testAuth), session); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}

	run2 := func(t *testing.T, hierarchy Handle, session interface{},
		createPrimary func(*testing.T, TPMContext, interface{}) ResourceContext) {
		primary := createPrimary(t, tpm, session)
		flushContext(t, tpm, primary)

		if err := tpm.HierarchyChangeAuth(hierarchy, nil, session); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}
	}

	resetHierarchyAuthIgnoringErrors := func(t *testing.T, hierarchy Handle) {
		tpm.HierarchyChangeAuth(hierarchy, nil, testAuth)
	}

	createSrk := func(t *testing.T, tpm TPMContext, session interface{}) ResourceContext {
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
		objectContext, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil,
			session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectContext
	}
	createEk := func(t *testing.T, tpm TPMContext, session interface{}) ResourceContext {
		template := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy |
				AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc,
				0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64,
				0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{Sym: 128},
						Mode:      SymModeU{Sym: AlgorithmCFB}},
					Scheme:   RSAScheme{Scheme: AlgorithmNull},
					KeyBits:  2048,
					Exponent: 0}}}
		objectContext, _, _, _, _, _, err := tpm.CreatePrimary(HandleEndorsement, nil, &template, nil, nil,
			session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectContext
	}

	t.Run("OwnerWithPW", func(t *testing.T) {
		run1(t, HandleOwner, nil)
		defer resetHierarchyAuthIgnoringErrors(t, HandleOwner)

		run2(t, HandleOwner, testAuth, createSrk)
	})

	t.Run("EndorsementWithPW", func(t *testing.T) {
		run1(t, HandleEndorsement, nil)
		defer resetHierarchyAuthIgnoringErrors(t, HandleEndorsement)

		run2(t, HandleEndorsement, testAuth, createEk)
	})

	t.Run("OwnerWithBoundHMACSession", func(t *testing.T) {
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionContext, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run1(t, HandleOwner, &session)
		defer resetHierarchyAuthIgnoringErrors(t, HandleOwner)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		session := Session{Context: sessionContext, Attrs: AttrContinueSession}

		run1(t, HandleOwner, &session)
		defer resetHierarchyAuthIgnoringErrors(t, HandleOwner)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})
}
