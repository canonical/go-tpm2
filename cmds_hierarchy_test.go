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
		objectHandle, outPublic, creationData, creationHash, creationTicket, name, err :=
			tpm.CreatePrimary(hierarchy, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}

		if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectHandle.Handle())
		}
		verifyPublicAgainstTemplate(t, outPublic, template)
		h, _ := tpm.WrapHandle(hierarchy)
		verifyCreationData(t, tpm, creationData, template, outsideInfo, creationPCR, h)
		verifyCreationHash(t, creationHash, template)
		verifyCreationTicket(t, creationTicket, hierarchy)

		nameAlgSize, _ := cryptGetDigestSize(template.NameAlg)
		if len(name) != int(nameAlgSize)+2 {
			t.Errorf("CreatePrimary returned a name of the wrong length %d", len(name))
		}

		return objectHandle, outPublic
	}

	setHierarchyAuth := func(t *testing.T, handle Handle, auth []byte) {
		if err := tpm.HierarchyChangeAuth(handle, Auth(auth), nil); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}
	}

	clearHierarchyAuth := func(t *testing.T, handle Handle, auth []byte) {
		if err := tpm.HierarchyChangeAuth(handle, nil, auth); err != nil {
			t.Errorf("Failed to reset hierarchy auth: %v", err)
		}
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

		objectHandle, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectHandle)
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

		objectHandle, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectHandle)
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

		objectHandle, pub := run(t, HandleEndorsement, nil, &template, Data{}, PCRSelectionList{}, nil)
		defer flushContext(t, tpm, objectHandle)
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

		objectHandle, pub := run(t, HandleOwner, &sensitive, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectHandle)
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

		_, _, _, _, _, err := tpm.Create(objectHandle, nil, &childTemplate, nil, nil, testAuth)
		if err != nil {
			t.Errorf("Use of authorization on primary key failed: %v", err)
		}
	})

	t.Run("RequireAuthPW", func(t *testing.T) {
		setHierarchyAuth(t, HandleOwner, testAuth)
		defer clearHierarchyAuth(t, HandleOwner, testAuth)

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

		objectHandle, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, testAuth)
		defer flushContext(t, tpm, objectHandle)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("RequireAuthSession", func(t *testing.T) {
		setHierarchyAuth(t, HandleOwner, testAuth)
		defer clearHierarchyAuth(t, HandleOwner, testAuth)

		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionHandle, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil,
			AlgorithmSHA256, testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionHandle)

		session := Session{Handle: sessionHandle, AuthValue: dummyAuth}

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

		objectHandle, pub := run(t, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, &session)
		defer flushContext(t, tpm, objectHandle)
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

		objectHandle, pub := run(t, HandleOwner, nil, &template, data, creationPCR, nil)
		defer flushContext(t, tpm, objectHandle)
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
			"marshal pointer type *tpm2.Public: cannot marshal struct type tpm2.Public: cannot "+
			"marshal field Params: cannot marshal struct type tpm2.PublicParamsU: error "+
			"marshalling union struct: cannot marshal pointer type *tpm2.ECCParams: nil pointer" {
			t.Errorf("CreatePrimary returned an unexpected error: %v", err)
		}
	})
}

func TestHierarchyChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	run1 := func(t *testing.T, hierarchy Handle, newAuth []byte, session interface{}) {
		if err := tpm.HierarchyChangeAuth(hierarchy, Auth(newAuth), session); err != nil {
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

	resetHierarchyAuth := func(t *testing.T, hierarchy Handle, auth []byte) {
		tpm.HierarchyChangeAuth(hierarchy, nil, auth)
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
		objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil,
			session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectHandle
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
		objectHandle, _, _, _, _, _, err := tpm.CreatePrimary(HandleEndorsement, nil, &template, nil, nil,
			session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		return objectHandle
	}

	t.Run("OwnerWithPW", func(t *testing.T) {
		run1(t, HandleOwner, testAuth, nil)
		defer resetHierarchyAuth(t, HandleOwner, testAuth)

		run2(t, HandleOwner, testAuth, createSrk)
	})

	t.Run("EndorsementWithPW", func(t *testing.T) {
		run1(t, HandleEndorsement, testAuth, nil)
		defer resetHierarchyAuth(t, HandleEndorsement, testAuth)

		run2(t, HandleEndorsement, testAuth, createEk)
	})

	t.Run("OwnerWithBoundHMACSession", func(t *testing.T) {
		owner, _ := tpm.WrapHandle(HandleOwner)
		sessionHandle, err := tpm.StartAuthSession(nil, owner, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)

		session := Session{Handle: sessionHandle, Attrs: AttrContinueSession, AuthValue: dummyAuth}

		run1(t, HandleOwner, testAuth, &session)
		defer resetHierarchyAuth(t, HandleOwner, testAuth)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession", func(t *testing.T) {
		sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)

		session := Session{Handle: sessionHandle, Attrs: AttrContinueSession}

		run1(t, HandleOwner, testAuth, &session)
		defer resetHierarchyAuth(t, HandleOwner, testAuth)

		session.AuthValue = testAuth
		run2(t, HandleOwner, &session, createSrk)
	})
}
