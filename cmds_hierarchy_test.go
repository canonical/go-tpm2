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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&ECCParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
					Scheme:  ECCScheme{Scheme: AlgorithmNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: AlgorithmNull}}},
			Unique: PublicIDU{&ECCPoint{}}}
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		objectContext, pub := run(t, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		if len(pub.Unique.ECC().X) != 32 || len(pub.Unique.ECC().Y) != 32 {
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
					Scheme:   RSAScheme{Scheme: AlgorithmNull},
					KeyBits:  2048,
					Exponent: 0}}}

		_, _, _, _, _, _, err := tpm.CreatePrimary(HandleOwner, nil, &template, nil, nil, nil)
		if err == nil {
			t.Fatalf("CreatePrimary should fail with an invalid template")
		}
		if err.Error() != "cannot marshal command parameters for command TPM_CC_CreatePrimary: cannot "+
			"marshal struct type tpm2.publicSized: cannot marshal field Ptr: cannot marshal pointer "+
			"type *tpm2.Public: cannot marshal struct type tpm2.Public: cannot marshal sized struct: "+
			"cannot marshal struct type tpm2.Public: cannot marshal field Params: cannot marshal "+
			"struct type tpm2.PublicParamsU: error marshalling union struct: data has incorrect "+
			"type *tpm2.RSAParams (expected *tpm2.ECCParams)" {
			t.Errorf("CreatePrimary returned an unexpected error: %v", err)
		}
	})
}

func TestClear(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, auth interface{}) {
		cleared := false

		var persistentObjects []ResourceContext
		var transientObjects []ResourceContext

		// Create platform primary key (should persist across Clear)
		template := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
				AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
					Scheme:   RSAScheme{Scheme: AlgorithmNull},
					KeyBits:  2048,
					Exponent: 0}}}
		platformPrimary, _, _, _, _, _, err := tpm.CreatePrimary(HandlePlatform, nil, &template, nil, nil,
			nil)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		defer flushContext(t, tpm, platformPrimary)
		persistentObjects = append(persistentObjects, platformPrimary)

		// Create storage primary key (should be evicted by Clear)
		ownerPrimary := createRSASrkForTesting(t, tpm, nil)
		defer func() {
			if cleared {
				return
			}
			flushContext(t, tpm, ownerPrimary)
		}()
		transientObjects = append(transientObjects, ownerPrimary)

		// Persist storage primary key (should be evicted by Clear)
		persist := Handle(0x8100ffff)
		if context, err := tpm.WrapHandle(persist); err == nil {
			_, err := tpm.EvictControl(HandleOwner, context, persist, nil)
			if err != nil {
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of "+
					"the test: %v", err)
			}
		}
		ownerPrimaryPersist, err := tpm.EvictControl(HandleOwner, ownerPrimary, persist, nil)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		defer func() {
			if cleared {
				return
			}
			if _, err := tpm.EvictControl(HandleOwner, ownerPrimaryPersist, persist, nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()
		transientObjects = append(transientObjects, ownerPrimaryPersist)

		// Persist platform primary key (should persist across Clear)
		persist2 := Handle(0x8180ffff)
		if context, err := tpm.WrapHandle(persist2); err == nil {
			_, err := tpm.EvictControl(HandlePlatform, context, persist2, nil)
			if err != nil {
				t.Logf("EvictControl failed whilst trying to remove a handle at the start of "+
					"the test: %v", err)
			}
		}
		platformPrimaryPersist, err := tpm.EvictControl(HandlePlatform, platformPrimary, persist2, nil)
		if err != nil {
			t.Fatalf("EvictControl failed: %v", err)
		}
		defer func() {
			if cleared {
				return
			}
			if _, err := tpm.EvictControl(HandlePlatform, platformPrimaryPersist, persist2,
				nil); err != nil {
				t.Errorf("EvictControl failed: %v", err)
			}
		}()
		persistentObjects = append(persistentObjects, platformPrimaryPersist)

		// Set endorsement hierarchy auth value (should be reset by Clear)
		setHierarchyAuthForTest(t, tpm, HandleEndorsement)
		defer func() {
			if cleared {
				return
			}
			resetHierarchyAuth(t, tpm, HandleEndorsement)
		}()

		// Create a context for a permanent resource (should persist across Clear)
		owner, _ := tpm.WrapHandle(HandleOwner)
		persistentObjects = append(persistentObjects, owner)

		// Create a session (should persist across Clear)
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		persistentObjects = append(persistentObjects, sessionContext)

		// Define an NV index in the owner hierarchy (should be undefined by Clear)
		nvPub1 := NVPublic{
			Index:   0x0181ffff,
			NameAlg: AlgorithmSHA256,
			Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
			Size:    8}
		if err := tpm.NVDefineSpace(HandleOwner, nil, &nvPub1, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		nv1, _ := tpm.WrapHandle(nvPub1.Index)
		defer func() {
			if cleared {
				return
			}
			undefineNVSpace(t, tpm, nv1, HandleOwner, nil)
		}()
		transientObjects = append(transientObjects, nv1)

		// Define an NV index in the platform hierarchy (should persist across Clear)
		nvPub2 := NVPublic{
			Index:   0x0141ffff,
			NameAlg: AlgorithmSHA256,
			Attrs: MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead|AttrNVPlatformCreate,
				NVTypeOrdinary),
			Size: 8}
		if err := tpm.NVDefineSpace(HandlePlatform, nil, &nvPub2, nil); err != nil {
			t.Fatalf("NVDefineSpace failed: %v", err)
		}
		nv2, _ := tpm.WrapHandle(nvPub2.Index)
		defer undefineNVSpace(t, tpm, nv2, HandlePlatform, nil)
		persistentObjects = append(persistentObjects, nv2)

		var transientHandles []Handle
		for _, rc := range transientObjects {
			transientHandles = append(transientHandles, rc.Handle())
		}

		// Perform the clear
		if err := tpm.Clear(HandleLockout, auth); err != nil {
			t.Fatalf("Clear failed: %v", err)
		}
		cleared = true

		// Verify that handles that should have been flushed have been
		for _, h := range transientHandles {
			handles, err := tpm.GetCapabilityHandles(h, 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) > 0 && handles[0] == h {
				t.Errorf("Handle 0x%08x should have been flushed", h)
			}
		}

		// Verify that contexts for flushed objects have been invalidated
		for _, rc := range transientObjects {
			if rc.Handle() != HandleNull {
				t.Errorf("Expected handle 0x%08x to be evicted", rc.Handle())
			}
		}

		// Verify that contexts for objects that should have persisted haven't been invalidated,
		// and check that they weren't flushed from the TPM against our expectation
		for _, rc := range persistentObjects {
			if rc.Handle() == HandleNull {
				t.Fatalf("Object was evicted when it shouldn't have been")
			}
			handle := rc.Handle()
			if rc.Handle()&HandleTypePolicySession == HandleTypePolicySession {
				handle = handle&Handle(0xffffff) | HandleTypeLoadedSession
			}
			handles, err := tpm.GetCapabilityHandles(handle, 1)
			if err != nil {
				t.Fatalf("GetCapability failed: %v", err)
			}
			if len(handles) < 1 || handles[0] != rc.Handle() {
				t.Errorf("Handle 0x%08x was flushed unexpectedly", rc.Handle())
			}
		}

		// Check that the endorsement hierarchy auth has been reset
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
				&RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{AESKeyBits(128)},
						Mode:      SymModeU{AlgorithmCFB}},
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
