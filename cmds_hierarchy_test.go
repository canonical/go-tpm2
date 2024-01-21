// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestCreatePrimary(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	run := func(t *testing.T, hierarchy ResourceContext, sensitive *SensitiveCreate, template *Public, outsideInfo Data, creationPCR PCRSelectionList, session SessionContext) (ResourceContext, *Public) {
		objectContext, outPublic, creationData, creationHash, creationTicket, err := tpm.CreatePrimary(hierarchy, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("CreatePrimary failed: %v", err)
		}
		if _, ok := objectContext.(ObjectContext); !ok {
			t.Errorf("CreatePrimary return an invalid resource type")
		}

		if objectContext.Handle().Type() != HandleTypeTransient {
			t.Errorf("CreatePrimary returned an invalid handle 0x%08x", objectContext.Handle())
		}
		verifyPublicAgainstTemplate(t, outPublic, template)
		verifyCreationData(t, tpm, creationData, creationHash, template, outsideInfo, creationPCR, hierarchy)
		verifyCreationTicket(t, creationTicket, hierarchy)

		nameAlgSize := template.NameAlg.Size()
		if len(objectContext.Name()) != nameAlgSize+2 {
			t.Errorf("CreatePrimary returned a name of the wrong length %d", len(objectContext.Name()))
		}

		return objectContext, outPublic
	}

	t.Run("RSASrk", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}
		creationPCR := PCRSelectionList{
			{Hash: HashAlgorithmSHA1, Select: []int{0, 1}},
			{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}}

		objectContext, pub := run(t, tpm.OwnerHandleContext(), nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("ECCSrk", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeECC,
			NameAlg: HashAlgorithmSHA1,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				ECCParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:  ECCScheme{Scheme: ECCSchemeNull},
					CurveID: ECCCurveNIST_P256,
					KDF:     KDFScheme{Scheme: KDFAlgorithmNull},
				},
			),
		}
		creationPCR := PCRSelectionList{
			{Hash: HashAlgorithmSHA1, Select: []int{0, 1}},
			{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}}

		objectContext, pub := run(t, tpm.OwnerHandleContext(), nil, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		if len(pub.Unique.ECC().X) != 32 || len(pub.Unique.ECC().Y) != 32 {
			t.Errorf("CreatePrimary returned object with invalid ECC coords")
		}
	})

	t.Run("Ek", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
				0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}

		objectContext, pub := run(t, tpm.EndorsementHandleContext(), nil, &template, Data{}, PCRSelectionList{}, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("CreateWithAuthValue", func(t *testing.T) {
		sensitive := SensitiveCreate{UserAuth: testAuth}
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt | AttrNoDA,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}
		creationPCR := PCRSelectionList{
			{Hash: HashAlgorithmSHA1, Select: []int{0, 1}},
			{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}}

		objectContext, pub := run(t, tpm.OwnerHandleContext(), &sensitive, &template, Data{}, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)

		childTemplate := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
					Scheme:    RSAScheme{Scheme: RSASchemeNull},
					KeyBits:   2048,
					Exponent:  0,
				},
			),
		}

		// We shouldn't need to call ResourceContext.SetAuthValue to use the primary object.
		_, _, _, _, _, err := tpm.Create(objectContext, nil, &childTemplate, nil, nil, nil)
		if err != nil {
			t.Errorf("Use of authorization on primary key failed: %v", err)
		}

		// Verify that the primary object was created with the right auth value
		objectContext.SetAuthValue(testAuth)
		_, _, _, _, _, err = tpm.Create(objectContext, nil, &childTemplate, nil, nil, nil)
		if err != nil {
			t.Errorf("Use of authorization on primary key failed: %v", err)
		}
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}

		objectContext, pub := run(t, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}

		objectContext, pub := run(t, tpm.OwnerHandleContext(), nil, &template, Data{}, PCRSelectionList{}, sessionContext)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("WithOutsideInfo", func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}
		creationPCR := PCRSelectionList{
			{Hash: HashAlgorithmSHA1, Select: []int{0, 1}},
			{Hash: HashAlgorithmSHA256, Select: []int{7, 8}}}
		data := Data("foo")

		objectContext, pub := run(t, tpm.OwnerHandleContext(), nil, &template, data, creationPCR, nil)
		defer flushContext(t, tpm, objectContext)
		verifyRSAAgainstTemplate(t, pub, &template)
	})
}

func TestHierarchyControl(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeaturePlatformHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	run := func(t *testing.T, authContext ResourceContext, enable Handle, state bool, session SessionContext) {
		if err := tpm.HierarchyControl(authContext, enable, state, session); err != nil {
			t.Errorf("HierarchyControl failed: %v", err)
		}

		props, err := tpm.GetCapabilityTPMProperties(PropertyStartupClear, 1)
		if err != nil || len(props) == 0 {
			t.Fatalf("GetCapability failed: %v", err)
		}
		var mask StartupClearAttributes
		switch enable {
		case HandleOwner:
			mask = AttrShEnable
		case HandleEndorsement:
			mask = AttrEhEnable
		}

		var expected StartupClearAttributes
		if state {
			expected = mask
		}

		if StartupClearAttributes(props[0].Value)&mask != expected {
			t.Errorf("Unexpected value")
		}
	}

	t.Run("Owner", func(t *testing.T) {
		run(t, tpm.OwnerHandleContext(), HandleOwner, false, nil)
		run(t, tpm.PlatformHandleContext(), HandleOwner, true, nil)
	})

	t.Run("Endorsement", func(t *testing.T) {
		run(t, tpm.EndorsementHandleContext(), HandleEndorsement, false, nil)
		run(t, tpm.PlatformHandleContext(), HandleEndorsement, true, nil)
	})

	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		run(t, tpm.OwnerHandleContext(), HandleOwner, false, nil)
		run(t, tpm.PlatformHandleContext(), HandleOwner, true, nil)
	})

	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.OwnerHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.OwnerHandleContext())

		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)

		run(t, tpm.OwnerHandleContext(), HandleOwner, false, sessionContext)
		run(t, tpm.PlatformHandleContext(), HandleOwner, true, nil)
	})
}

func TestClear(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeatureLockoutHierarchy|testutil.TPMFeaturePlatformHierarchy|testutil.TPMFeatureClear|testutil.TPMFeatureNV)
	defer closeTPM()

	run := func(t *testing.T, authSession SessionContext) {
		cleared := false

		owner := tpm.OwnerHandleContext()

		// Create storage primary key to test it gets evicted
		primary := createRSASrkForTesting(t, tpm, nil)
		// Persist storage primary key to test it gets evicted
		primaryPersistHandle := Handle(0x8100ffff)
		primaryPersist := persistObjectForTesting(t, tpm, owner, primary, primaryPersistHandle)
		defer func() {
			if cleared {
				return
			}
			flushContext(t, tpm, primary)
			evictPersistentObject(t, tpm, owner, primaryPersist)
		}()

		// Set endorsement hierarchy auth value (should be reset by Clear)
		setHierarchyAuthForTest(t, tpm, tpm.EndorsementHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.EndorsementHandleContext())

		// Set platform hierarchy auth value (shouldn't be reset by Clear)
		setHierarchyAuthForTest(t, tpm, tpm.PlatformHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.PlatformHandleContext())

		primaryHandle := primary.Handle()

		// Perform the clear
		if err := tpm.Clear(tpm.LockoutHandleContext(), authSession); err != nil {
			t.Fatalf("Clear failed: %v", err)
		}

		cleared = true

		// Verify that the objects we created have gone so we know that the command executed
		if _, err := tpm.NewResourceContext(primaryHandle); err == nil {
			t.Errorf("Clear didn't evict owner object")
		}
		if _, err := tpm.NewResourceContext(primaryPersistHandle); err == nil {
			t.Errorf("Clear didn't evict owner object")
		}

		if tpm.EndorsementHandleContext().AuthValue() != nil {
			t.Errorf("Clear didn't reset the authorization value for the EH ResourceContext")
		}
		if !bytes.Equal(tpm.PlatformHandleContext().AuthValue(), testAuth) {
			t.Errorf("Clear reset the authorization value for the PH ResourceContext")
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("UsePasswordAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.LockoutHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.LockoutHandleContext())
		run(t, nil)
	})
	t.Run("UseSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.LockoutHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.LockoutHandleContext())
		sessionContext, err := tpm.StartAuthSession(nil, tpm.LockoutHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, sessionContext)
	})
	t.Run("UseUnboundSessionAuth", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, tpm.LockoutHandleContext())
		defer resetHierarchyAuth(t, tpm, tpm.LockoutHandleContext())
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, sessionContext)
	})
}

func TestHierarchyChangeAuth(t *testing.T) {
	tpm, _, closeTPM := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureEndorsementHierarchy|testutil.TPMFeatureNV)
	defer closeTPM()

	setAuth := func(t *testing.T, hierarchy ResourceContext, session SessionContext, testHierarchy func(t *testing.T)) {
		if err := tpm.HierarchyChangeAuth(hierarchy, testAuth, session); err != nil {
			t.Fatalf("HierarchyChangeAuth failed: %v", err)
		}

		testHierarchy(t)
		hierarchy.SetAuthValue(testAuth)
		testHierarchy(t)
	}

	resetAuth := func(t *testing.T, hierarchy ResourceContext, session SessionContext, testHierarchy func(*testing.T)) {
		if err := tpm.HierarchyChangeAuth(hierarchy, nil, session); err != nil {
			t.Errorf("HierarchyChangeAuth failed: %v", err)
		}

		testHierarchy(t)
		hierarchy.SetAuthValue(nil)
		testHierarchy(t)
	}

	createSrk := func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrRestricted | AttrDecrypt,
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}
		objectContext, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
		if err != nil {
			t.Errorf("CreatePrimary failed: %v", err)
		}
		flushContext(t, tpm, objectContext)
	}
	createEk := func(t *testing.T) {
		template := Public{
			Type:    ObjectTypeRSA,
			NameAlg: HashAlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrAdminWithPolicy | AttrRestricted | AttrDecrypt,
			AuthPolicy: []byte{0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24, 0xfd, 0x52,
				0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa},
			Params: MakePublicParamsUnion(
				RSAParams{
					Symmetric: SymDefObject{
						Algorithm: SymObjectAlgorithmAES,
						KeyBits:   MakeSymKeyBitsUnion[uint16](128),
						Mode:      MakeSymModeUnion(SymModeCFB),
					},
					Scheme:   RSAScheme{Scheme: RSASchemeNull},
					KeyBits:  2048,
					Exponent: 0,
				},
			),
		}
		objectContext, _, _, _, _, err := tpm.CreatePrimary(tpm.EndorsementHandleContext(), nil, &template, nil, nil, nil)
		if err != nil {
			t.Errorf("CreatePrimary failed: %v", err)
		}
		flushContext(t, tpm, objectContext)
	}

	t.Run("OwnerWithPW", func(t *testing.T) {
		setAuth(t, tpm.OwnerHandleContext(), nil, createSrk)
		resetAuth(t, tpm.OwnerHandleContext(), nil, createSrk)
	})

	t.Run("EndorsementWithPW", func(t *testing.T) {
		setAuth(t, tpm.EndorsementHandleContext(), nil, createEk)
		resetAuth(t, tpm.EndorsementHandleContext(), nil, createEk)
	})

	t.Run("OwnerWithBoundHMACSession/1", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		sessionContext.SetAttrs(AttrContinueSession)

		setAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
		resetAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
	})

	t.Run("OwnerWithBoundHMACSession/2", func(t *testing.T) {
		sessionContext1, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext1)

		setAuth(t, tpm.OwnerHandleContext(), sessionContext1, createSrk)

		sessionContext2, err := tpm.StartAuthSession(nil, tpm.OwnerHandleContext(), SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext2)

		resetAuth(t, tpm.OwnerHandleContext(), sessionContext2, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession/1", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		sessionContext.SetAttrs(AttrContinueSession)

		setAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
		resetAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
	})

	t.Run("OwnerWithUnboundHMACSession/2", func(t *testing.T) {
		// This test highlights a bug where we didn't preserve the value of Session.includeAuthValue (which should be true) before computing
		// the response HMAC. It's not caught by OwnerWithUnboundHMACSession because the lack of session key combined with
		// Session.includeAuthValue incorrectly being false was causing processResponseSessionAuth to bail out early
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, nil, HashAlgorithmSHA256)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		sessionContext.SetAttrs(AttrContinueSession)

		setAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
		resetAuth(t, tpm.OwnerHandleContext(), sessionContext, createSrk)
	})
}
