// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func getDictionaryAttackParams(t *testing.T, tpm *TPMContext) (uint32, uint32, uint32) {
	props, err := tpm.GetCapabilityTPMProperties(PropertyMaxAuthFail, 3)
	if err != nil {
		t.Fatalf("GetCapability failed: %v", err)
	}

	params := make(map[Property]uint32)

	for _, prop := range []Property{PropertyMaxAuthFail, PropertyLockoutInterval, PropertyLockoutRecovery} {
		found := false
		for _, data := range props {
			if data.Property == prop {
				params[prop] = data.Value
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("Missing property %v", prop)
		}
	}

	return params[PropertyMaxAuthFail], params[PropertyLockoutInterval], params[PropertyLockoutRecovery]
}

func TestDictionaryAttackParameters(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureDAParameters|testutil.TPMFeatureChangeLockoutAuth)
	defer closeTPM(t, tpm)

	origMaxTries, origRecoveryTime, origLockoutRecovery := getDictionaryAttackParams(t, tpm)

	run := func(t *testing.T, authSession SessionContext) {
		params := map[Property]uint32{
			PropertyMaxAuthFail:     32,
			PropertyLockoutInterval: 7200,
			PropertyLockoutRecovery: 86400}

		if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), params[PropertyMaxAuthFail], params[PropertyLockoutInterval], params[PropertyLockoutRecovery], authSession); err != nil {
			t.Fatalf("DictionaryAttackParameters failed: %v", err)
		}
		defer func() {
			if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), origMaxTries, origRecoveryTime, origLockoutRecovery, authSession); err != nil {
				t.Errorf("Failed to reset dictionary attack parameters: %v", err)
			}
		}()

		props, err := tpm.GetCapabilityTPMProperties(PropertyMaxAuthFail, 3)
		if err != nil {
			t.Fatalf("GetCapability failed: %v", err)
		}

		for k, v := range params {
			found := false
			var value uint32
			for _, data := range props {
				if data.Property == k {
					found = true
					value = data.Value
					break
				}
			}
			if !found {
				t.Errorf("Missing property: %v", k)
			}
			if value != v {
				t.Errorf("Unexpected value for property %v (got %d, expected %d)", k, value, v)
			}
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
		defer flushContext(t, tpm, sessionContext)
		run(t, sessionContext.WithAttrs(AttrContinueSession))
	})
}

func TestDictionaryAttackLockReset(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy|testutil.TPMFeatureDAParameters|testutil.TPMFeatureChangeLockoutAuth)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    ObjectTypeRSA,
		NameAlg: HashAlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
		Params: &PublicParamsU{
			RSADetail: &RSAParams{
				Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
				Scheme:    RSAScheme{Scheme: RSASchemeNull},
				KeyBits:   2048,
				Exponent:  0}}}
	sensitive := SensitiveCreate{UserAuth: testAuth}
	priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	context, err := tpm.Load(primary, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, context)

	origMaxTries, origRecoveryTime, origLockoutRecovery := getDictionaryAttackParams(t, tpm)
	if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), 2, origRecoveryTime, origLockoutRecovery, nil); err != nil {
		t.Fatalf("DictionaryAttackParameters failed: %v", err)
	}
	defer func() {
		if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), origMaxTries, origRecoveryTime, origLockoutRecovery, nil); err != nil {
			t.Errorf("Failed to reset dictionary attack parameters: %v", err)
		}
	}()

	run := func(t *testing.T, authSession SessionContext) {
		context.SetAuthValue(nil)
	Loop:
		for i := 0; i < 3; i++ {
			_, err := tpm.ObjectChangeAuth(context, primary, nil, nil)
			if err == nil {
				t.Fatalf("Expected ObjectChangeAuth to fail")
			}
			switch {
			case IsTPMWarning(err, WarningLockout, CommandObjectChangeAuth):
				break Loop
			case IsTPMSessionError(err, ErrorAuthFail, CommandObjectChangeAuth, 1):
				continue
			}
			t.Fatalf("Unexpected error: %v", err)
		}

		context.SetAuthValue(testAuth)
		_, err := tpm.ObjectChangeAuth(context, primary, nil, nil)
		if err == nil {
			t.Fatalf("ObjectChangeAuth should have failed")
		}
		if !IsTPMWarning(err, WarningLockout, CommandObjectChangeAuth) {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), authSession); err != nil {
			t.Errorf("DictionaryAttackLockReset failed: %v", err)
		}

		props, err := tpm.GetCapabilityTPMProperties(PropertyLockoutCounter, 1)
		if err != nil {
			t.Fatalf("GetCapability failed: %v", err)
		}
		if len(props) < 1 {
			t.Fatalf("GetCapability returned the wrong number of properties (%d)", len(props))
		}

		if props[0].Value != 0 {
			t.Errorf("DictionaryAttackLockReset should have reset TPM_PT_LOCKOUT_COUNTER")
		}

		_, err = tpm.ObjectChangeAuth(context, primary, nil, nil)
		if err != nil {
			t.Errorf("ObjectChangeAuth failed: %v", err)
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
		defer flushContext(t, tpm, sessionContext)
		run(t, sessionContext.WithAttrs(AttrContinueSession))
	})
}
