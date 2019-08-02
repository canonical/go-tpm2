// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func getDictionaryAttackParams(t *testing.T, tpm TPMContext) (uint32, uint32, uint32) {
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
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	origMaxTries, origRecoveryTime, origLockoutRecovery := getDictionaryAttackParams(t, tpm)

	run := func(t *testing.T, auth interface{}) {
		params := map[Property]uint32{
			PropertyMaxAuthFail:     32,
			PropertyLockoutInterval: 7200,
			PropertyLockoutRecovery: 86400}

		if err := tpm.DictionaryAttackParameters(HandleLockout, params[PropertyMaxAuthFail],
			params[PropertyLockoutInterval], params[PropertyLockoutRecovery], auth); err != nil {
			t.Fatalf("DictionaryAttackParameters failed: %v", err)
		}
		defer func() {
			if err := tpm.DictionaryAttackParameters(HandleLockout, origMaxTries, origRecoveryTime,
				origLockoutRecovery, auth); err != nil {
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
	t.Run("RequirePW", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		run(t, testAuth)
	})
	t.Run("RequireSession", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		lockout, _ := tpm.WrapHandle(HandleLockout)
		sessionContext, err := tpm.StartAuthSession(nil, lockout, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth})
	})
}

func TestDictionaryAttackLockReset(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, Auth(testAuth))
	defer flushContext(t, tpm, primary)

	origMaxTries, origRecoveryTime, origLockoutRecovery := getDictionaryAttackParams(t, tpm)
	if err := tpm.DictionaryAttackParameters(HandleLockout, 2, origRecoveryTime, origLockoutRecovery,
		nil); err != nil {
		t.Fatalf("DictionaryAttackParameters failed: %v", err)
	}
	defer func() {
		if err := tpm.DictionaryAttackParameters(HandleLockout, origMaxTries, origRecoveryTime,
			origLockoutRecovery, nil); err != nil {
			t.Errorf("Failed to reset dictionary attack parameters: %v", err)
		}
	}()

	run := func(t *testing.T, auth interface{}) {
		template := Public{
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
	Loop:
		for i := 0; i < 3; i++ {
			_, _, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
			if err == nil {
				t.Fatalf("Expected Create to fail")
			}
			switch e := err.(type) {
			case TPMWarning:
				if e.Code == WarningLockout {
					break Loop
				}
			case TPMSessionError:
				if e.Code == ErrorAuthFail {
					continue
				}
			}
			t.Fatalf("Unexpected error: %v", err)
		}

		_, _, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, testAuth)
		if err == nil {
			t.Fatalf("Create should have failed")
		}
		warning, isWarning := err.(TPMWarning)
		if !isWarning || warning.Code != WarningLockout {
			t.Errorf("Unexpected error: %v", err)
		}

		if err := tpm.DictionaryAttackLockReset(HandleLockout, auth); err != nil {
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

		_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, testAuth)
		if err != nil {
			t.Errorf("Create failed: %v", err)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		run(t, nil)
	})
	t.Run("RequirePW", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		run(t, testAuth)
	})
	t.Run("RequireSession", func(t *testing.T) {
		setHierarchyAuthForTest(t, tpm, HandleLockout)
		defer resetHierarchyAuth(t, tpm, HandleLockout)
		lockout, _ := tpm.WrapHandle(HandleLockout)
		sessionContext, err := tpm.StartAuthSession(nil, lockout, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)
		run(t, &Session{Context: sessionContext, Attrs: AttrContinueSession, AuthValue: testAuth})
	})
}
