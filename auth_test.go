// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestHMACSessions(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	owner, _ := tpm.WrapHandle(HandleOwner)

	primary := createRSASrkForTesting(t, tpm, Auth(testAuth))
	defer flushContext(t, tpm, primary)

	primaryECC, _ := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		bindAuth     []byte
		sessionAuth  []byte
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted1",
			bind:         primary,
			bindAuth:     testAuth,
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted2",
			bind:         primary,
			bindAuth:     testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         owner,
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:        "UnboundUnsaltedUncontinued",
			sessionAuth: testAuth,
		},
		{
			desc:         "UnboundSaltedRSA",
			tpmKey:       primary,
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSaltedECC",
			tpmKey:       primaryECC,
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSaltedRSA",
			tpmKey:       primary,
			bind:         primary,
			bindAuth:     testAuth,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypeHMAC, nil, AlgorithmSHA256, data.bindAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sessionContext)
				} else {
					verifyContextFlushed(t, tpm, sessionContext)
				}
			}()

			template := Public{
				Type:    AlgorithmRSA,
				NameAlg: AlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
				Params: PublicParamsU{
					&RSAParams{
						Symmetric: SymDefObject{Algorithm: AlgorithmNull},
						Scheme:    RSAScheme{Scheme: AlgorithmNull},
						KeyBits:   2048,
						Exponent:  0}}}

			session := &Session{Context: sessionContext, AuthValue: data.sessionAuth, Attrs: data.sessionAttrs}
			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, session)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, session)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent session usage failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Subsequent use of the session should fail")
				}
				if err.Error() != "cannot process ResourceWithAuth for command TPM_CC_Create at index 1: invalid resource context for session: "+
					"resource has been closed" {
					t.Errorf("Subsequent use of the session failed with an unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicySessions(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	secret := []byte("super secret data")

	template := Public{
		Type:       AlgorithmKeyedHash,
		NameAlg:    AlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent,
		AuthPolicy: make([]byte, 32),
		Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
	sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, testAuth)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		bindAuth     []byte
		sessionAuth  []byte
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSalted",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "BoundUnsalted1",
			bind:         objectContext,
			bindAuth:     testAuth,
			sessionAuth:  testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted2",
			bind:         objectContext,
			bindAuth:     testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted3",
			bind:         objectContext,
			bindAuth:     testAuth,
			sessionAuth:  dummyAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource1",
			bind:         primary,
			bindAuth:     testAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource2",
			bind:         primary,
			bindAuth:     testAuth,
			sessionAuth:  dummyAuth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSalted",
			tpmKey:       primary,
			bind:         objectContext,
			bindAuth:     testAuth,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypePolicy, nil, AlgorithmSHA256, data.bindAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sessionContext)
				} else {
					verifyContextFlushed(t, tpm, sessionContext)
				}
			}()

			session := Session{Context: sessionContext, Attrs: data.sessionAttrs, AuthValue: data.sessionAuth}
			_, err = tpm.Unseal(objectContext, &session)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, err = tpm.Unseal(objectContext, &session)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent usage of the session failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Subsequent usage of the session should fail")
				}
				if err.Error() != "cannot process ResourceWithAuth for command TPM_CC_Unseal at index 1: invalid resource context for session: "+
					"resource has been closed" {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
