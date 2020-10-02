// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/canonical/go-tpm2"
)

func TestHMACSessions(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	owner := tpm.OwnerHandleContext()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	primaryECC := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
		sessionAttrs SessionAttributes
	}{
		{
			desc:         "UnboundUnsalted",
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         owner,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc: "UnboundUnsaltedUncontinued",
		},
		{
			desc:         "UnboundSaltedRSA",
			tpmKey:       primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSaltedECC",
			tpmKey:       primaryECC,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSaltedRSA",
			tpmKey:       primary,
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypeHMAC, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			template := Public{
				Type:    ObjectTypeRSA,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
				Params: PublicParamsU{
					Data: &RSAParams{
						Symmetric: SymDefObject{Algorithm: SymObjectAlgorithmNull},
						Scheme:    RSAScheme{Scheme: RSASchemeNull},
						KeyBits:   2048,
						Exponent:  0}}}

			sc.SetAttrs(data.sessionAttrs)
			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent session usage failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandCreate, 1) {
					t.Errorf("Subsequent use of the session failed with an unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicySessions(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityOwnerHierarchy)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	secret := []byte("super secret data")

	template := Public{
		Type:       ObjectTypeKeyedHash,
		NameAlg:    HashAlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent,
		AuthPolicy: make([]byte, 32),
		Params:     PublicParamsU{Data: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
	sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}
	objectContext, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	objectContext.SetAuthValue(testAuth)

	for _, data := range []struct {
		desc         string
		tpmKey       ResourceContext
		bind         ResourceContext
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
			desc:         "BoundUnsalted",
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource",
			bind:         primary,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSalted",
			tpmKey:       primary,
			bind:         objectContext,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypePolicy, nil, HashAlgorithmSHA256)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer func() {
				if data.sessionAttrs&AttrContinueSession > 0 {
					flushContext(t, tpm, sc)
				} else {
					verifyContextFlushed(t, tpm, sc)
				}
			}()

			sc.SetAttrs(data.sessionAttrs)
			_, err = tpm.Unseal(objectContext, sc)
			if err != nil {
				t.Errorf("Session usage failed: %v", err)
			}

			_, err = tpm.Unseal(objectContext, sc)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Subsequent usage of the session failed: %v", err)
				}
			} else {
				if !IsTPMSessionError(err, ErrorValue, CommandUnseal, 1) {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}
