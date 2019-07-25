// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

func TestStartAuthSession(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	auth := []byte("foo")
	primary := createRSASrkForTesting(t, tpm, Auth(auth))
	defer flushContext(t, tpm, primary)
	primaryECC, _ := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	owner, _ := tpm.WrapHandle(HandleOwner)

	for _, data := range []struct {
		desc        string
		tpmKey      ResourceContext
		bind        ResourceContext
		sessionType SessionType
		alg         AlgorithmId
		bindAuth    []byte
		handleType  Handle
		errMsg      string
	}{
		{
			desc:        "HMACUnboundUnsaltedSHA256",
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA256,
			handleType:  HandleTypeHMACSession,
		},
		{
			desc:        "HMACBoundUnsaltedSHA256",
			bind:        primary,
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA256,
			bindAuth:    auth,
			handleType:  HandleTypeHMACSession,
		},
		{
			desc:        "HMACUnboundSaltedRSASHA256",
			tpmKey:      primary,
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA256,
			handleType:  HandleTypeHMACSession,
		},
		{
			desc:        "HMACUnboundSaltedECCSHA256",
			tpmKey:      primaryECC,
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA256,
			handleType:  HandleTypeHMACSession,
		},
		{
			desc:        "HMACBoundSaltedRSASHA1",
			tpmKey:      primary,
			bind:        primary,
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA1,
			bindAuth:    auth,
			handleType:  HandleTypeHMACSession,
		},
		{
			desc:        "TrialSessionSHA256",
			sessionType: SessionTypeTrial,
			alg:         AlgorithmSHA256,
			handleType:  HandleTypePolicySession,
		},
		{
			desc:        "PolicySessionSHA256",
			sessionType: SessionTypePolicy,
			alg:         AlgorithmSHA256,
			handleType:  HandleTypePolicySession,
		},
		{
			desc:        "HMACUnboundUnsaltedInvalidAlg",
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmNull,
			errMsg:      "invalid authHash parameter: unsupported digest algorithm TPM_ALG_NULL",
		},
		{
			desc:        "HMACUnboundSaltedInvalidKey",
			tpmKey:      owner,
			sessionType: SessionTypeHMAC,
			alg:         AlgorithmSHA256,
			errMsg:      "invalid tpmKey parameter: not an object",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sc, err := tpm.StartAuthSession(data.tpmKey, data.bind, data.sessionType, nil,
				data.alg, data.bindAuth)
			if data.errMsg == "" {
				if err != nil {
					t.Fatalf("StartAuthSession returned an error: %v", err)
				}
				defer flushContext(t, tpm, sc)

				if sc.Handle()&data.handleType != data.handleType {
					t.Errorf("StartAuthSession returned a handle of the wrong type")
				}

				context, isSessionContext := sc.(*sessionContext)
				if !isSessionContext {
					t.Fatalf("StartAuthSession didn't return a session context")
				}
				if context.hashAlg != data.alg {
					t.Errorf("The returned session context has the wrong algorithm (got %v)",
						context.hashAlg)
				}
				if data.bind != nil && !context.isBoundTo(data.bind) {
					t.Errorf("The returned session context has the wrong bound resource")
				}
				digestSize, _ := cryptGetDigestSize(data.alg)
				sessionKeySize := int(digestSize)
				if data.bind == nil && data.tpmKey == nil {
					sessionKeySize = 0
				}
				if len(context.sessionKey) != sessionKeySize {
					t.Errorf("The returned session key has the wrong length (got %d)",
						len(context.sessionKey))
				}
				if len(context.nonceCaller) != int(digestSize) {
					t.Errorf("The returned caller nonce has the wrong length (got %d)",
						len(context.nonceCaller))
				}
				if len(context.nonceTPM) != int(digestSize) {
					t.Errorf("The returned TPM nonce has the wrong length (got %d)",
						len(context.nonceTPM))
				}
			} else {
				if err == nil {
					t.Fatalf("StartAuthSession should have returned an error")
				}
				if err.Error() != data.errMsg {
					t.Errorf("StartAuthSession returned an unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPolicyRestart(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	sc, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}

	if err := tpm.PolicyPCR(sc, nil,
		PCRSelectionList{PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7}}}); err != nil {
		t.Fatalf("PolicyPCR failed: %v", err)
	}

	digest, err := tpm.PolicyGetDigest(sc)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if err := tpm.PolicyRestart(sc); err != nil {
		t.Fatalf("PolicyRestart failed: %v", err)
	}

	restartedDigest, err := tpm.PolicyGetDigest(sc)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if bytes.Equal(digest, make(Digest, sha256.Size)) {
		t.Errorf("Original digest should not be zero")
	}
	if !bytes.Equal(restartedDigest, make(Digest, sha256.Size)) {
		t.Errorf("Digest wasn't reset to zero")
	}
}
