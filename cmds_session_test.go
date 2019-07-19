package tpm2

import (
	"testing"
)

func TestStartAuthSession(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	auth := []byte("foo")
	primary := createRSASrkForTesting(t, tpm, Auth(auth))
	defer flushContext(t, tpm, primary)
	primaryECC := createECCSrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primaryECC)

	owner, _ := tpm.WrapHandle(HandleOwner)

	for _, data := range []struct{
		desc string
		tpmKey ResourceContext
		bind ResourceContext
		sessionType SessionType
		alg AlgorithmId
		bindAuth []byte
		handleType Handle
		errMsg string
	}{
		{
			desc: "HMACUnboundUnsaltedSHA256",
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA256,
			handleType: HandleTypeHMACSession,
		},
		{
			desc: "HMACBoundUnsaltedSHA256",
			bind: primary,
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA256,
			bindAuth: auth,
			handleType: HandleTypeHMACSession,
		},
		{
			desc: "HMACUnboundSaltedRSASHA256",
			tpmKey: primary,
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA256,
			handleType: HandleTypeHMACSession,
		},
		{
			desc: "HMACUnboundSaltedECCSHA256",
			tpmKey: primaryECC,
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA256,
			handleType: HandleTypeHMACSession,
		},
		{
			desc: "HMACBoundSaltedRSASHA1",
			tpmKey: primary,
			bind: primary,
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA1,
			bindAuth: auth,
			handleType: HandleTypeHMACSession,
		},
		{
			desc: "TrialSessionSHA256",
			sessionType: SessionTypeTrial,
			alg: AlgorithmSHA256,
			handleType: HandleTypePolicySession,
		},
		{
			desc: "PolicySessionSHA256",
			sessionType: SessionTypePolicy,
			alg: AlgorithmSHA256,
			handleType: HandleTypePolicySession,
		},
		{
			desc: "HMACUnboundUnsaltedInvalidAlg",
			sessionType: SessionTypeHMAC,
			alg: AlgorithmNull,
			errMsg: "invalid authHash parameter: unsupported digest algorithm TPM_ALG_NULL",
		},
		{
			desc: "HMACUnboundSaltedInvalidKey",
			tpmKey: owner,
			sessionType: SessionTypeHMAC,
			alg: AlgorithmSHA256,
			errMsg: "invalid tpmKey parameter: not an object",
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionHandle, err := tpm.StartAuthSession(data.tpmKey, data.bind, data.sessionType, nil,
				data.alg, data.bindAuth)
			if data.errMsg == "" {
				if err != nil {
					t.Fatalf("StartAuthSession returned an error: %v", err)
				}
				defer flushContext(t, tpm, sessionHandle)

				if sessionHandle.Handle()&data.handleType != data.handleType {
					t.Errorf("StartAuthSession returned a handle of the wrong type")
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
