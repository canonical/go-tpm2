package tpm2

import (
	"testing"
)

func TestHMACSessions(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	auth := []byte("1234")

	owner, _ := tpm.WrapHandle(HandleOwner)

	primary := createRSASrkForTesting(t, tpm, Auth(auth))
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
			sessionAuth:  auth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsalted",
			bind:         primary,
			bindAuth:     auth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundUnsaltedUsedOnNonBoundResource)",
			bind:         owner,
			sessionAuth:  auth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:        "UnboundUnsaltedUncontinued",
			sessionAuth: auth,
		},
		{
			desc:         "UnboundSaltedRSA",
			tpmKey:       primary,
			sessionAuth:  auth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "UnboundSaltedECC",
			tpmKey:       primaryECC,
			sessionAuth:  auth,
			sessionAttrs: AttrContinueSession,
		},
		{
			desc:         "BoundSaltedRSA",
			tpmKey:       primary,
			bind:         primary,
			bindAuth:     auth,
			sessionAttrs: AttrContinueSession,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionHandle, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypeHMAC,
				nil, AlgorithmSHA256, data.bindAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			sessionLoaded := true
			defer func() {
				if !sessionLoaded {
					return
				}
				flushContext(t, tpm, sessionHandle)
			}()

			template := Public{
				Type:    AlgorithmRSA,
				NameAlg: AlgorithmSHA256,
				Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin |
					AttrUserWithAuth | AttrDecrypt | AttrSign,
				Params: PublicParamsU{
					RSADetail: &RSAParams{
						Symmetric: SymDefObject{Algorithm: AlgorithmNull},
						Scheme:    RSAScheme{Scheme: AlgorithmNull},
						KeyBits:   2048,
						Exponent:  0}}}

			session := &Session{Handle: sessionHandle, AuthValue: data.sessionAuth,
				Attributes: data.sessionAttrs}
			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, session)
			if err != nil {
				t.Errorf("Create failed: %v", err)
			}

			_, _, _, _, _, err = tpm.Create(primary, nil, &template, nil, nil, session)
			if data.sessionAttrs&AttrContinueSession > 0 {
				if err != nil {
					t.Errorf("Create failed: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("Subsequent use of the session should fail")
				}
				sessionLoaded = false
				if err.Error() != "cannot build auth area for command TPM_CC_Create: invalid "+
					"resource context for session: resource has been closed" {
					t.Errorf("Subsequent use of the session failed with an unexpected "+
						"error: %v", err)
				}
			}
		})
	}
}
