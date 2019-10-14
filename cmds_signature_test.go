// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"crypto/rand"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		keyScheme RSAScheme
		inScheme  *SigScheme
	}{
		{
			desc: "KeyScheme1",
			keyScheme: RSAScheme{
				Scheme: AlgorithmRSASSA,
				Details: AsymSchemeU{
					Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}},
		},
		{
			desc: "KeyScheme2",
			keyScheme: RSAScheme{
				Scheme: AlgorithmRSASSA,
				Details: AsymSchemeU{
					Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}},
			inScheme: &SigScheme{
				Scheme: AlgorithmRSASSA,
				Details: SigSchemeU{
					Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}},
		},
		{
			desc:      "InScheme",
			keyScheme: RSAScheme{Scheme: AlgorithmNull},
			inScheme: &SigScheme{
				Scheme: AlgorithmRSAPSS,
				Details: SigSchemeU{
					Data: &SigSchemeRSAPSS{HashAlg: AlgorithmSHA256}}},
		},
	} {
		create := func(t *testing.T, authValue []byte) ResourceContext {
			template := Public{
				Type:    AlgorithmRSA,
				NameAlg: AlgorithmSHA256,
				Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin |
					AttrUserWithAuth | AttrSign,
				Params: PublicParamsU{
					Data: &RSAParams{
						Symmetric: SymDefObject{Algorithm: AlgorithmNull},
						Scheme:    data.keyScheme,
						KeyBits:   2048,
						Exponent:  0}}}
			sensitive := SensitiveCreate{UserAuth: authValue}
			priv, pub, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			context, _, err := tpm.Load(primary, priv, pub, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			return context
		}

		run := func(t *testing.T, key ResourceContext, auth interface{}) {
			digest := make([]byte, 32)
			rand.Read(digest)

			signature, err := tpm.Sign(key, digest, data.inScheme, nil, auth)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			verified, err := tpm.VerifySignature(key, digest, signature)
			if err != nil {
				t.Fatalf("VerifySignature failed: %v", err)
			}

			if verified.Tag != TagVerified {
				t.Errorf("Invalid tag %v", verified.Tag)
			}
			if verified.Hierarchy != HandleOwner {
				t.Errorf("Invalid hierarchy 0x%08x", verified.Hierarchy)
			}

		}

		t.Run(data.desc+"/NoAuth", func(t *testing.T) {
			key := create(t, nil)
			defer flushContext(t, tpm, key)
			run(t, key, nil)
		})

		t.Run(data.desc+"/UsePasswordAuth", func(t *testing.T) {
			key := create(t, testAuth)
			defer flushContext(t, tpm, key)
			run(t, key, testAuth)
		})

		t.Run(data.desc+"/UseSessionAuth", func(t *testing.T) {
			key := create(t, testAuth)
			defer flushContext(t, tpm, key)

			sessionContext, err := tpm.StartAuthSession(nil, key, SessionTypeHMAC, nil,
				AlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer verifyContextFlushed(t, tpm, sessionContext)

			run(t, key, &Session{Context: sessionContext})
		})
	}
}
