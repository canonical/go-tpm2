// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"testing"
)

func TestCommandParameterEncryptionDedicated(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   SymKeyBitsU{uint16(128)},
				Mode:      SymModeU{SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   SymKeyBitsU{HashAlgorithmSHA256}},
		},
	} {
		run := func(t *testing.T, primaryAuth interface{}) {
			sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			secret := []byte("sensitive data")

			template := Public{
				Type:    ObjectTypeKeyedHash,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
				Params: PublicParamsU{
					&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
			sensitive := SensitiveCreate{Data: secret}
			session := Session{Context: sessionContext, Attrs: AttrContinueSession | AttrCommandEncrypt}

			outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, primaryAuth, &session)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, primaryAuth)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, objectContext)

			data, err := tpm.Unseal(objectContext, nil)
			if err != nil {
				t.Fatalf("Unseal failed: %v", err)
			}

			if !bytes.Equal(data, secret) {
				t.Errorf("Got unexpected data")
			}
		}

		t.Run(data.desc+"/UsePasswordAuth", func(t *testing.T) {
			run(t, testAuth)
		})

		t.Run(data.desc+"/UseSessionAuth", func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)
			run(t, &Session{Context: sessionContext, Attrs: AttrContinueSession})
		})
	}
}

func TestResponseParameterEncryptionDedicated(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   SymKeyBitsU{uint16(128)},
				Mode:      SymModeU{SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   SymKeyBitsU{HashAlgorithmSHA256}},
		},
	} {
		secret := []byte("sensitive data")

		prepare := func(t *testing.T) ResourceContext {
			template := Public{
				Type:    ObjectTypeKeyedHash,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
				Params: PublicParamsU{
					&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
			sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

			outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}

			return objectContext
		}

		run := func(t *testing.T, objectContext ResourceContext, unsealAuth interface{}) {
			sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			session := Session{Context: sessionContext, Attrs: AttrContinueSession | AttrResponseEncrypt}

			data, err := tpm.Unseal(objectContext, unsealAuth, &session)
			if err != nil {
				t.Fatalf("Unseal failed: %v", err)
			}

			if !bytes.Equal(data, secret) {
				t.Errorf("Got unexpected data")
			}
		}

		t.Run(data.desc+"/UsePasswordAuth", func(t *testing.T) {
			object := prepare(t)
			defer flushContext(t, tpm, object)
			run(t, object, testAuth)
		})

		t.Run(data.desc+"/UseSessionAuth", func(t *testing.T) {
			object := prepare(t)
			defer flushContext(t, tpm, object)

			sessionContext, err := tpm.StartAuthSession(nil, object, SessionTypeHMAC, nil, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			run(t, object, &Session{Context: sessionContext, Attrs: AttrContinueSession})
		})
	}
}

func TestCommandParameterEncryptionShared(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, testAuth)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   SymKeyBitsU{uint16(128)},
				Mode:      SymModeU{SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   SymKeyBitsU{HashAlgorithmSHA256}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			secret := []byte("sensitive data")

			template := Public{
				Type:    ObjectTypeKeyedHash,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
				Params: PublicParamsU{
					&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
			sensitive := SensitiveCreate{Data: secret}

			session := Session{
				Context:   sessionContext,
				Attrs:     AttrContinueSession | AttrCommandEncrypt,
				AuthValue: testAuth}

			outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, &session)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, &session)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, objectContext)

			data, err := tpm.Unseal(objectContext, nil)
			if err != nil {
				t.Fatalf("Unseal failed: %v", err)
			}

			if !bytes.Equal(data, secret) {
				t.Errorf("Got unexpected data")
			}
		})
	}
}
func TestResponseParameterEncryptionShared(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	for _, data := range []struct {
		desc      string
		symmetric SymDef
	}{
		{
			desc: "AES",
			symmetric: SymDef{
				Algorithm: SymAlgorithmAES,
				KeyBits:   SymKeyBitsU{uint16(128)},
				Mode:      SymModeU{SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   SymKeyBitsU{HashAlgorithmSHA256}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			secret := []byte("sensitive data")

			template := Public{
				Type:    ObjectTypeKeyedHash,
				NameAlg: HashAlgorithmSHA256,
				Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
				Params: PublicParamsU{
					&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
			sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

			outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
			if err != nil {
				t.Fatalf("Create failed: %v", err)
			}

			objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
			if err != nil {
				t.Fatalf("Load failed: %v", err)
			}
			defer flushContext(t, tpm, objectContext)

			sessionContext, err := tpm.StartAuthSession(primary, objectContext, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			session := Session{
				Context:   sessionContext,
				Attrs:     AttrContinueSession | AttrResponseEncrypt,
				AuthValue: testAuth}

			data, err := tpm.Unseal(objectContext, &session)
			if err != nil {
				t.Fatalf("Unseal failed: %v", err)
			}

			if !bytes.Equal(data, secret) {
				t.Errorf("Got unexpected data")
			}
		})
	}
}
