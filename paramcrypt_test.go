// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"testing"
)

func TestParameterEncryptionSingleExtra(t *testing.T) {
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
			for _, data2 := range []struct {
				desc  string
				attrs SessionAttributes
			}{
				{
					desc:  "Command",
					attrs: AttrCommandEncrypt,
				},
				{
					desc:  "Response",
					attrs: AttrResponseEncrypt,
				},
				{
					desc:  "CommandAndResponse",
					attrs: AttrCommandEncrypt | AttrResponseEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					secret := []byte("sensitive data")

					run1 := func(t *testing.T, auth interface{}) HandleContext {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						template := Public{
							Type:    ObjectTypeKeyedHash,
							NameAlg: HashAlgorithmSHA256,
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
							Params: PublicParamsU{
								&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						session := Session{Context: sessionContext, Attrs: AttrContinueSession | data2.attrs}
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, auth, &session)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, name, err := tpm.Load(primary, outPrivate, outPublic, auth, &session)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(name, expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object HandleContext, auth interface{}) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						session := &Session{Context: sessionContext, Attrs: AttrContinueSession | (data2.attrs &^ AttrCommandEncrypt)}
						if session.Attrs&AttrResponseEncrypt == 0 {
							session = nil
						}
						data, err := tpm.Unseal(object, auth, session)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, testAuth)
						defer flushContext(t, tpm, object)
						run2(t, object, testAuth)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						session := Session{Context: sessionContext, Attrs: AttrContinueSession}
						object := run1(t, &session)
						defer flushContext(t, tpm, object)
						run2(t, object, session.WithAuthValue(testAuth))
					})
				})
			}
		})
	}
}

func TestParameterEncryptionSharedWithAuth(t *testing.T) {
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
			for _, data2 := range []struct {
				desc  string
				attrs SessionAttributes
			}{
				{
					desc:  "Command",
					attrs: AttrCommandEncrypt,
				},
				{
					desc:  "Response",
					attrs: AttrResponseEncrypt,
				},
				{
					desc:  "CommandAndResponse",
					attrs: AttrCommandEncrypt | AttrResponseEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
					if err != nil {
						t.Fatalf("StartAuthSession failed: %v", err)
					}
					defer flushContext(t, tpm, sessionContext)
					session := Session{Context: sessionContext, Attrs: AttrContinueSession | data2.attrs, AuthValue: testAuth}

					secret := []byte("sensitive data")

					template := Public{
						Type:    ObjectTypeKeyedHash,
						NameAlg: HashAlgorithmSHA256,
						Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
						Params: PublicParamsU{
							&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
					sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

					outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, &session)
					if err != nil {
						t.Fatalf("Create failed: %v", err)
					}

					objectContext, name, err := tpm.Load(primary, outPrivate, outPublic, &session)
					if err != nil {
						t.Fatalf("Load failed: %v", err)
					}
					defer flushContext(t, tpm, objectContext)

					expectedName, err := outPublic.Name()
					if err != nil {
						t.Fatalf("Cannot compute name: %v", err)
					}
					if !bytes.Equal(name, expectedName) {
						t.Errorf("Unexpected name")
					}

					data, err := tpm.Unseal(objectContext, session.RemoveAttrs(AttrCommandEncrypt))
					if err != nil {
						t.Fatalf("Unseal failed: %v", err)
					}

					if !bytes.Equal(data, secret) {
						t.Errorf("Got unexpected data")
					}
				})
			}
		})
	}
}

func TestParameterEncryptionMultipleExtra(t *testing.T) {
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
			for _, data2 := range []struct {
				desc   string
				attrs1 SessionAttributes
				attrs2 SessionAttributes
			}{
				{
					desc:   "1",
					attrs1: AttrCommandEncrypt,
					attrs2: AttrResponseEncrypt,
				},
				{
					desc:   "2",
					attrs1: AttrResponseEncrypt,
					attrs2: AttrCommandEncrypt,
				},
			} {
				t.Run(data2.desc, func(t *testing.T) {
					secret := []byte("sensitive data")

					run1 := func(t *testing.T, auth interface{}) HandleContext {
						sessionContext1, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext1)

						sessionContext2, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext2)

						template := Public{
							Type:    ObjectTypeKeyedHash,
							NameAlg: HashAlgorithmSHA256,
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
							Params: PublicParamsU{
								&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						session1 := Session{Context: sessionContext1, Attrs: AttrContinueSession | data2.attrs1}
						session2 := Session{Context: sessionContext2, Attrs: AttrContinueSession | data2.attrs2}
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, auth, &session1, &session2)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, name, err := tpm.Load(primary, outPrivate, outPublic, auth, &session1, &session2)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(name, expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object HandleContext, auth interface{}) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						session := &Session{Context: sessionContext, Attrs: AttrContinueSession | data2.attrs1}
						if session.Attrs&AttrResponseEncrypt == 0 {
							session = nil
						}
						data, err := tpm.Unseal(object, auth, session)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, testAuth)
						defer flushContext(t, tpm, object)
						run2(t, object, testAuth)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						session := Session{Context: sessionContext, Attrs: AttrContinueSession}
						object := run1(t, &session)
						defer flushContext(t, tpm, object)
						run2(t, object, session.WithAuthValue(testAuth))
					})
				})
			}
		})
	}
}
