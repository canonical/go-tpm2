// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

func TestParameterEncryptionSingleExtra(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
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
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
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
					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					run1 := func(t *testing.T, authSession SessionContext) ResourceContext {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						template := Public{
							Type:    ObjectTypeKeyedHash,
							NameAlg: HashAlgorithmSHA256,
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
							Params: &PublicParamsU{
								KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						sessionContext.SetAttrs(AttrContinueSession | data2.attrs)
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, authSession, sessionContext)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, err := tpm.Load(primary, outPrivate, outPublic, authSession, sessionContext)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}
						objectContext.SetAuthValue(testAuth)

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(objectContext.Name(), expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object ResourceContext, authSession SessionContext) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						attrs := AttrContinueSession | (data2.attrs &^ AttrCommandEncrypt)
						sc := sessionContext.WithAttrs(attrs)
						if attrs&AttrResponseEncrypt == 0 {
							sc = nil
						}
						data, err := tpm.Unseal(object, authSession, sc)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, nil)
						defer flushContext(t, tpm, object)
						run2(t, object, nil)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						sessionContext.SetAttrs(AttrContinueSession)
						object := run1(t, sessionContext)
						defer flushContext(t, tpm, object)
						run2(t, object, sessionContext)
					})
				})
			}
		})
	}
}

func TestParameterEncryptionSharedWithAuth(t *testing.T) {
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
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
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
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
					sessionContext.SetAttrs(AttrContinueSession | data2.attrs)

					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					template := Public{
						Type:    ObjectTypeKeyedHash,
						NameAlg: HashAlgorithmSHA256,
						Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
						Params: &PublicParamsU{
							KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
					sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

					outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, sessionContext)
					if err != nil {
						t.Fatalf("Create failed: %v", err)
					}

					objectContext, err := tpm.Load(primary, outPrivate, outPublic, sessionContext)
					if err != nil {
						t.Fatalf("Load failed: %v", err)
					}
					defer flushContext(t, tpm, objectContext)
					objectContext.SetAuthValue(testAuth)

					expectedName, err := outPublic.Name()
					if err != nil {
						t.Fatalf("Cannot compute name: %v", err)
					}
					if !bytes.Equal(objectContext.Name(), expectedName) {
						t.Errorf("Unexpected name")
					}

					data, err := tpm.Unseal(objectContext, sessionContext.ExcludeAttrs(AttrCommandEncrypt))
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
	tpm, _ := testutil.NewTPMContextT(t, testutil.TPMFeatureOwnerHierarchy)
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
				KeyBits:   &SymKeyBitsU{Sym: 128},
				Mode:      &SymModeU{Sym: SymModeCFB}},
		},
		{
			desc: "XOR",
			symmetric: SymDef{
				Algorithm: SymAlgorithmXOR,
				KeyBits:   &SymKeyBitsU{XOR: HashAlgorithmSHA256}},
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
					secret := []byte("sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data sensitive data")

					run1 := func(t *testing.T, authSession SessionContext) ResourceContext {
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
							Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth | AttrNoDA,
							Params: &PublicParamsU{
								KeyedHashDetail: &KeyedHashParams{Scheme: KeyedHashScheme{Scheme: KeyedHashSchemeNull}}}}
						sensitive := SensitiveCreate{Data: secret, UserAuth: testAuth}

						sessionContext1.SetAttrs(AttrContinueSession | data2.attrs1)
						sessionContext2.SetAttrs(AttrContinueSession | data2.attrs2)
						outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, authSession, sessionContext1, sessionContext2)
						if err != nil {
							t.Fatalf("Create failed: %v", err)
						}

						objectContext, err := tpm.Load(primary, outPrivate, outPublic, authSession, sessionContext1, sessionContext2)
						if err != nil {
							t.Fatalf("Load failed: %v", err)
						}
						objectContext.SetAuthValue(testAuth)

						expectedName, err := outPublic.Name()
						if err != nil {
							t.Fatalf("Cannot compute name: %v", err)
						}
						if !bytes.Equal(objectContext.Name(), expectedName) {
							t.Errorf("Unexpected name")
						}

						return objectContext
					}

					run2 := func(t *testing.T, object ResourceContext, authSession SessionContext) {
						sessionContext, err := tpm.StartAuthSession(primary, nil, SessionTypeHMAC, &data.symmetric, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)

						attrs := AttrContinueSession | data2.attrs1
						sc := sessionContext.WithAttrs(attrs)
						if attrs&AttrResponseEncrypt == 0 {
							sc = nil
						}
						data, err := tpm.Unseal(object, authSession, sc)
						if err != nil {
							t.Fatalf("Unseal failed: %v", err)
						}

						if !bytes.Equal(data, secret) {
							t.Errorf("Got unexpected data")
						}
					}

					t.Run("UsePasswordAuth", func(t *testing.T) {
						object := run1(t, nil)
						defer flushContext(t, tpm, object)
						run2(t, object, nil)
					})

					t.Run("/UseSessionAuth", func(t *testing.T) {
						sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, HashAlgorithmSHA256)
						if err != nil {
							t.Fatalf("StartAuthSession failed: %v", err)
						}
						defer flushContext(t, tpm, sessionContext)
						sessionContext.SetAttrs(AttrContinueSession)
						object := run1(t, sessionContext)
						defer flushContext(t, tpm, object)
						run2(t, object, sessionContext)
					})
				})
			}
		})
	}
}
