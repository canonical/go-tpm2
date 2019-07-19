package tpm2

import (
	"bytes"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCreate(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	run := func(t *testing.T, parent ResourceContext, hierarchy Handle, sensitive *SensitiveCreate,
		template *Public, outsideInfo Data, creationPCR PCRSelectionList,
		session interface{}) (*Public, Private) {
		outPrivate, outPublic, creationData, creationHash, creationTicket, err := tpm.Create(
			parent, sensitive, template, outsideInfo, creationPCR, session)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		if len(outPrivate) == 0 {
			t.Errorf("Create returned a zero sized private part")
		}

		verifyPublicAgainstTemplate(t, outPublic, template)
		verifyCreationData(t, tpm, creationData, template, outsideInfo, creationPCR, parent)
		verifyCreationHash(t, creationHash, template)
		verifyCreationTicket(t, creationTicket, hierarchy)

		return outPublic, outPrivate
	}

	t.Run("RSA", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

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
		creationPCR := PCRSelectionList{
			PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{0, 1}},
			PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8}}}

		pub, _ := run(t, primary, HandleOwner, nil, &template, Data{}, creationPCR, nil)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("ECC", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		template := Public{
			Type:    AlgorithmECC,
			NameAlg: AlgorithmSHA1,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
				AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				ECCDetail: &ECCParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    ECCScheme{Scheme: AlgorithmNull},
					CurveID:   ECCCurveNIST_P256,
					KDF:       KDFScheme{Scheme: AlgorithmNull}}},
			Unique: PublicIDU{ECC: &ECCPoint{}}}

		pub, _ := run(t, primary, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, nil)
		if len(pub.Unique.ECC.X) != 32 || len(pub.Unique.ECC.Y) != 32 {
			t.Errorf("CreatePrimary returned object with invalid ECC coords")
		}
	})

	t.Run("WithAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		auth := []byte("1234")

		sensitive := SensitiveCreate{UserAuth: Auth(auth)}
		template := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs: AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth |
				AttrRestricted | AttrDecrypt,
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{
						Algorithm: AlgorithmAES,
						KeyBits:   SymKeyBitsU{Sym: 128},
						Mode:      SymModeU{Sym: AlgorithmCFB}},
					Scheme:   RSAScheme{Scheme: AlgorithmNull},
					KeyBits:  2048,
					Exponent: 0}}}

		pub, priv := run(t, primary, HandleOwner, &sensitive, &template, Data{}, PCRSelectionList{}, nil)
		verifyRSAAgainstTemplate(t, pub, &template)

		handle, _, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, handle)

		run(t, handle, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, auth)
	})

	t.Run("WithOutsideInfo", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

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
		outsideInfo := Data("foo")

		pub, _ := run(t, primary, HandleOwner, nil, &template, outsideInfo, PCRSelectionList{}, nil)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("RequireAuthPW", func(t *testing.T) {
		auth := []byte("foo")

		primary := createRSASrkForTesting(t, tpm, auth)
		defer flushContext(t, tpm, primary)

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

		pub, _ := run(t, primary, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, auth)
		verifyRSAAgainstTemplate(t, pub, &template)
	})

	t.Run("RequireAuthSession", func(t *testing.T) {
		auth := []byte("1234")

		primary := createRSASrkForTesting(t, tpm, auth)
		defer flushContext(t, tpm, primary)

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

		sessionHandle, err :=
			tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, AlgorithmSHA256, auth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)

		session := Session{Handle: sessionHandle}

		pub, _ := run(t, primary, HandleOwner, nil, &template, Data{}, PCRSelectionList{}, &session)
		verifyRSAAgainstTemplate(t, pub, &template)
	})
}

func TestLoad(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	run := func(t *testing.T, parent ResourceContext, session interface{}) {
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

		outPrivate, outPublic, _, _, _, err := tpm.Create(parent, nil, &template, nil, nil, session)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectHandle, name, err := tpm.Load(parent, outPrivate, outPublic, session)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle)

		if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("Create returned an invalid handle 0x%08x", objectHandle.Handle())
		}
		if len(name) != 34 {
			t.Errorf("Create returned a name of the wrong length %d", len(name))
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		primary := createRSASrkForTesting(t, tpm, nil)
		defer flushContext(t, tpm, primary)

		run(t, primary, nil)
	})

	t.Run("RequireAuthPW", func(t *testing.T) {
		auth := []byte("foo")

		primary := createRSASrkForTesting(t, tpm, auth)
		defer flushContext(t, tpm, primary)

		run(t, primary, auth)
	})

	t.Run("RequireAuthSession", func(t *testing.T) {
		auth := []byte("foo")

		primary := createRSASrkForTesting(t, tpm, auth)
		defer flushContext(t, tpm, primary)

		sessionHandle, err :=
			tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, AlgorithmSHA256, auth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)

		session := Session{Handle: sessionHandle, Attrs: AttrContinueSession}

		run(t, primary, &session)
	})
}

func TestReadPublic(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

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
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectHandle, name1, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectHandle)

	public, name2, qualifiedName, err := tpm.ReadPublic(objectHandle)
	if err != nil {
		t.Fatalf("ReadPublic failed: %v", err)
	}

	verifyPublicAgainstTemplate(t, &template, public)

	if !bytes.Equal(name1, name2) {
		t.Errorf("ReadPublic returned an unexpected name")
	}
	if len(qualifiedName) != 34 {
		t.Errorf("ReadPublic returned a qualifiedName of the wrong length")
	}
}

func TestLoadExternal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	run := func(t *testing.T, sensitive *Sensitive, template *Public, hierarchy Handle) {
		objectHandle, name, err := tpm.LoadExternal(sensitive, template, hierarchy)
		if err != nil {
			t.Fatalf("LoadExternal failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle)

		if objectHandle.Handle()&HandleTypeTransientObject != HandleTypeTransientObject {
			t.Errorf("LoadExternal returned an invalid handle 0x%08x", objectHandle.Handle())
		}
		nameAlgSize, _ := digestSizes[template.NameAlg]
		if len(name) != int(nameAlgSize)+2 {
			t.Errorf("LoadExternal returned a name of the wrong length")
		}
	}

	t.Run("RSA", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}
		sensitive := Sensitive{
			Type:      AlgorithmRSA,
			Sensitive: SensitiveCompositeU{RSA: key.Primes[0].Bytes()}}
		public := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    RSAScheme{Scheme: AlgorithmNull},
					KeyBits:   2048,
					Exponent:  uint32(key.PublicKey.E)}},
			Unique: PublicIDU{RSA: key.PublicKey.N.Bytes()}}

		run(t, &sensitive, &public, HandleNull)
	})

	t.Run("ECC", func(t *testing.T) {
		priv, x, y, err := elliptic.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("Generating an ECC key failed: %v", err)
		}
		sensitive := Sensitive{
			Type:      AlgorithmECC,
			Sensitive: SensitiveCompositeU{ECC: priv}}
		public := Public{
			Type:    AlgorithmECC,
			NameAlg: AlgorithmSHA1,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				ECCDetail: &ECCParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    ECCScheme{Scheme: AlgorithmNull},
					CurveID:   ECCCurveNIST_P256,
					KDF:       KDFScheme{Scheme: AlgorithmNull}}},
			Unique: PublicIDU{ECC: &ECCPoint{X: x.Bytes(), Y: y.Bytes()}}}

		run(t, &sensitive, &public, HandleNull)
	})

	t.Run("PublicOnly", func(t *testing.T) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("Generating an RSA key failed: %v", err)
		}

		public := Public{
			Type:    AlgorithmRSA,
			NameAlg: AlgorithmSHA256,
			Attrs:   AttrSensitiveDataOrigin | AttrUserWithAuth | AttrDecrypt | AttrSign,
			Params: PublicParamsU{
				RSADetail: &RSAParams{
					Symmetric: SymDefObject{Algorithm: AlgorithmNull},
					Scheme:    RSAScheme{Scheme: AlgorithmNull},
					KeyBits:   2048,
					Exponent:  uint32(key.PublicKey.E)}},
			Unique: PublicIDU{RSA: key.PublicKey.N.Bytes()}}

		run(t, nil, &public, HandleOwner)
	})
}

func TestUnseal(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	secret := []byte("sensitive data")

	create := func(t *testing.T, authPolicy Digest, authValue Auth,
		extraAttrs ObjectAttributes) ResourceContext {
		template := Public{
			Type:       AlgorithmKeyedHash,
			NameAlg:    AlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent | extraAttrs,
			AuthPolicy: authPolicy,
			Params: PublicParamsU{
				KeyedHashDetail: &KeyedHashParams{
					Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}

		sensitive := SensitiveCreate{Data: secret, UserAuth: authValue}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectHandle, _, err := tpm.Load(primary, outPrivate, outPublic, "")
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		return objectHandle
	}

	run := func(t *testing.T, handle ResourceContext, session interface{}) {
		sensitiveData, err := tpm.Unseal(handle, session)
		if err != nil {
			t.Fatalf("Unseal failed: %v", err)
		}
		if !bytes.Equal(sensitiveData, secret) {
			t.Errorf("Unseal didn't return the expected data (got %x)", sensitiveData)
		}
	}

	t.Run("NoAuth", func(t *testing.T) {
		handle := create(t, nil, nil, AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		run(t, handle, nil)
	})

	t.Run("WithPWAuth", func(t *testing.T) {
		auth := []byte("foo")
		handle := create(t, nil, Auth(auth), AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		run(t, handle, auth)
	})

	t.Run("WithHMACAuth", func(t *testing.T) {
		auth := []byte("foo")
		handle := create(t, nil, Auth(auth), AttrUserWithAuth)
		defer flushContext(t, tpm, handle)
		sessionHandle, err :=
			tpm.StartAuthSession(nil, handle, SessionTypeHMAC, nil, AlgorithmSHA256, auth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)
		run(t, handle, &Session{Handle: sessionHandle})
	})

	t.Run("WithPolicyAuth", func(t *testing.T) {
		handle := create(t, make([]byte, 32), nil, 0)
		defer flushContext(t, tpm, handle)
		sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)
		run(t, handle, &Session{Handle: sessionHandle})
	})
}

func TestObjectChangeAuth(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer tpm.Close()

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	create := func(t *testing.T, userAuth Auth) (ResourceContext, *Public) {
		sensitive := SensitiveCreate{Data: []byte("sensitive data"), UserAuth: userAuth}
		template := Public{
			Type:    AlgorithmKeyedHash,
			NameAlg: AlgorithmSHA256,
			Attrs:   AttrFixedTPM | AttrFixedParent | AttrUserWithAuth,
			Params: PublicParamsU{
				KeyedHashDetail: &KeyedHashParams{
					Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectHandle, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		return objectHandle, outPublic
	}

	run := func(t *testing.T, handle ResourceContext, pub *Public, authValue Auth, session interface{}) {
		priv, err := tpm.ObjectChangeAuth(handle, primary, authValue, session)
		if err != nil {
			t.Fatalf("ObjectChangeAuth failed: %v", err)
		}

		newHandle, _, err := tpm.Load(primary, priv, pub, nil)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, newHandle)

		_, err = tpm.Unseal(newHandle, authValue)
		if err != nil {
			t.Errorf("Unseal failed: %v", err)
		}
	}

	t.Run("WithNoAuth", func(t *testing.T) {
		handle, pub := create(t, nil)
		defer flushContext(t, tpm, handle)
		run(t, handle, pub, Auth("foo"), nil)
	})

	t.Run("WithPWAuth", func(t *testing.T) {
		auth := []byte("foo")
		handle, pub := create(t, Auth(auth))
		defer flushContext(t, tpm, handle)
		run(t, handle, pub, Auth("1234"), auth)
	})

	t.Run("WithUnboundSession", func(t *testing.T) {
		auth := []byte("foo")
		handle, pub := create(t, Auth(auth))
		defer flushContext(t, tpm, handle)
		sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)
		session := Session{Handle: sessionHandle, AuthValue: auth}
		run(t, handle, pub, Auth("1234"), &session)
	})

	t.Run("WithBoundSession", func(t *testing.T) {
		auth := []byte("foo")
		handle, pub := create(t, Auth(auth))
		defer flushContext(t, tpm, handle)
		sessionHandle, err := tpm.StartAuthSession(nil, handle, SessionTypeHMAC, nil, AlgorithmSHA256,
			auth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)
		run(t, handle, pub, Auth("1234"), &Session{Handle: sessionHandle})
	})
}
