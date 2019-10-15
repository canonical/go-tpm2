// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func policyUpdate(alg AlgorithmId, digest Digest, commandCode CommandCode, arg2 Name, arg3 Nonce) Digest {
	h := cryptConstructHash(alg)
	h.Write(digest)
	binary.Write(h, binary.BigEndian, commandCode)
	h.Write(arg2)

	digest = h.Sum(nil)

	h = cryptConstructHash(alg)
	h.Write(digest)
	h.Write(arg3)

	return h.Sum(nil)
}

func TestPolicySigned(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme: RSAScheme{
					Scheme: AlgorithmRSASSA,
					Details: AsymSchemeU{
						Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, keyName, err := tpm.Load(primary, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, key)

	testHash := make([]byte, 32)
	rand.Read(testHash)

	for _, data := range []struct {
		desc            string
		includeNonceTPM bool
		expiration      int32
		cpHashA         Digest
		policyRef       Nonce
	}{
		{
			desc: "Basic",
		},
		{
			desc:            "WithNonceTPM",
			includeNonceTPM: true,
		},
		{
			desc:      "WithPolicyRef",
			policyRef: []byte("foo"),
		},
		{
			desc:       "WithNegativeExpiration",
			expiration: -200,
		},
		{
			desc:       "WithExpiration",
			expiration: 100,
		},
		{
			desc:    "WithCpHash",
			cpHashA: testHash,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			h := sha256.New()
			if data.includeNonceTPM {
				h.Write(sessionContext.(SessionContext).NonceTPM())
			}
			binary.Write(h, binary.BigEndian, data.expiration)
			h.Write(data.cpHashA)
			h.Write(data.policyRef)

			aHash := h.Sum(nil)

			signature, err := tpm.Sign(key, aHash, nil, nil, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			timeout, policyTicket, err := tpm.PolicySigned(key, sessionContext, data.includeNonceTPM,
				data.cpHashA, data.policyRef, data.expiration, signature)
			if err != nil {
				t.Fatalf("PolicySigned failed: %v", err)
			}

			if policyTicket == nil {
				t.Fatalf("Expected a policyTicket")
			}
			if policyTicket.Tag != TagAuthSigned {
				t.Errorf("Unexpected tag: %v", policyTicket.Tag)
			}

			if data.expiration >= 0 {
				if len(timeout) != 0 {
					t.Errorf("Expected an empty timeout")
				}
				if policyTicket.Hierarchy != HandleNull {
					t.Errorf("Unexpected hierarchy: 0x%08x", policyTicket.Hierarchy)
				}
			} else {
				if len(timeout) == 0 {
					t.Errorf("Expected a non zero-length timeout")
				}
				if policyTicket.Hierarchy != HandleOwner {
					t.Errorf("Unexpected hierarchy: 0x%08x", policyTicket.Hierarchy)
				}
			}

			expectedDigest := policyUpdate(AlgorithmSHA256, make([]byte, 32), CommandPolicySigned,
				keyName, data.policyRef)

			policyDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(expectedDigest, policyDigest) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestPolicySecret(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, Auth(testAuth))
	defer flushContext(t, tpm, primary)

	run := func(t *testing.T, cpHashA []byte, policyRef Nonce, expiration int32,
		useSession func(ResourceContext), auth interface{}) {
		sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionContext)

		timeout, policyTicket, err := tpm.PolicySecret(primary, sessionContext, cpHashA, policyRef,
			expiration, auth)
		if err != nil {
			t.Fatalf("PolicySecret failed: %v", err)
		}

		if policyTicket == nil {
			t.Fatalf("Expected a policyTicket")
		}
		if policyTicket.Tag != TagAuthSecret {
			t.Errorf("Unexpected tag: %v", policyTicket.Tag)
		}

		if expiration >= 0 {
			if len(timeout) != 0 {
				t.Errorf("Expected an empty timeout")
			}
			if policyTicket.Hierarchy != HandleNull {
				t.Errorf("Unexpected hierarchy: 0x%08x", policyTicket.Hierarchy)
			}
		} else {
			if len(timeout) == 0 {
				t.Errorf("Expected a non zero-length timeout")
			}
			if policyTicket.Hierarchy != HandleOwner {
				t.Errorf("Unexpected hierarchy: 0x%08x", policyTicket.Hierarchy)
			}
		}

		policyDigest, err := tpm.PolicyGetDigest(sessionContext)
		if err != nil {
			t.Fatalf("PolicyGetDigest failed: %v", err)
		}

		expectedDigest := policyUpdate(AlgorithmSHA256, make([]byte, 32), CommandPolicySecret,
			primary.Name(), policyRef)

		if !bytes.Equal(expectedDigest, policyDigest) {
			t.Errorf("Unexpected digest")
		}

		if useSession != nil {
			useSession(sessionContext)
		}
	}

	t.Run("UsePassword", func(t *testing.T) {
		run(t, nil, nil, 0, nil, testAuth)
	})
	t.Run("UseSession", func(t *testing.T) {
		sessionContext, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifyContextFlushed(t, tpm, sessionContext)
		run(t, nil, nil, 0, nil, &Session{Context: sessionContext, AuthValue: testAuth})
	})
	t.Run("WithPolicyRef", func(t *testing.T) {
		run(t, nil, []byte("foo"), 0, nil, testAuth)
	})
	t.Run("WithNegativeExpiration", func(t *testing.T) {
		run(t, nil, nil, -100, nil, testAuth)
	})
	t.Run("WithExpiration", func(t *testing.T) {
		policyDigest := policyUpdate(AlgorithmSHA256, make([]byte, 32), CommandPolicySecret,
			primary.Name(), nil)

		secret := []byte("secret data")
		template := Public{
			Type:       AlgorithmKeyedHash,
			NameAlg:    AlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent,
			AuthPolicy: policyDigest,
			Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
		sensitive := SensitiveCreate{Data: secret}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil,
			testAuth)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectContext)

		useSession := func(sessionContext ResourceContext) {
			time.Sleep(2 * time.Second)
			_, err := tpm.Unseal(objectContext,
				&Session{Context: sessionContext, Attrs: AttrContinueSession})
			if err == nil {
				t.Fatalf("Unseal should have failed")
			}
			se, isSessionErr := err.(TPMSessionError)
			if !isSessionErr || se.Code != ErrorExpired {
				t.Errorf("Unexpected error: %v", err)
			}
		}

		run(t, nil, nil, 1, useSession, testAuth)
	})
	t.Run("WithCpHash", func(t *testing.T) {
		policyDigest := policyUpdate(AlgorithmSHA256, make([]byte, 32), CommandPolicySecret,
			primary.Name(), nil)

		secret1 := []byte("secret data1")
		secret2 := []byte("secret data2")
		template := Public{
			Type:       AlgorithmKeyedHash,
			NameAlg:    AlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent,
			AuthPolicy: policyDigest,
			Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
		sensitive1 := SensitiveCreate{Data: secret1}
		sensitive2 := SensitiveCreate{Data: secret2}

		outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive1, &template, nil, nil,
			testAuth)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext1, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectContext1)

		outPrivate, outPublic, _, _, _, err = tpm.Create(primary, &sensitive2, &template, nil, nil,
			testAuth)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectContext2, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectContext2)

		cpHash, err := ComputeCpHash(AlgorithmSHA256, CommandUnseal, objectContext2)
		if err != nil {
			t.Fatalf("ComputeCpHash failed: %v", err)
		}

		useSession := func(sessionContext ResourceContext) {
			_, err := tpm.Unseal(objectContext1,
				&Session{Context: sessionContext, Attrs: AttrContinueSession})
			if err == nil {
				t.Fatalf("Unseal should have failed")
			}
			se, isSessionErr := err.(TPMSessionError)
			if !isSessionErr || se.Code != ErrorPolicyFail {
				t.Errorf("Unexpected error: %v", err)
			}
			_, err = tpm.Unseal(objectContext2,
				&Session{Context: sessionContext, Attrs: AttrContinueSession})
			if err != nil {
				t.Errorf("Unseal failed: %v", err)
			}
		}

		run(t, cpHash, nil, 0, useSession, testAuth)
	})
}

func TestPolicyTicketFromSecret(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, Auth(testAuth))
	defer flushContext(t, tpm, primary)

	testHash := make([]byte, 32)
	rand.Read(testHash)

	for _, data := range []struct {
		desc      string
		cpHashA   Digest
		policyRef Nonce
	}{
		{
			desc: "Basic",
		},
		{
			desc:    "WithCpHash",
			cpHashA: testHash,
		},
		{
			desc:      "WithPolicyRef",
			policyRef: []byte("5678"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext1, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext1)

			timeout, ticket, err := tpm.PolicySecret(primary, sessionContext1, data.cpHashA,
				data.policyRef, -60, testAuth)
			if err != nil {
				t.Fatalf("PolicySecret failed: %v", err)
			}

			sessionContext2, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext2)

			if err := tpm.PolicyTicket(sessionContext2, timeout, data.cpHashA, data.policyRef,
				primary.Name(), ticket); err != nil {
				t.Errorf("PolicyTicket failed: %v", err)
			}

			digest1, err := tpm.PolicyGetDigest(sessionContext1)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			digest2, err := tpm.PolicyGetDigest(sessionContext2)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest1, digest2) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestPolicyTicketFromSigned(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:    AlgorithmRSA,
		NameAlg: AlgorithmSHA256,
		Attrs:   AttrFixedTPM | AttrFixedParent | AttrSensitiveDataOrigin | AttrUserWithAuth | AttrSign,
		Params: PublicParamsU{
			Data: &RSAParams{
				Symmetric: SymDefObject{Algorithm: AlgorithmNull},
				Scheme: RSAScheme{
					Scheme: AlgorithmRSASSA,
					Details: AsymSchemeU{
						Data: &SigSchemeRSASSA{HashAlg: AlgorithmSHA256}}},
				KeyBits:  2048,
				Exponent: 0}}}
	priv, pub, _, _, _, err := tpm.Create(primary, nil, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	key, keyName, err := tpm.Load(primary, priv, pub, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, key)

	testHash := make([]byte, 32)
	rand.Read(testHash)

	for _, data := range []struct {
		desc      string
		cpHashA   Digest
		policyRef Nonce
	}{
		{
			desc: "Basic",
		},
		{
			desc:    "WithCpHash",
			cpHashA: testHash,
		},
		{
			desc:      "WithPolicyRef",
			policyRef: []byte("5678"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext1, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext1)

			h := sha256.New()
			h.Write(sessionContext1.(SessionContext).NonceTPM())
			binary.Write(h, binary.BigEndian, int32(-60))
			h.Write(data.cpHashA)
			h.Write(data.policyRef)

			aHash := h.Sum(nil)

			signature, err := tpm.Sign(key, aHash, nil, nil, nil)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			timeout, ticket, err := tpm.PolicySigned(key, sessionContext1, true, data.cpHashA,
				data.policyRef, -60, signature)
			if err != nil {
				t.Fatalf("PolicySigned failed: %v", err)
			}

			sessionContext2, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext2)

			if err := tpm.PolicyTicket(sessionContext2, timeout, data.cpHashA, data.policyRef,
				keyName, ticket); err != nil {
				t.Errorf("PolicyTicket failed: %v", err)
			}

			digest1, err := tpm.PolicyGetDigest(sessionContext1)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			digest2, err := tpm.PolicyGetDigest(sessionContext2)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest1, digest2) {
				t.Errorf("Unexpected digest")
			}
		})
	}
}

func TestPolicyOR(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	trialSessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, trialSessionContext)

	pcrSelection := PCRSelectionList{PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7}}}
	if err := tpm.PolicyPCR(trialSessionContext, nil, pcrSelection); err != nil {
		t.Fatalf("PolicyPCR failed: %v", err)
	}

	trialPolicyDigest, err := tpm.PolicyGetDigest(trialSessionContext)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if err := tpm.FlushContext(trialSessionContext); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}

	digestList := []Digest{trialPolicyDigest}
	for i := 0; i < 4; i++ {
		digest := make(Digest, sha256.Size)
		if _, err := rand.Read(digest); err != nil {
			t.Fatalf("Failed to get random data: %v", err)
		}
		digestList = append(digestList, digest)
	}

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionContext)

	if err := tpm.PolicyPCR(sessionContext, nil, pcrSelection); err != nil {
		t.Fatalf("PolicyPCR failed: %v", err)
	}
	if err := tpm.PolicyOR(sessionContext, digestList); err != nil {
		t.Fatalf("PolicyOR failed: %v", err)
	}

	policyDigest, err := tpm.PolicyGetDigest(sessionContext)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	digests := new(bytes.Buffer)
	for _, digest := range digestList {
		digests.Write(digest)
	}

	hasher := sha256.New()
	hasher.Write(make([]byte, sha256.Size))
	binary.Write(hasher, binary.BigEndian, CommandPolicyOR)
	hasher.Write(digests.Bytes())

	expectedPolicyDigest := hasher.Sum(nil)

	if !bytes.Equal(policyDigest, expectedPolicyDigest) {
		t.Errorf("Unexpected policy digest")
	}
}

func TestPolicyPCR(t *testing.T) {
	tpm, _ := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		index int
		data  []byte
	}{
		{
			index: 7,
			data:  []byte("foo"),
		},
		{
			index: 8,
			data:  []byte("bar"),
		},
		{
			index: 9,
			data:  []byte("1234"),
		},
	} {
		_, err := tpm.PCREvent(Handle(data.index), data.data, nil)
		if err != nil {
			t.Fatalf("PCREvent failed: %v", err)
		}
	}

	calculatePCRDigest := func(pcrs PCRSelectionList) []byte {
		_, pcrValues, err := tpm.PCRRead(pcrs)
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}

		hasher := sha256.New()
		j := 0
		for _, selection := range pcrs {
			for _ = range selection.Select {
				hasher.Write(pcrValues[j])
				j++
			}
		}
		return hasher.Sum(nil)
	}

	for _, data := range []struct {
		desc   string
		digest Digest
		pcrs   PCRSelectionList
	}{
		{
			desc: "SinglePCRSingleBank",
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7}}},
		},
		{
			desc: "SinglePCRMultipleBank",
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{8}},
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{8}}},
		},
		{
			desc: "SinglePCRMultipleBank2",
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{8}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{8}}},
		},
		{
			desc: "MultiplePCRSingleBank",
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8, 9}}},
		},
		{
			desc: "MultiplePCRMultipleBank",
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7, 8, 9}},
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{7, 8, 9}}},
		},
		{
			desc: "WithDigest",
			digest: calculatePCRDigest(PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{8}},
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{8}}}),
			pcrs: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{8}},
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{8}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyPCR(sessionContext, data.digest, data.pcrs); err != nil {
				t.Fatalf("PolicyPCR failed: %v", err)
			}

			policyDigest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			pcrDigest := calculatePCRDigest(data.pcrs)

			hasher := sha256.New()
			hasher.Write(make([]byte, sha256.Size))
			binary.Write(hasher, binary.BigEndian, CommandPolicyPCR)
			MarshalToWriter(hasher, data.pcrs)
			hasher.Write(pcrDigest)

			expectedPolicyDigest := hasher.Sum(nil)

			if !bytes.Equal(policyDigest, expectedPolicyDigest) {
				t.Errorf("Unexpected policy digest")
			}
		})
	}
}

func TestPolicyCommandCode(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	hasher := sha256.New()
	hasher.Write(make([]byte, 32))
	binary.Write(hasher, binary.BigEndian, CommandPolicyCommandCode)
	binary.Write(hasher, binary.BigEndian, CommandUnseal)

	authPolicy := hasher.Sum(nil)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:       AlgorithmKeyedHash,
		NameAlg:    AlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent,
		AuthPolicy: authPolicy,
		Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
	sensitive := SensitiveCreate{Data: []byte("secret")}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, sessionContext)

	if err := tpm.PolicyCommandCode(sessionContext, CommandUnseal); err != nil {
		t.Fatalf("PolicyPassword failed: %v", err)
	}

	digest, err := tpm.PolicyGetDigest(sessionContext)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if !bytes.Equal(digest, authPolicy) {
		t.Errorf("Unexpected session digest")
	}

	if _, err := tpm.Unseal(objectContext, &Session{Context: sessionContext}); err != nil {
		t.Errorf("Unseal failed: %v", err)
	}
}

func TestPolicyAuthValue(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	hasher := sha256.New()
	hasher.Write(make([]byte, 32))
	binary.Write(hasher, binary.BigEndian, CommandPolicyAuthValue)

	authPolicy := hasher.Sum(nil)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:       AlgorithmKeyedHash,
		NameAlg:    AlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent,
		AuthPolicy: authPolicy,
		Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
	sensitive := SensitiveCreate{Data: []byte("secret"), UserAuth: testAuth}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	for _, data := range []struct {
		desc     string
		tpmKey   ResourceContext
		bind     ResourceContext
		bindAuth []byte
	}{
		{
			desc: "UnboundUnsalted",
		},
		{
			desc:     "BoundUnsalted",
			bind:     objectContext,
			bindAuth: testAuth,
		},
		{
			desc:   "UnboundSalted",
			tpmKey: primary,
		},
		{
			desc:     "BoundSalted",
			tpmKey:   primary,
			bind:     objectContext,
			bindAuth: testAuth,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			sessionContext, err := tpm.StartAuthSession(data.tpmKey, data.bind, SessionTypePolicy,
				nil, AlgorithmSHA256, data.bindAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer verifyContextFlushed(t, tpm, sessionContext)

			if err := tpm.PolicyAuthValue(sessionContext); err != nil {
				t.Fatalf("PolicyAuthValue failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, authPolicy) {
				t.Errorf("Unexpected session digest")
			}

			if _, err := tpm.Unseal(objectContext, &Session{Context: sessionContext,
				AuthValue: testAuth}); err != nil {
				t.Errorf("Unseal failed: %v", err)
			}
		})
	}
}

func TestPolicyPassword(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	hasher := sha256.New()
	hasher.Write(make([]byte, 32))
	binary.Write(hasher, binary.BigEndian, CommandPolicyAuthValue)

	authPolicy := hasher.Sum(nil)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	template := Public{
		Type:       AlgorithmKeyedHash,
		NameAlg:    AlgorithmSHA256,
		Attrs:      AttrFixedTPM | AttrFixedParent,
		AuthPolicy: authPolicy,
		Params:     PublicParamsU{&KeyedHashParams{Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
	sensitive := SensitiveCreate{Data: []byte("secret"), UserAuth: testAuth}
	outPrivate, outPublic, _, _, _, err := tpm.Create(primary, &sensitive, &template, nil, nil, nil)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	objectContext, _, err := tpm.Load(primary, outPrivate, outPublic, nil)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	defer flushContext(t, tpm, objectContext)

	sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer verifyContextFlushed(t, tpm, sessionContext)

	if err := tpm.PolicyPassword(sessionContext); err != nil {
		t.Fatalf("PolicyPassword failed: %v", err)
	}

	digest, err := tpm.PolicyGetDigest(sessionContext)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if !bytes.Equal(digest, authPolicy) {
		t.Errorf("Unexpected session digest")
	}

	if _, err := tpm.Unseal(objectContext, &Session{Context: sessionContext,
		AuthValue: testAuth}); err != nil {
		t.Errorf("Unseal failed: %v", err)
	}
}

func TestPolicyNV(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, nil)
	defer flushContext(t, tpm, primary)

	twentyFiveUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(twentyFiveUint64, 25)

	tenUint64 := make(Operand, 8)
	binary.BigEndian.PutUint64(tenUint64, 10)

	fortyUint32 := make(Operand, 4)
	binary.BigEndian.PutUint32(fortyUint32, 40)

	for _, data := range []struct {
		desc      string
		pub       NVPublic
		prepare   func(*testing.T, ResourceContext, interface{})
		operandB  Operand
		offset    uint16
		operation ArithmeticOp
	}{
		{
			desc: "UnsignedLE",
			pub: NVPublic{
				Index:   Handle(0x0181ffff),
				NameAlg: AlgorithmSHA256,
				Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				Size:    8},
			prepare: func(t *testing.T, index ResourceContext, auth interface{}) {
				if err := tpm.NVWrite(index, index, MaxNVBuffer(twentyFiveUint64), 0,
					auth); err != nil {
					t.Fatalf("NVWrite failed: %v", err)
				}
			},
			operandB:  twentyFiveUint64,
			offset:    0,
			operation: OpUnsignedLE,
		},
		{
			desc: "UnsignedGT",
			pub: NVPublic{
				Index:   Handle(0x0181ffff),
				NameAlg: AlgorithmSHA256,
				Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				Size:    8},
			prepare: func(t *testing.T, index ResourceContext, auth interface{}) {
				if err := tpm.NVWrite(index, index, MaxNVBuffer(twentyFiveUint64), 0,
					auth); err != nil {
					t.Fatalf("NVWrite failed: %v", err)
				}
			},
			operandB:  tenUint64,
			offset:    0,
			operation: OpUnsignedGT,
		},
		{
			desc: "Offset",
			pub: NVPublic{
				Index:   Handle(0x0181ffff),
				NameAlg: AlgorithmSHA256,
				Attrs:   MakeNVAttributes(AttrNVAuthWrite|AttrNVAuthRead, NVTypeOrdinary),
				Size:    8},
			prepare: func(t *testing.T, index ResourceContext, auth interface{}) {
				if err := tpm.NVWrite(index, index, MaxNVBuffer(fortyUint32), 4,
					auth); err != nil {
					t.Fatalf("NVWrite failed: %v", err)
				}
			},
			operandB:  fortyUint32,
			offset:    4,
			operation: OpEq,
		},
	} {
		createIndex := func(t *testing.T, authValue Auth) ResourceContext {
			if err := tpm.NVDefineSpace(HandleOwner, authValue, &data.pub, nil); err != nil {
				t.Fatalf("NVDefineSpace failed: %v", err)
			}
			index, err := tpm.WrapHandle(data.pub.Index)
			if err != nil {
				t.Fatalf("WrapHandle failed: %v", err)
			}
			return index
		}

		run := func(t *testing.T, index ResourceContext, auth interface{}) {
			data.prepare(t, index, auth)

			h := sha256.New()
			h.Write(data.operandB)
			binary.Write(h, binary.BigEndian, data.offset)
			binary.Write(h, binary.BigEndian, data.operation)

			args := h.Sum(nil)

			h = sha256.New()
			h.Write(make([]byte, 32))
			binary.Write(h, binary.BigEndian, CommandPolicyNV)
			h.Write(args)
			h.Write(index.Name())

			authPolicy := h.Sum(nil)

			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			if err := tpm.PolicyNV(index, index, sessionContext, data.operandB, data.offset,
				data.operation, auth); err != nil {
				t.Fatalf("PolicyNV failed: %v", err)
			}

			digest, err := tpm.PolicyGetDigest(sessionContext)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			if !bytes.Equal(digest, authPolicy) {
				t.Errorf("Unexpected session digest")
			}
		}

		t.Run(data.desc+"/NoAuth", func(t *testing.T) {
			index := createIndex(t, nil)
			defer undefineNVSpace(t, tpm, index, HandleOwner, nil)
			run(t, index, nil)
		})

		t.Run(data.desc+"/UsePasswordAuth", func(t *testing.T) {
			index := createIndex(t, testAuth)
			defer undefineNVSpace(t, tpm, index, HandleOwner, nil)
			run(t, index, testAuth)
		})

		t.Run(data.desc+"/UseSessionAuth", func(t *testing.T) {
			index := createIndex(t, testAuth)
			defer undefineNVSpace(t, tpm, index, HandleOwner, nil)

			// Don't use a bound session as the name of index changes when it is written to for the
			// first time
			sessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeHMAC, nil,
				AlgorithmSHA256, testAuth)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionContext)

			session := &Session{Context: sessionContext, Attrs: AttrContinueSession,
				AuthValue: testAuth}
			run(t, index, session)
		})
	}

}

type mockResourceContext struct {
	name Name
}

func (c *mockResourceContext) Name() Name {
	return c.name
}
func (c *mockResourceContext) Handle() Handle {
	return HandleNull
}

func TestComputeCpHash(t *testing.T) {
	h := sha256.New()
	h.Write([]byte("foo"))
	name, _ := MarshalToBytes(AlgorithmSHA256, RawBytes(h.Sum(nil)))
	rc := &mockResourceContext{name}

	for _, data := range []struct {
		desc     string
		alg      AlgorithmId
		command  CommandCode
		params   []interface{}
		expected Digest
	}{
		{
			desc:    "Unseal",
			alg:     AlgorithmSHA256,
			command: CommandUnseal,
			params:  []interface{}{rc},
			expected: Digest{0xe5, 0xe8, 0x03, 0xe4, 0xcb, 0xd3, 0x3f, 0x78, 0xc5, 0x65, 0x1b, 0x49,
				0xf2, 0x83, 0xba, 0x63, 0x8a, 0xdf, 0x34, 0xca, 0x69, 0x60, 0x76, 0x40, 0xfb,
				0xea, 0x9e, 0xe2, 0x89, 0xfd, 0x93, 0xe7},
		},
		{
			desc:    "EvictControl",
			alg:     AlgorithmSHA1,
			command: CommandEvictControl,
			params:  []interface{}{HandleOwner, rc, Handle(0x8100ffff)},
			expected: Digest{0x40, 0x93, 0x38, 0x44, 0x00, 0xde, 0x24, 0x3a, 0xcb, 0x81, 0x04, 0xba,
				0x14, 0xbf, 0x2f, 0x2e, 0xf8, 0xa8, 0x27, 0x0b},
		},
		{
			desc:    "DAParameters",
			alg:     AlgorithmSHA256,
			command: CommandDictionaryAttackParameters,
			params:  []interface{}{HandleLockout, Separator, uint32(32), uint32(7200), uint32(86400)},
			expected: Digest{0x8e, 0xa6, 0x7e, 0x49, 0x3d, 0x62, 0x56, 0x21, 0x4c, 0x2e, 0xd2, 0xe9,
				0xfd, 0x69, 0xbe, 0x71, 0x4a, 0x5e, 0x1b, 0xab, 0x5d, 0x55, 0x24, 0x56, 0xd0,
				0x29, 0x82, 0xe1, 0x5c, 0xd2, 0x61, 0xde},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			cpHash, err := ComputeCpHash(data.alg, data.command, data.params...)
			if err != nil {
				t.Fatalf("ComputeCpHash failed: %v", err)
			}

			if !bytes.Equal(cpHash, data.expected) {
				t.Errorf("Unexpected digest (got %x, expected %x)", cpHash, data.expected)
			}
		})
	}
}
