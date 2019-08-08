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

func TestPolicySecret(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	primary := createRSASrkForTesting(t, tpm, Auth(testAuth))
	defer flushContext(t, tpm, primary)

	trialDigest := func(t *testing.T, policyRef Nonce) Digest {
		hasher := sha256.New()
		hasher.Write(make([]byte, sha256.Size))
		binary.Write(hasher, binary.BigEndian, CommandPolicySecret)
		hasher.Write(primary.Name())

		newDigest1 := hasher.Sum(nil)

		hasher = sha256.New()
		hasher.Write(newDigest1)
		hasher.Write(policyRef)

		return hasher.Sum(nil)
	}

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

		expectedDigest := trialDigest(t, policyRef)

		if !bytes.Equal(expectedDigest, policyDigest) {
			t.Errorf("Unexpected digest")
		}

		if useSession != nil {
			useSession(sessionContext)
		}
	}

	t.Run("PWAuth", func(t *testing.T) {
		run(t, nil, nil, 0, nil, testAuth)
	})
	t.Run("SessionAuth", func(t *testing.T) {
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
		policyDigest := trialDigest(t, nil)

		secret := []byte("secret data")
		template := Public{
			Type:       AlgorithmKeyedHash,
			NameAlg:    AlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent,
			AuthPolicy: policyDigest,
			Params: PublicParamsU{
				KeyedHashDetail: &KeyedHashParams{
					Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
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
		policyDigest := trialDigest(t, nil)

		secret1 := []byte("secret data1")
		secret2 := []byte("secret data2")
		template := Public{
			Type:       AlgorithmKeyedHash,
			NameAlg:    AlgorithmSHA256,
			Attrs:      AttrFixedTPM | AttrFixedParent,
			AuthPolicy: policyDigest,
			Params: PublicParamsU{
				KeyedHashDetail: &KeyedHashParams{
					Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
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

		cpHash := cryptComputeCpHash(AlgorithmSHA256, CommandUnseal, []Name{objectContext2.Name()}, nil)

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

func TestPolicyOR(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	trialSessionContext, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	trialSessionFlushed := false
	defer func() {
		if trialSessionFlushed {
			return
		}
		flushContext(t, tpm, trialSessionContext)
	}()

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
	trialSessionFlushed = true

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
		Params: PublicParamsU{
			KeyedHashDetail: &KeyedHashParams{
				Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
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
		Params: PublicParamsU{
			KeyedHashDetail: &KeyedHashParams{
				Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
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
		Params: PublicParamsU{
			KeyedHashDetail: &KeyedHashParams{
				Scheme: KeyedHashScheme{Scheme: AlgorithmNull}}}}
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
