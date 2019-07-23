// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/rand"
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
		digestSize, _ := cryptGetDigestSize(AlgorithmSHA256)
		hasher := cryptHashAlgToGoConstructor(AlgorithmSHA256)()
		hasher.Write(make([]byte, digestSize))
		binary.Write(hasher, binary.BigEndian, CommandPolicySecret)
		hasher.Write(primary.Name())

		newDigest1 := hasher.Sum(nil)

		hasher = cryptHashAlgToGoConstructor(AlgorithmSHA256)()
		hasher.Write(newDigest1)
		hasher.Write(policyRef)

		return hasher.Sum(nil)
	}

	run := func(t *testing.T, cpHashA []byte, policyRef Nonce, expiration int32,
		useSession func(ResourceContext), auth interface{}) {
		sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer flushContext(t, tpm, sessionHandle)

		timeout, policyTicket, err := tpm.PolicySecret(primary, sessionHandle, cpHashA, policyRef,
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

		policyDigest, err := tpm.PolicyGetDigest(sessionHandle)
		if err != nil {
			t.Fatalf("PolicyGetDigest failed: %v", err)
		}

		expectedDigest := trialDigest(t, policyRef)

		if !bytes.Equal(expectedDigest, policyDigest) {
			t.Errorf("Unexpected digest")
		}

		if useSession != nil {
			useSession(sessionHandle)
		}
	}

	t.Run("PWAuth", func(t *testing.T) {
		run(t, nil, nil, 0, nil, testAuth)
	})
	t.Run("SessionAuth", func(t *testing.T) {
		sessionHandle, err := tpm.StartAuthSession(nil, primary, SessionTypeHMAC, nil, AlgorithmSHA256,
			testAuth)
		if err != nil {
			t.Fatalf("StartAuthSession failed: %v", err)
		}
		defer verifySessionFlushed(t, tpm, sessionHandle)
		run(t, nil, nil, 0, nil, &Session{Handle: sessionHandle, AuthValue: dummyAuth})
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

		objectHandle, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle)

		useSession := func(sessionHandle ResourceContext) {
			time.Sleep(2 * time.Second)
			_, err := tpm.Unseal(objectHandle,
				&Session{Handle: sessionHandle, Attrs: AttrContinueSession})
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

		objectHandle1, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle1)

		outPrivate, outPublic, _, _, _, err = tpm.Create(primary, &sensitive2, &template, nil, nil,
			testAuth)
		if err != nil {
			t.Fatalf("Create failed: %v", err)
		}

		objectHandle2, _, err := tpm.Load(primary, outPrivate, outPublic, testAuth)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}
		defer flushContext(t, tpm, objectHandle2)

		cpHash := cryptComputeCpHash(AlgorithmSHA256, CommandUnseal, []Name{objectHandle2.Name()}, nil)

		useSession := func(sessionHandle ResourceContext) {
			_, err := tpm.Unseal(objectHandle1,
				&Session{Handle: sessionHandle, Attrs: AttrContinueSession})
			if err == nil {
				t.Fatalf("Unseal should have failed")
			}
			se, isSessionErr := err.(TPMSessionError)
			if !isSessionErr || se.Code != ErrorPolicyFail {
				t.Errorf("Unexpected error: %v", err)
			}
			_, err = tpm.Unseal(objectHandle2,
				&Session{Handle: sessionHandle, Attrs: AttrContinueSession})
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

	trialSessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypeTrial, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	trialSessionFlushed := false
	defer func() {
		if trialSessionFlushed {
			return
		}
		flushContext(t, tpm, trialSessionHandle)
	}()

	pcrSelection := PCRSelectionList{PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{7}}}
	if err := tpm.PolicyPCR(trialSessionHandle, nil, pcrSelection); err != nil {
		t.Fatalf("PolicyPCR failed: %v", err)
	}

	trialPolicyDigest, err := tpm.PolicyGetDigest(trialSessionHandle)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	if err := tpm.FlushContext(trialSessionHandle); err != nil {
		t.Errorf("FlushContext failed: %v", err)
	}
	trialSessionFlushed = true

	digestList := []Digest{trialPolicyDigest}
	for i := 0; i < 4; i++ {
		digestSize, _ := cryptGetDigestSize(AlgorithmSHA256)
		digest := make(Digest, digestSize)
		if _, err := rand.Read(digest); err != nil {
			t.Fatalf("Failed to get random data: %v", err)
		}
		digestList = append(digestList, digest)
	}

	sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil, AlgorithmSHA256, nil)
	if err != nil {
		t.Fatalf("StartAuthSession failed: %v", err)
	}
	defer flushContext(t, tpm, sessionHandle)

	if err := tpm.PolicyPCR(sessionHandle, nil, pcrSelection); err != nil {
		t.Fatalf("PolicyPCR failed: %v", err)
	}
	if err := tpm.PolicyOR(sessionHandle, digestList); err != nil {
		t.Fatalf("PolicyOR failed: %v", err)
	}

	policyDigest, err := tpm.PolicyGetDigest(sessionHandle)
	if err != nil {
		t.Fatalf("PolicyGetDigest failed: %v", err)
	}

	digests := new(bytes.Buffer)
	for _, digest := range digestList {
		digests.Write(digest)
	}

	digestSize, _ := cryptGetDigestSize(AlgorithmSHA256)
	hasher := cryptHashAlgToGoConstructor(AlgorithmSHA256)()
	hasher.Write(make([]byte, digestSize))
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
		_, _, pcrValues, err := tpm.PCRRead(pcrs)
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}

		hasher := cryptHashAlgToGoConstructor(AlgorithmSHA256)()
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
			sessionHandle, err := tpm.StartAuthSession(nil, nil, SessionTypePolicy, nil,
				AlgorithmSHA256, nil)
			if err != nil {
				t.Fatalf("StartAuthSession failed: %v", err)
			}
			defer flushContext(t, tpm, sessionHandle)

			if err := tpm.PolicyPCR(sessionHandle, data.digest, data.pcrs); err != nil {
				t.Fatalf("PolicyPCR failed: %v", err)
			}

			policyDigest, err := tpm.PolicyGetDigest(sessionHandle)
			if err != nil {
				t.Fatalf("PolicyGetDigest failed: %v", err)
			}

			pcrDigest := calculatePCRDigest(data.pcrs)

			digestSize, _ := cryptGetDigestSize(AlgorithmSHA256)
			hasher := cryptHashAlgToGoConstructor(AlgorithmSHA256)()
			hasher.Write(make([]byte, digestSize))
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
