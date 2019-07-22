// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

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
