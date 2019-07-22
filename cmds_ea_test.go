package tpm2

import (
	"bytes"
	"encoding/binary"
	"testing"
)

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
