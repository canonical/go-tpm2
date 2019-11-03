// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"testing"
)

func TestPCRExtend(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc       string
		index      int
		algorithms []AlgorithmId
		data       []byte
	}{
		{
			desc:       "1",
			index:      0,
			algorithms: []AlgorithmId{AlgorithmSHA1},
			data:       []byte("foo"),
		},
		{
			desc:       "2",
			index:      3,
			algorithms: []AlgorithmId{AlgorithmSHA256},
			data:       []byte("bar"),
		},
		{
			desc:       "3",
			index:      3,
			algorithms: []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256},
			data:       []byte("foo"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcrSelection := PCRSelectionList{}
			for _, alg := range data.algorithms {
				pcrSelection = append(pcrSelection, PCRSelection{Hash: alg, Select: PCRSelectionData{data.index}})
			}

			origUpdateCounter, origValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			hashList := TaggedHashList{}

			for _, alg := range data.algorithms {
				hasher := cryptConstructHash(alg)
				hasher.Write(data.data)
				hashList = append(hashList, TaggedHash{HashAlg: alg, Digest: hasher.Sum(nil)})
			}

			if err := tpm.PCRExtend(Handle(data.index), hashList, nil); err != nil {
				t.Fatalf("PCRExtend failed: %v", err)
			}

			newUpdateCounter, newValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			expectedUpdateCounter := origUpdateCounter + uint32(len(data.algorithms))
			if newUpdateCounter != expectedUpdateCounter {
				t.Errorf("Unexpected update count (got %d, expected %d)", newUpdateCounter, expectedUpdateCounter)
			}

			for i, alg := range data.algorithms {
				hasher := cryptConstructHash(alg)
				hasher.Write(origValues[alg][data.index])
				hasher.Write(hashList[i].Digest)

				expected := hasher.Sum(nil)

				if !bytes.Equal(expected, newValues[alg][data.index]) {
					t.Errorf("Updated PCR has unexpected value for algorithm %v (got %x, expected %x)", alg, newValues[alg][data.index], expected)
				}
			}
		})
	}
}

func TestPCREvent(t *testing.T) {
	tpm := openTPMForTesting(t)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc  string
		index int
		data  Event
	}{
		{
			desc:  "1",
			index: 2,
			data:  Event("foo"),
		},
		{
			desc:  "2",
			index: 2,
			data:  Event("bar"),
		},
		{
			desc:  "3",
			index: 5,
			data:  Event("foo"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcrSelection := PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{data.index}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{data.index}}}

			origUpdateCounter, origValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			digests, err := tpm.PCREvent(Handle(data.index), data.data, nil)
			if err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}

			for _, alg := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256} {
				hasher := cryptConstructHash(alg)
				hasher.Write(data.data)
				expectedDigest := hasher.Sum(nil)
				digest := []byte{}
				for _, d := range digests {
					if d.HashAlg == alg {
						digest = d.Digest
						break
					}
				}
				if !bytes.Equal(digest, expectedDigest) {
					t.Errorf("PCREvent returned an unexpected digest for algorithm %v (got %x, expected %x)", alg, digest, expectedDigest)
				}
			}

			newUpdateCounter, newValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			expectedUpdateCounter := origUpdateCounter + uint32(len(digests))
			if newUpdateCounter != expectedUpdateCounter {
				t.Errorf("Unexpected update count (got %d, expected %d)", newUpdateCounter, expectedUpdateCounter)
			}

			for _, alg := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256} {
				hasher := cryptConstructHash(alg)
				hasher.Write(origValues[alg][data.index])
				for _, d := range digests {
					if d.HashAlg == alg {
						hasher.Write(d.Digest)
						break
					}
				}

				expected := hasher.Sum(nil)

				if !bytes.Equal(expected, newValues[alg][data.index]) {
					t.Errorf("Updated PCR has unexpected value for algorithm %v (got %x, expected %x)", alg, newValues[alg][data.index], expected)
				}
			}
		})
	}
}

func TestPCRRead(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	resetTPMSimulator(t, tpm, tcti)

	expectedDigests := make(PCRValues)

	for _, data := range []struct {
		index int
		data  []byte
	}{
		{
			index: 1,
			data:  []byte("foo"),
		},
		{
			index: 2,
			data:  []byte("bar"),
		},
		{
			index: 3,
			data:  []byte("xyz"),
		},
		{
			index: 4,
			data:  []byte("1234"),
		},
		{
			index: 5,
			data:  []byte("5678"),
		},
	} {
		_, err := tpm.PCREvent(Handle(data.index), data.data, nil)
		if err != nil {
			t.Fatalf("PCREvent failed: %v", err)
		}
		for _, alg := range []AlgorithmId{AlgorithmSHA1, AlgorithmSHA256} {
			expectedDigests.EnsureBank(alg)
			digestSize := cryptGetDigestSize(alg)

			if _, ok := expectedDigests[alg][data.index]; !ok {
				expectedDigests[alg][data.index] = make(Digest, digestSize)
			}

			h := cryptConstructHash(alg)
			h.Write(data.data)
			dataDigest := h.Sum(nil)

			h = cryptConstructHash(alg)
			h.Write(expectedDigests[alg][data.index])
			h.Write(dataDigest)
			expectedDigests[alg][data.index] = h.Sum(nil)
		}
	}

	for _, data := range []struct {
		desc      string
		selection PCRSelectionList
	}{
		{
			desc: "SinglePCRSingleBank",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{1}}},
		},
		{
			desc: "MultiplePCRSingleBank",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{2, 3, 1}}},
		},
		{
			desc: "SinglePCRMultipleBank",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{2}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{2}}},
		},
		{
			desc: "SinglePCRMultipleBank2",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{2}},
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{2}}},
		},
		{
			desc: "MultiplePCRMultipleBank",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{1, 2, 5}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{1, 5, 2}}},
		},
		{
			desc: "MultipleRequest",
			selection: PCRSelectionList{
				PCRSelection{Hash: AlgorithmSHA1, Select: PCRSelectionData{1, 2, 3, 4, 5}},
				PCRSelection{Hash: AlgorithmSHA256, Select: PCRSelectionData{1, 5, 2, 3, 4}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			_, digests, err := tpm.PCRRead(data.selection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
			for _, selection := range data.selection {
				if _, ok := digests[selection.Hash]; !ok {
					t.Fatalf("No digests for algorithm %v", selection.Hash)
				}
				for _, i := range selection.Select {
					if _, ok := digests[selection.Hash][i]; !ok {
						t.Fatalf("No digest for PCR%d, algorithm %v", i, selection.Hash)
					}
					if !bytes.Equal(expectedDigests[selection.Hash][i], digests[selection.Hash][i]) {
						t.Errorf("Unexpected digest (got %x, expected %x)", digests[selection.Hash][i], expectedDigests[selection.Hash][i])
					}
				}
			}
		})
	}
}
