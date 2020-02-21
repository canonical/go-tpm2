// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"bytes"
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
)

func TestPCRExtend(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityPCRChange)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc       string
		index      int
		algorithms []HashAlgorithmId
		data       []byte
	}{
		{
			desc:       "1",
			index:      0,
			algorithms: []HashAlgorithmId{HashAlgorithmSHA1},
			data:       []byte("foo"),
		},
		{
			desc:       "2",
			index:      3,
			algorithms: []HashAlgorithmId{HashAlgorithmSHA256},
			data:       []byte("bar"),
		},
		{
			desc:       "3",
			index:      3,
			algorithms: []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256},
			data:       []byte("foo"),
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcrSelection := PCRSelectionList{}
			for _, alg := range data.algorithms {
				pcrSelection = append(pcrSelection, PCRSelection{Hash: alg, Select: []int{data.index}})
			}

			origUpdateCounter, origValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			hashList := TaggedHashList{}

			for _, alg := range data.algorithms {
				hasher := alg.NewHash()
				hasher.Write(data.data)
				hashList = append(hashList, TaggedHash{HashAlg: alg, Digest: hasher.Sum(nil)})
			}

			if err := tpm.PCRExtend(tpm.PCRHandleContext(data.index), hashList, nil); err != nil {
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
				hasher := alg.NewHash()
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
	tpm := openTPMForTesting(t, testCapabilityPCRChange)
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
				{Hash: HashAlgorithmSHA1, Select: []int{data.index}},
				{Hash: HashAlgorithmSHA256, Select: []int{data.index}}}

			origUpdateCounter, origValues, err := tpm.PCRRead(pcrSelection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}

			digests, err := tpm.PCREvent(tpm.PCRHandleContext(data.index), data.data, nil)
			if err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}

			for _, alg := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
				hasher := alg.NewHash()
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

			for _, alg := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
				hasher := alg.NewHash()
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
		_, err := tpm.PCREvent(tpm.PCRHandleContext(data.index), data.data, nil)
		if err != nil {
			t.Fatalf("PCREvent failed: %v", err)
		}
		for _, alg := range []HashAlgorithmId{HashAlgorithmSHA1, HashAlgorithmSHA256} {
			expectedDigests.EnsureBank(alg)
			digestSize := alg.Size()

			if _, ok := expectedDigests[alg][data.index]; !ok {
				expectedDigests[alg][data.index] = make(Digest, digestSize)
			}

			h := alg.NewHash()
			h.Write(data.data)
			dataDigest := h.Sum(nil)

			h = alg.NewHash()
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
				{Hash: HashAlgorithmSHA256, Select: []int{1}}},
		},
		{
			desc: "MultiplePCRSingleBank",
			selection: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{2, 3, 1}}},
		},
		{
			desc: "SinglePCRMultipleBank",
			selection: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{2}},
				{Hash: HashAlgorithmSHA256, Select: []int{2}}},
		},
		{
			desc: "SinglePCRMultipleBank2",
			selection: PCRSelectionList{
				{Hash: HashAlgorithmSHA256, Select: []int{2}},
				{Hash: HashAlgorithmSHA1, Select: []int{2}}},
		},
		{
			desc: "MultiplePCRMultipleBank",
			selection: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{1, 2, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{1, 5, 2}}},
		},
		{
			desc: "MultipleRequest",
			selection: PCRSelectionList{
				{Hash: HashAlgorithmSHA1, Select: []int{1, 2, 3, 4, 5}},
				{Hash: HashAlgorithmSHA256, Select: []int{1, 5, 2, 3, 4}}},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			_, digests, err := tpm.PCRRead(data.selection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
			var empty struct{}
			expected := make(map[HashAlgorithmId]map[int]struct{})
			for _, selection := range data.selection {
				if _, ok := expected[selection.Hash]; !ok {
					expected[selection.Hash] = make(map[int]struct{})
				}
				if _, ok := digests[selection.Hash]; !ok {
					t.Fatalf("No digests for algorithm %v", selection.Hash)
				}
				for _, i := range selection.Select {
					expected[selection.Hash][i] = empty
					if _, ok := digests[selection.Hash][i]; !ok {
						t.Fatalf("No digest for PCR%d, algorithm %v", i, selection.Hash)
					}
					if !bytes.Equal(expectedDigests[selection.Hash][i], digests[selection.Hash][i]) {
						t.Errorf("Unexpected digest (got %x, expected %x)", digests[selection.Hash][i], expectedDigests[selection.Hash][i])
					}
				}
			}
			for k, v := range digests {
				if _, ok := expected[k]; !ok {
					t.Errorf("Digest for unexpected algorithm %v returned", k)
				}
				for i, _ := range v {
					if _, ok := expected[k][i]; !ok {
						t.Errorf("Digest for unexpected index %d, algorithm %v returned", i, k)
					}
				}
			}
		})
	}

	t.Run("Empty", func(t *testing.T) {
		pcrUpdateCounter, pcrValues, err := tpm.PCRRead(nil)
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}
		if len(pcrValues) > 0 {
			t.Errorf("Unexpected digests returned")
		}

		if err := tpm.PCRExtend(tpm.PCRHandleContext(7), TaggedHashList{TaggedHash{HashAlg: HashAlgorithmSHA256, Digest: make(Digest, 32)}}, nil); err != nil {
			t.Fatalf("PCRExtend failed: %v", err)
		}

		pcrUpdateCounter2, _, err := tpm.PCRRead(nil)
		if err != nil {
			t.Fatalf("PCRRead failed: %v", err)
		}

		if pcrUpdateCounter2 != pcrUpdateCounter+1 {
			t.Errorf("Unexpected pcrUpdateCounter")
		}
	})
}

func TestPCRReset(t *testing.T) {
	tpm := openTPMForTesting(t, testCapabilityPCRChange)
	defer closeTPM(t, tpm)

	for _, data := range []struct {
		desc string
		pcr  int
	}{
		{
			desc: "16",
			pcr:  16,
		},
		{
			desc: "23",
			pcr:  23,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			pcr := tpm.PCRHandleContext(data.pcr)
			if _, err := tpm.PCREvent(pcr, []byte("foo"), nil); err != nil {
				t.Fatalf("PCREvent failed: %v", err)
			}
			zeroDigest := make(Digest, HashAlgorithmSHA256.Size())
			selection := PCRSelectionList{{Hash: HashAlgorithmSHA256, Select: []int{data.pcr}}}
			_, v, err := tpm.PCRRead(selection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
			if bytes.Equal(zeroDigest, v[HashAlgorithmSHA256][data.pcr]) {
				t.Fatalf("PCR has unexpected initial value")
			}

			if err := tpm.PCRReset(pcr, nil); err != nil {
				t.Errorf("PCRReset failed: %v", err)
			}

			_, v, err = tpm.PCRRead(selection)
			if err != nil {
				t.Fatalf("PCRRead failed: %v", err)
			}
			if !bytes.Equal(zeroDigest, v[HashAlgorithmSHA256][data.pcr]) {
				t.Fatalf("PCR was not reset")
			}
		})
	}
}
