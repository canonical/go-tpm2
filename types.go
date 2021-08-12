// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"sort"
)

// PCRValues contains a collection of PCR values, keyed by HashAlgorithmId and PCR index.
type PCRValues map[HashAlgorithmId]map[int]Digest

// SelectionList computes a list of PCR selections corresponding to this set of PCR values.
func (v PCRValues) SelectionList() PCRSelectionList {
	var out PCRSelectionList
	for h := range v {
		s := PCRSelection{Hash: h}
		for p := range v[h] {
			s.Select = append(s.Select, p)
		}
		out = append(out, s)
	}
	return out.Sort()
}

// ToListAndSelection converts this set of PCR values to a list of PCR selections and list of PCR
// values, in a form that can be serialized.
func (v PCRValues) ToListAndSelection() (pcrs PCRSelectionList, digests DigestList) {
	pcrs = v.SelectionList()
	for _, p := range pcrs {
		for _, s := range p.Select {
			digests = append(digests, v[p.Hash][s])
		}
	}
	return
}

// SetValuesFromListAndSelection sets PCR values from the supplied list of PCR selections and list
// of values.
func (v PCRValues) SetValuesFromListAndSelection(pcrs PCRSelectionList, digests DigestList) (int, error) {
	i := 0
	for _, p := range pcrs {
		if _, ok := v[p.Hash]; !ok {
			v[p.Hash] = make(map[int]Digest)
		}
		sel := make([]int, len(p.Select))
		copy(sel, p.Select)
		sort.Ints(sel)
		for _, s := range sel {
			if len(digests) == 0 {
				return 0, errors.New("insufficient digests")
			}
			d := digests[0]
			digests = digests[1:]
			if len(d) != p.Hash.Size() {
				return 0, errors.New("incorrect digest size")
			}
			v[p.Hash][s] = d
			i++
		}
	}
	return i, nil
}

// SetValue sets the PCR value for the specified PCR and PCR bank.
func (v PCRValues) SetValue(alg HashAlgorithmId, pcr int, digest Digest) {
	if _, ok := v[alg]; !ok {
		v[alg] = make(map[int]Digest)
	}
	v[alg][pcr] = digest
}

// CreatePCRValuesFromListAndSelection constructs a new set of PCR values from the
// supplied list of PCR selections and list of PCR values.
func CreatePCRValuesFromListAndSelection(pcrs PCRSelectionList, digests DigestList) (PCRValues, int, error) {
	out := make(PCRValues)
	n, err := out.SetValuesFromListAndSelection(pcrs, digests)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// PublicTemplate exists to allow either Public or PublicDerived structures
// to be used as the template value for TPMContext.CreateLoaded.
type PublicTemplate interface {
	ToTemplate() (Template, error)
}
