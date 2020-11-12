// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 22 - Integrity Collection (PCR)

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

// ToListAndSelection converts this set of PCR values to a list of PCR selections and list of PCR values, in a form that can be
// serialized.
func (v PCRValues) ToListAndSelection() (pcrs PCRSelectionList, digests DigestList) {
	pcrs = v.SelectionList()
	for _, p := range pcrs {
		for _, s := range p.Select {
			digests = append(digests, v[p.Hash][s])
		}
	}
	return
}

// SetValuesFromListAndSelection sets PCR values from the supplied list of PCR selections and list of values.
func (v PCRValues) SetValuesFromListAndSelection(pcrs PCRSelectionList, digests DigestList) (int, error) {
	i := 0
	for _, p := range pcrs {
		if !p.Hash.Supported() {
			return 0, errors.New("unsupported digest algorithm")
		}
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

// CreatePCRValuesFromListAndSelection constructs a new set of PCR values from the supplied list of PCR selections and list of
// PCR values.
func CreatePCRValuesFromListAndSelection(pcrs PCRSelectionList, digests DigestList) (PCRValues, int, error) {
	out := make(PCRValues)
	n, err := out.SetValuesFromListAndSelection(pcrs, digests)
	if err != nil {
		return nil, 0, err
	}
	return out, n, nil
}

// PCRExtend executes the TPM2_PCR_Extend command to extend the PCR associated with the pcrContext parameter with the tagged digests
// provided via the digests argument. If will iterate over the digests and extend the PCR with each one for the PCR bank associated
// with the algorithm for each digest.
//
// If pcrContext is nil, this function will do nothing. The command requires authorization with the user auth role for pcrContext,
// with session based authorization provided via pcrContextAuthSession.
//
// If the PCR associated with pcrContext can not be extended from the current locality, a *TPMError error with an error code of
// ErrorLocality will be returned.
func (t *TPMContext) PCRExtend(pcrContext ResourceContext, digests TaggedHashList, pcrContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.RunCommand(CommandPCRExtend, sessions,
		ResourceContextWithSession{Context: pcrContext, Session: pcrContextAuthSession}, Delimiter,
		digests)
}

// PCREvent executes the TPM2_PCR_Event command to extend the PCR associated with the pcrContext parameter with a digest of the
// provided eventData, hashed with the algorithm for each supported PCR bank.
//
// If pcrContext is nil, this function will do nothing. The command requires authorization with the user auth role for pcrContext,
// with session based authorization provided via pcrContextAuthSession.
//
// If the PCR associated with pcrContext can not be extended from the current locality, a *TPMError error with an error code of
// ErrorLocality will be returned.
//
// On success, this function will return a list of tagged digests that the PCR associated with pcrContext was extended with.
func (t *TPMContext) PCREvent(pcrContext ResourceContext, eventData Event, pcrContextAuthSession SessionContext, sessions ...SessionContext) (digests TaggedHashList, err error) {
	if err := t.RunCommand(CommandPCREvent, sessions,
		ResourceContextWithSession{Context: pcrContext, Session: pcrContextAuthSession}, Delimiter,
		eventData, Delimiter,
		Delimiter,
		&digests); err != nil {
		return nil, err
	}
	return digests, nil
}

// PCRRead executes the TPM2_PCR_Read command to return the values of the PCRs defined in the pcrSelectionIn parameter. The
// underlying command may not be able to read all of the specified PCRs in a single transaction, so this function will
// re-execute the TPM2_PCR_Read command until all requested values have been read. As a consequence, any SessionContext instances
// provided should have the AttrContinueSession attribute defined.
//
// On success, the current value of pcrUpdateCounter is returned, as well as the requested PCR values.
func (t *TPMContext) PCRRead(pcrSelectionIn PCRSelectionList, sessions ...SessionContext) (pcrUpdateCounter uint32, pcrValues PCRValues, err error) {
	var remaining PCRSelectionList
	for _, s := range pcrSelectionIn {
		c := PCRSelection{Hash: s.Hash, Select: make([]int, len(s.Select))}
		copy(c.Select, s.Select)
		remaining = append(remaining, c)
	}

	pcrValues = make(PCRValues)

	for i := 0; ; i++ {
		var updateCounter uint32
		var pcrSelectionOut PCRSelectionList
		var values DigestList

		if err := t.RunCommand(CommandPCRRead, sessions,
			Delimiter,
			remaining, Delimiter,
			Delimiter,
			&updateCounter, &pcrSelectionOut, &values); err != nil {
			return 0, nil, err
		}

		if i == 0 {
			pcrUpdateCounter = updateCounter
		} else if updateCounter != pcrUpdateCounter {
			return 0, nil, &InvalidResponseError{CommandPCRRead, "PCR update counter changed between commands"}
		} else if len(values) == 0 && pcrSelectionOut.IsEmpty() {
			return 0, nil, makeInvalidArgError("pcrSelectionIn", "unimplemented PCRs specified")
		}

		if n, err := pcrValues.SetValuesFromListAndSelection(pcrSelectionOut, values); err != nil {
			return 0, nil, &InvalidResponseError{CommandPCRRead, err.Error()}
		} else if n != len(values) {
			return 0, nil, &InvalidResponseError{CommandPCRRead, "too many digests"}
		}

		remaining = remaining.Remove(pcrSelectionOut)
		if remaining.IsEmpty() {
			break
		}
	}

	return pcrUpdateCounter, pcrValues, nil
}

// PCRReset executes the TPM2_PCR_Reset command to reset the PCR associated with pcrContext in all banks. This command requires
// authorization with the user auth role for pcrContext, with session based authorization provided via pcrContextAuthSession.
//
// If the PCR associated with pcrContext can not be reset from the current locality, a *TPMError error with an error code of
// ErrorLocality will be returned.
func (t *TPMContext) PCRReset(pcrContext ResourceContext, pcrContextAuthSession SessionContext, sessions ...SessionContext) error {
	return t.RunCommand(CommandPCRReset, sessions, ResourceContextWithSession{Context: pcrContext, Session: pcrContextAuthSession})
}
