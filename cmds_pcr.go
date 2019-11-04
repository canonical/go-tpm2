// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 22 - Integrity Collection (PCR)

import (
	"errors"
	"fmt"
)

// PCRValues contains a collection of PCR values, keyed by AlgorithmId and PCR index.
type PCRValues map[HashAlgorithmId]map[int]Digest

// EnsureBank initializes a map of PCR indices to PCR values for the specified algorithm if one doesn't exist already.
func (v PCRValues) EnsureBank(alg HashAlgorithmId) {
	if _, ok := v[alg]; !ok {
		v[alg] = make(map[int]Digest)
	}
}

func (l PCRSelectionList) subtract(r PCRSelectionList) (PCRSelectionList, error) {
	if len(l) != len(r) {
		return nil, errors.New("incorrect number of PCRSelections")
	}

	var o PCRSelectionList
	for i, sl := range l {
		if r[i].Hash != sl.Hash {
			return nil, errors.New("PCRSelection has unexpected algorithm")
		}
		so := PCRSelection{Hash: sl.Hash}
	Loop:
		for _, sli := range sl.Select {
			for _, sri := range r[i].Select {
				if sri == sli {
					continue Loop
				}
			}
			so.Select = append(so.Select, sli)
		}
		o = append(o, so)
	}

	return o, nil
}

func (l PCRSelectionList) empty() bool {
	for _, s := range l {
		if len(s.Select) > 0 {
			return false
		}
	}
	return true
}

// PCRExtend executes the TPM2_PCR_Extend command to extend the PCR associated with the pcrHandle parameter with the tagged digests
// provided via the digests argument. If will iterate over the digests and extend the PCR with each one for the PCR bank associated
// with the algorithm for each digest.
//
// If pcrHandle is HandleNull, this function will do nothing. The command requires authorization with the user auth role for
// pcrHandle, provided via pcrHandleAuth.
//
// If the PCR associated with pcrHandle can not be extended from the current locality, a *TPMError error with an error code of
// ErrorLocality will be returned.
func (t *TPMContext) PCRExtend(pcrHandle Handle, digests TaggedHashList, pcrHandleAuth interface{}, sessions ...*Session) error {
	return t.RunCommand(CommandPCRExtend, sessions,
		HandleWithAuth{Handle: pcrHandle, Auth: pcrHandleAuth}, Separator,
		digests)
}

// PCREvent executes the TPM2_PCR_Event command to extend the PCR associated with the pcrHandle parameter with a digest of the
// provided eventData, hashed with the algorithm for each supported PCR bank.
//
// If pcrHandle is HandleNull, this function will do nothing. The command requires authorization with the user auth role for
// pcrHandle, provided via pcrHandleAuth.
//
// If the PCR associated with pcrHandle can not be extended from the current locality, a *TPMError error with an error code of
// ErrorLocality will be returned.
//
// On success, this function will return a list of tagged digests that the PCR associated with pcrHandle was extended with.
func (t *TPMContext) PCREvent(pcrHandle Handle, eventData Event, pcrHandleAuth interface{}, sessions ...*Session) (TaggedHashList, error) {
	var digests TaggedHashList
	if err := t.RunCommand(CommandPCREvent, sessions,
		HandleWithAuth{Handle: pcrHandle, Auth: pcrHandleAuth}, Separator,
		eventData, Separator,
		Separator,
		&digests); err != nil {
		return nil, err
	}
	return digests, nil
}

// PCRRead executes the TPM2_PCR_Read command to return the values of the PCRs defined in the pcrSelectionIn parameter. The
// underlying command may not be able to read all of the specified PCRs in a single transaction, so this function will
// re-execute the TPM2_PCR_Read command until all requested values have been read. As a consequence, any *Session instances
// provided should have the AttrContinueSession attribute defined.
//
// On success, the current value of pcrUpdateCounter is returned, as well as the requested PCR values.
func (t *TPMContext) PCRRead(pcrSelectionIn PCRSelectionList, sessions ...*Session) (uint32, PCRValues, error) {
	var remaining PCRSelectionList
	for _, s := range pcrSelectionIn {
		c := PCRSelection{Hash: s.Hash, Select: make([]int, len(s.Select))}
		copy(c.Select, s.Select)
		remaining = append(remaining, c)
	}

	var pcrUpdateCounter uint32
	pcrValues := make(PCRValues)

	for i := 0; ; i++ {
		var updateCounter uint32
		var pcrSelectionOut PCRSelectionList
		var values DigestList

		if err := t.RunCommand(CommandPCRRead, sessions,
			Separator,
			remaining, Separator,
			Separator,
			&updateCounter, &pcrSelectionOut, &values); err != nil {
			return 0, nil, err
		}

		if i == 0 {
			pcrUpdateCounter = updateCounter
		} else if updateCounter != pcrUpdateCounter {
			return 0, nil, &InvalidResponseError{CommandPCRRead, fmt.Sprintf("TPM responded with the wrong pcrUpdateCounter value: got %d, "+
				"expected %d", updateCounter, pcrUpdateCounter)}
		}

		if len(values) == 0 {
			if !pcrSelectionOut.empty() {
				return 0, nil, makeInvalidParamError("pcrSelectionIn", "unimplemented PCRs specified")
			}
			break
		}

		for _, s := range pcrSelectionOut {
			pcrValues.EnsureBank(s.Hash)
			for _, i := range s.Select {
				if len(values) == 0 {
					return 0, nil, &InvalidResponseError{CommandPCRRead, "TPM didn't return enough digests"}
				}
				if _, exists := pcrValues[s.Hash][i]; exists {
					return 0, nil, &InvalidResponseError{CommandPCRRead, "TPM responded with an unexpected PCR digest"}
				}
				pcrValues[s.Hash][i] = values[0]
				values = values[1:]
			}
		}
		if len(values) > 0 {
			return 0, nil, &InvalidResponseError{CommandPCRRead, "TPM returned too many digests"}
		}

		var err error
		remaining, err = remaining.subtract(pcrSelectionOut)
		if err != nil {
			return 0, nil, &InvalidResponseError{CommandPCRRead, fmt.Sprintf("cannot determine outstanding PCR selection from selection returned "+
				"from TPM: %v", err)}
		}
		if remaining.empty() {
			break
		}
	}

	return pcrUpdateCounter, pcrValues, nil
}
