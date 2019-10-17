// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 22 - Integrity Collection (PCR)

import (
	"fmt"
	"sort"
)

func (l *PCRSelectionList) subtract(x PCRSelectionList) {
	for i, sl := range *l {
		for _, sx := range x {
			if sx.Hash != sl.Hash {
				continue
			}
			n := 0
		Loop:
			for _, sls := range sl.Select {
				for _, sxs := range sx.Select {
					if sxs == sls {
						continue Loop
					}
				}
				(*l)[i].Select[n] = sls
				n++
			}
			(*l)[i].Select = (*l)[i].Select[:n]
		}
	}
	n := 0
	for _, sl := range *l {
		if len(sl.Select) > 0 {
			(*l)[n] = sl
			n++
		}
	}
	*l = (*l)[:n]
}

func (t *TPMContext) PCRExtend(pcrHandle Handle, digests TaggedHashList, pcrHandleAuth interface{}) error {
	return t.RunCommand(CommandPCRExtend, nil,
		HandleWithAuth{Handle: pcrHandle, Auth: pcrHandleAuth}, Separator,
		digests)
}

func (t *TPMContext) PCREvent(pcrHandle Handle, eventData Event, pcrHandleAuth interface{},
	sessions ...*Session) (TaggedHashList, error) {
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

func (t *TPMContext) PCRRead(pcrSelectionIn PCRSelectionList) (uint32, DigestList, error) {
	var remaining PCRSelectionList
	for _, s := range pcrSelectionIn {
		c := PCRSelection{Hash: s.Hash}
		sort.Ints(s.Select)
		for _, i := range s.Select {
			c.Select = append(c.Select, i)
		}
		remaining = append(remaining, c)
	}

	var pcrUpdateCounter uint32
	var pcrValues DigestList

	for i := 0; ; i++ {
		var updateCounter uint32
		var pcrSelectionOut PCRSelectionList
		var values DigestList

		if err := t.RunCommand(CommandPCRRead, nil,
			Separator,
			remaining, Separator,
			Separator,
			&updateCounter, &pcrSelectionOut, &values); err != nil {
			return 0, nil, err
		}

		if i == 0 {
			pcrUpdateCounter = updateCounter
		} else if updateCounter != pcrUpdateCounter {
			return 0, nil, fmt.Errorf("TPM responded with the wrong pcrUpdateCounter value: got %d, expected %d",
				updateCounter, pcrUpdateCounter)
		}

		pcrValues = append(pcrValues, values...)

		remaining.subtract(pcrSelectionOut)
		if len(remaining) == 0 {
			break
		}
	}

	return pcrUpdateCounter, pcrValues, nil
}
