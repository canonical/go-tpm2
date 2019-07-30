// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) PCRExtend(pcrHandle Handle, digests TaggedHashList, pcrHandleAuth interface{}) error {
	return t.RunCommand(CommandPCRExtend, HandleWithAuth{Handle: pcrHandle, Auth: pcrHandleAuth},
		Separator, digests)
}

func (t *tpmContext) PCREvent(pcrHandle Handle, eventData Event, pcrHandleAuth interface{},
	sessions ...*Session) (TaggedHashList, error) {
	var digests TaggedHashList
	if err := t.RunCommand(CommandPCREvent, HandleWithAuth{Handle: pcrHandle, Auth: pcrHandleAuth},
		Separator, eventData, Separator, Separator, &digests, Separator, sessions); err != nil {
		return nil, err
	}
	return digests, nil
}

func (t *tpmContext) PCRRead(pcrSelectionIn PCRSelectionList) (uint32, PCRSelectionList, DigestList, error) {
	var pcrUpdateCounter uint32
	var pcrSelectionOut PCRSelectionList
	var pcrValues DigestList

	if err := t.RunCommand(CommandPCRRead, Separator, pcrSelectionIn, Separator, Separator, &pcrUpdateCounter,
		&pcrSelectionOut, &pcrValues); err != nil {
		return 0, nil, nil, err
	}

	return pcrUpdateCounter, pcrSelectionOut, pcrValues, nil
}
