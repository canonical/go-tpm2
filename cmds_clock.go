// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) ReadClock(sessions ...*Session) (*TimeInfo, error) {
	var currentTime TimeInfo
	if err := t.RunCommand(CommandReadClock, sessions); err != nil {
		return nil, err
	}
	return &currentTime, nil
}
