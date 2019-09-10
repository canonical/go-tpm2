// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 29 - Clocks and Timers

func (t *TPMContext) ReadClock(sessions ...*Session) (*TimeInfo, error) {
	var currentTime TimeInfo
	if err := t.RunCommand(CommandReadClock, sessions); err != nil {
		return nil, err
	}
	return &currentTime, nil
}

// func (t *TPMContext) ClockSet(auth Handle, newTime uint64, authAuth interface{}) error {
// }

// func (t *TPMContext) ClockRateAdjust(auth Handle, rateAdjust ClockAdjust, authAuth interface{}) error {
// }
