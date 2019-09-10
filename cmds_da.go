// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 25 - Dictionary Attack Functions

func (t *TPMContext) DictionaryAttackLockReset(lockHandle Handle, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackLockReset, nil,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth})
}

func (t *TPMContext) DictionaryAttackParameters(lockHandle Handle, newMaxTries, newRecoveryTime,
	lockoutRecovery uint32, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackParameters, nil,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth}, Separator, newMaxTries, newRecoveryTime,
		lockoutRecovery)
}
