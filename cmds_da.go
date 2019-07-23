// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) DictionaryAttackLockReset(lockHandle Handle, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackLockReset,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth})
}

func (t *tpmContext) DictionaryAttackParameters(lockHandle Handle, newMaxTries, newRecoveryTime,
	lockoutRecovery uint32, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackParameters,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth}, Separator, newMaxTries, newRecoveryTime,
		lockoutRecovery)
}
