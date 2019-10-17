// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 25 - Dictionary Attack Functions

// DictionaryAttackLockReset executes the TPM2_DictionaryAttackLockReset command to cancel the effect of a TPM lockout. The lockHandle
// parameter must always be HandleLockout. The command requires the user auth role for lockHandle, provided via lockHandleAuth.
//
// On successful completion, the lockout counter will be reset to zero.
func (t *TPMContext) DictionaryAttackLockReset(lockHandle Handle, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackLockReset, nil,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth})
}

// DictionaryAttackParameters executes the TPM2_DictionaryAttackParameters command to change the dictionary attack lockout settings.
// The newMaxTries parameter sets the maximum value of the lockout counter before the TPM enters lockout mode. If it is set to zero,
// then the TPM will enter lockout mode and the use of dictionary attack protected entities will be disabled. The newRecoveryTime
// parameter specifies the amount of time in seconds it takes for the lockout counter to decrement by one. If it is set to zero, then
// dictionary attack protection is disabled. The lockoutRecovery parameter specifies the amount of time in seconds that the lockout
// hierarchy authorization cannot be used after an authorization failure. If it is set to zero, then the lockout hierarchy can be used
// again after a TPM reset, restart or resume. The newRecoveryTime and lockoutRecovery parameters are measured against powered on time
// rather than clock time.
//
// The lockHandle parameter must be HandleLockout. The command requires the user auth role for lockHandle, provided via
// lockHandleAuth.
func (t *TPMContext) DictionaryAttackParameters(lockHandle Handle, newMaxTries, newRecoveryTime, lockoutRecovery uint32, lockHandleAuth interface{}) error {
	return t.RunCommand(CommandDictionaryAttackParameters, nil,
		HandleWithAuth{Handle: lockHandle, Auth: lockHandleAuth}, Separator,
		newMaxTries, newRecoveryTime, lockoutRecovery)
}
