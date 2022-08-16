// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 16 - Random Number Generator

// GetRandomRaw executes the TPM2_GetRandom command to return the next bytesRequested number of bytes from the TPM's
// random number generator.
func (t *TPMContext) GetRandomRaw(bytesRequested uint16, sessions ...SessionContext) (randomBytes Digest, err error) {
	if err := t.StartCommand(CommandGetRandom).
		AddParams(bytesRequested).
		AddExtraSessions(sessions...).
		Run(nil, &randomBytes); err != nil {
		return nil, err
	}
	return randomBytes, nil
}

// GetRandom executes the TPM2_GetRandom command to return the next bytesRequested number of bytes from the TPM's
// random number generator. If the requested bytes cannot be read in a single command, this function will reexecute
// the TPM2_GetRandom command until all requested bytes have been read.
func (t *TPMContext) GetRandom(bytesRequested uint16, sessions ...SessionContext) (randomBytes []byte, err error) {
	if err := t.initPropertiesIfNeeded(); err != nil {
		return nil, err
	}

	return readMultipleHelper(bytesRequested, t.maxDigestSize, func(sz, _ uint16, sessions ...SessionContext) ([]byte, error) {
		return t.GetRandomRaw(sz, sessions...)
	}, sessions...)
}

func (t *TPMContext) StirRandom(inData SensitiveData, sessions ...SessionContext) error {
	return t.StartCommand(CommandStirRandom).
		AddParams(inData).
		AddExtraSessions(sessions...).
		Run(nil)
}
