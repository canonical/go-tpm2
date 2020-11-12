// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

// Section 16 - Random Number Generator

func (t *TPMContext) GetRandom(bytesRequested uint16, sessions ...SessionContext) (randomBytes Digest, err error) {
	if err := t.RunCommand(CommandGetRandom, sessions,
		Delimiter,
		bytesRequested, Delimiter,
		Delimiter,
		&randomBytes); err != nil {
		return nil, err
	}

	return randomBytes, nil
}

func (t *TPMContext) StirRandom(inData SensitiveData, sessions ...SessionContext) error {
	return t.RunCommand(CommandStirRandom, sessions, Delimiter, inData)
}
