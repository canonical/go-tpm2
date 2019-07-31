// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) GetRandom(bytesRequested uint16, sessions ...*Session) (Digest, error) {
	var randomBytes Digest
	if err := t.RunCommand(CommandGetRandom, sessions, Separator, bytesRequested, Separator, Separator,
		&randomBytes); err != nil {
		return nil, err
	}

	return randomBytes, nil
}

func (t *tpmContext) StirRandom(inData SensitiveData, sessions ...*Session) error {
	return t.RunCommand(CommandStirRandom, sessions, Separator, inData)
}
