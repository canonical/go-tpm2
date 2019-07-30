// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

func (t *tpmContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic NVPublic2B
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName, Separator, sessions); err != nil {
		return nil, nil, err
	}
	return (*NVPublic)(&nvPublic), nvName, nil
}

func (t *tpmContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex, "nvIndex"); err != nil {
		return nil, nil, err
	}
	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}
