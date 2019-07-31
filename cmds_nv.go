// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

func (t *tpmContext) nvReadPublic(nvIndex Handle, sessions ...*Session) (*NVPublic, Name, error) {
	var nvPublic NVPublic2B
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, sessions, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return (*NVPublic)(&nvPublic), nvName, nil
}

func (t *tpmContext) NVReadPublic(nvIndex ResourceContext, sessions ...*Session) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, fmt.Errorf("invalid resource context for nvIndex: %v", err)
	}

	return t.nvReadPublic(nvIndex.Handle(), sessions...)
}
