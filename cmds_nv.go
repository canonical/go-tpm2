package tpm2

func (t *tpmImpl) nvReadPublic(nvIndex Handle) (*NVPublic, Name, error) {
	var nvPublic NVPublic
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, nvIndex, Separator, Separator, Separator, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return &nvPublic, nvName, nil
}

func (t *tpmImpl) NVReadPublic(nvIndex ResourceContext) (*NVPublic, Name, error) {
	if err := t.checkResourceContextParam(nvIndex, "nvIndex"); err != nil {
		return nil, nil, err
	}
	return t.nvReadPublic(nvIndex.Handle())
}
