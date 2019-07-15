package tpm2

func (t *tpmImpl) nvReadPublic(nvIndex Handle) (*NVPublic, Name, error) {
	var nvPublic NVPublic
	var nvName Name
	if err := t.RunCommand(CommandNVReadPublic, Format{1, 0}, Format{0, 2}, nvIndex, &nvPublic,
		&nvName); err != nil {
		return nil, nil, err
	}
	return &nvPublic, nvName, nil
}

func (t *tpmImpl) NVReadPublic(nvIndex ResourceContext) (*NVPublic, Name, error) {
	if nvIndex == nil {
		return nil, nil, InvalidParamError{"nil nvIndex"}
	}
	if err := t.checkResourceContextParam(nvIndex); err != nil {
		return nil, nil, err
	}
	return t.nvReadPublic(nvIndex.Handle())
}
