package tpm2

func (t *tpmImpl) FlushContext(flushHandle Resource) error {
	if flushHandle == nil {
		return InvalidParamError{"nil flushHandle"}
	}
	if err := t.checkResourceParam(flushHandle); err != nil {
		return err
	}

	return t.RunCommand(CommandFlushContext, Format{0, 1}, Format{0, 0}, flushHandle.Handle())
}

func (t *tpmImpl) EvictControl(auth Handle, objectHandle Resource, persistentHandle Handle,
	session interface{}) (Resource, error) {
	if objectHandle == nil {
		return nil, InvalidParamError{"nil objectHandle"}
	}
	if err := t.checkResourceParam(objectHandle); err != nil {
		return nil, err
	}

	if err := t.RunCommand(CommandEvictControl, Format{2, 1}, Format{0, 0}, auth, objectHandle.Handle(),
		persistentHandle, session); err != nil {
		return nil, err
	}

	if objectHandle.Handle() == persistentHandle {
		t.evictResource(objectHandle)
		return nil, nil
	}
	return t.WrapHandle(persistentHandle)
}
