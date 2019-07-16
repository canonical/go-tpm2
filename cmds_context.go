package tpm2

func (t *tpmImpl) FlushContext(flushHandle ResourceContext) error {
	if flushHandle == nil {
		return InvalidParamError{"nil flushHandle"}
	}
	if err := t.checkResourceContextParam(flushHandle); err != nil {
		return err
	}

	if err := t.RunCommand(CommandFlushContext, Separator, flushHandle.Handle()); err != nil {
		return err
	}

	t.evictResourceContext(flushHandle)
	return nil
}

func (t *tpmImpl) EvictControl(auth Handle, objectHandle ResourceContext, persistentHandle Handle,
	authAuth interface{}) (ResourceContext, error) {
	if objectHandle == nil {
		return nil, InvalidParamError{"nil objectHandle"}
	}
	if err := t.checkResourceContextParam(objectHandle); err != nil {
		return nil, err
	}

	if err := t.RunCommand(CommandEvictControl, HandleWithAuth{Handle: auth, Auth: authAuth},
		objectHandle, Separator, persistentHandle); err != nil {
		return nil, err
	}

	if objectHandle.Handle() == persistentHandle {
		t.evictResourceContext(objectHandle)
		return nil, nil
	}
	return t.WrapHandle(persistentHandle)
}
