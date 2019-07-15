package tpm2

func (t *tpmImpl) Startup(startupType StartupType) error {
	return t.RunCommand(CommandStartup, Format{0, 1}, Format{0, 0}, startupType)
}

func (t *tpmImpl) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, Format{0, 1}, Format{0, 0}, shutdownType)
}
