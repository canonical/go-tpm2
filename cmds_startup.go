package tpm2

func (t *tpmImpl) Startup(startupType StartupType) error {
	return t.RunCommand(CommandStartup, Separator, startupType)
}

func (t *tpmImpl) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, Separator, shutdownType)
}
