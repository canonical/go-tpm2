package tpm2

func (t *tpmConnection) Startup(startupType StartupType) error {
	return t.RunCommand(CommandStartup, Separator, startupType)
}

func (t *tpmConnection) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, Separator, shutdownType)
}
