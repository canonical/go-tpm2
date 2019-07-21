package tpm2

func (t *tpmContext) Startup(startupType StartupType) error {
	return t.RunCommand(CommandStartup, Separator, startupType)
}

func (t *tpmContext) Shutdown(shutdownType StartupType) error {
	return t.RunCommand(CommandShutdown, Separator, shutdownType)
}
