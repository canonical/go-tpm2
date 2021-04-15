// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"

	"golang.org/x/xerrors"
)

type commandInfo struct {
	authHandles int
	cmdHandles  int

	// canModifyPersistentStorage indicates that the command can make
	// changes to data stored persistently in the device, such as persisting
	// or evicting objects, and definining, undefining, modifying NV objects.
	canModifyPersistentStorage bool

	// canMakeStClearChange indicates that the command can make changes
	// that persist until the next Startup(ST_CLEAR).
	canMakeStClearChange bool
}

var commandInfoMap = map[tpm2.CommandCode]commandInfo{
	tpm2.CommandNVUndefineSpaceSpecial:     commandInfo{2, 2, true, false},
	tpm2.CommandEvictControl:               commandInfo{2, 2, true, false},
	tpm2.CommandHierarchyControl:           commandInfo{1, 1, false, false},
	tpm2.CommandNVUndefineSpace:            commandInfo{1, 2, true, false},
	tpm2.CommandClear:                      commandInfo{1, 1, true, false},
	tpm2.CommandClearControl:               commandInfo{1, 1, false, false},
	tpm2.CommandHierarchyChangeAuth:        commandInfo{1, 1, false, false},
	tpm2.CommandNVDefineSpace:              commandInfo{1, 1, true, false},
	tpm2.CommandCreatePrimary:              commandInfo{1, 1, false, false},
	tpm2.CommandNVGlobalWriteLock:          commandInfo{1, 1, true, false},
	tpm2.CommandGetCommandAuditDigest:      commandInfo{2, 2, false, false},
	tpm2.CommandNVIncrement:                commandInfo{1, 2, true, false},
	tpm2.CommandNVSetBits:                  commandInfo{1, 2, true, false},
	tpm2.CommandNVExtend:                   commandInfo{1, 2, true, false},
	tpm2.CommandNVWrite:                    commandInfo{1, 2, true, false},
	tpm2.CommandNVWriteLock:                commandInfo{1, 2, true, false},
	tpm2.CommandDictionaryAttackLockReset:  commandInfo{1, 1, false, false},
	tpm2.CommandDictionaryAttackParameters: commandInfo{1, 1, false, false},
	tpm2.CommandNVChangeAuth:               commandInfo{1, 1, true, false},
	tpm2.CommandPCREvent:                   commandInfo{1, 1, false, false},
	tpm2.CommandPCRReset:                   commandInfo{1, 1, false, false},
	tpm2.CommandSequenceComplete:           commandInfo{1, 1, false, false},
	tpm2.CommandSetCommandCodeAuditStatus:  commandInfo{1, 1, false, false},
	tpm2.CommandIncrementalSelfTest:        commandInfo{0, 0, false, false},
	tpm2.CommandSelfTest:                   commandInfo{0, 0, false, false},
	tpm2.CommandStartup:                    commandInfo{0, 0, false, false},
	tpm2.CommandShutdown:                   commandInfo{0, 0, false, false},
	tpm2.CommandStirRandom:                 commandInfo{0, 0, false, false},
	tpm2.CommandActivateCredential:         commandInfo{2, 2, false, false},
	tpm2.CommandCertify:                    commandInfo{2, 2, false, false},
	tpm2.CommandPolicyNV:                   commandInfo{1, 3, false, false},
	tpm2.CommandCertifyCreation:            commandInfo{1, 2, false, false},
	tpm2.CommandDuplicate:                  commandInfo{1, 2, false, false},
	tpm2.CommandGetTime:                    commandInfo{2, 2, false, false},
	tpm2.CommandGetSessionAuditDigest:      commandInfo{2, 3, false, false},
	tpm2.CommandNVRead:                     commandInfo{1, 2, false, false},
	tpm2.CommandNVReadLock:                 commandInfo{1, 2, false, true},
	tpm2.CommandObjectChangeAuth:           commandInfo{1, 2, false, false},
	tpm2.CommandPolicySecret:               commandInfo{1, 2, false, false},
	tpm2.CommandCreate:                     commandInfo{1, 1, false, false},
	tpm2.CommandImport:                     commandInfo{1, 1, false, false},
	tpm2.CommandLoad:                       commandInfo{1, 1, false, false},
	tpm2.CommandQuote:                      commandInfo{1, 1, false, false},
	tpm2.CommandHMACStart:                  commandInfo{1, 1, false, false},
	tpm2.CommandSequenceUpdate:             commandInfo{1, 1, false, false},
	tpm2.CommandSign:                       commandInfo{1, 1, false, false},
	tpm2.CommandUnseal:                     commandInfo{1, 1, false, false},
	tpm2.CommandPolicySigned:               commandInfo{0, 2, false, false},
	tpm2.CommandContextLoad:                commandInfo{0, 0, false, false},
	tpm2.CommandContextSave:                commandInfo{0, 1, false, false},
	tpm2.CommandFlushContext:               commandInfo{0, 0, false, false},
	tpm2.CommandLoadExternal:               commandInfo{0, 0, false, false},
	tpm2.CommandMakeCredential:             commandInfo{0, 1, false, false},
	tpm2.CommandNVReadPublic:               commandInfo{0, 1, false, false},
	tpm2.CommandPolicyAuthorize:            commandInfo{0, 1, false, false},
	tpm2.CommandPolicyAuthValue:            commandInfo{0, 1, false, false},
	tpm2.CommandPolicyCommandCode:          commandInfo{0, 1, false, false},
	tpm2.CommandPolicyCounterTimer:         commandInfo{0, 1, false, false},
	tpm2.CommandPolicyCpHash:               commandInfo{0, 1, false, false},
	tpm2.CommandPolicyNameHash:             commandInfo{0, 1, false, false},
	tpm2.CommandPolicyOR:                   commandInfo{0, 1, false, false},
	tpm2.CommandPolicyTicket:               commandInfo{0, 1, false, false},
	tpm2.CommandReadPublic:                 commandInfo{0, 1, false, false},
	tpm2.CommandStartAuthSession:           commandInfo{0, 2, false, false},
	tpm2.CommandVerifySignature:            commandInfo{0, 1, false, false},
	tpm2.CommandGetCapability:              commandInfo{0, 0, false, false},
	tpm2.CommandGetRandom:                  commandInfo{0, 0, false, false},
	tpm2.CommandGetTestResult:              commandInfo{0, 0, false, false},
	tpm2.CommandPCRRead:                    commandInfo{0, 0, false, false},
	tpm2.CommandPolicyPCR:                  commandInfo{0, 0, false, false},
	tpm2.CommandPolicyRestart:              commandInfo{0, 1, false, false},
	tpm2.CommandReadClock:                  commandInfo{0, 0, false, false},
	tpm2.CommandPCRExtend:                  commandInfo{1, 1, false, false},
	tpm2.CommandEventSequenceComplete:      commandInfo{2, 2, false, false},
	tpm2.CommandHashSequenceStart:          commandInfo{0, 0, false, false},
	tpm2.CommandPolicyDuplicationSelect:    commandInfo{0, 1, false, false},
	tpm2.CommandPolicyGetDigest:            commandInfo{0, 1, false, false},
	tpm2.CommandTestParms:                  commandInfo{0, 0, false, false},
	tpm2.CommandPolicyPassword:             commandInfo{0, 1, false, false},
	tpm2.CommandPolicyNvWritten:            commandInfo{0, 1, false, false},
	tpm2.CommandCreateLoaded:               commandInfo{1, 1, false, false},
}

// TCTI is a special inteface used for testing, which wraps a real interface.
type TCTI struct {
	tcti              tpm2.TCTI
	requestedFeatures TPMFeatureFlags
}

func (t *TCTI) Read(data []byte) (int, error) {
	return t.tcti.Read(data)
}

func (t *TCTI) Write(data []byte) (int, error) {
	cmd := tpm2.CommandPacket(data)

	commandCode, err := cmd.GetCommandCode()
	if err != nil {
		return 0, xerrors.Errorf("cannot determine command code: %w", err)
	}

	cmdInfo, ok := commandInfoMap[commandCode]
	if !ok {
		return 0, errors.New("unsupported command")
	}

	handles, _, _, err := cmd.UnmarshalPayload(cmdInfo.cmdHandles)
	if err != nil {
		return 0, xerrors.Errorf("invalid command payload: %w", err)
	}

	var commandFeatures TPMFeatureFlags

	if cmdInfo.canModifyPersistentStorage {
		commandFeatures |= TPMFeaturePersist
	}
	if cmdInfo.canMakeStClearChange {
		commandFeatures |= TPMFeatureStClearChange
	}

	switch commandCode {
	case tpm2.CommandDictionaryAttackParameters:
		commandFeatures |= TPMFeatureDAParameters
	case tpm2.CommandHierarchyChangeAuth:
		commandFeatures |= TPMFeatureHierarchyChangeAuth
	case tpm2.CommandSetCommandCodeAuditStatus:
		commandFeatures |= TPMFeatureSetCommandCodeAuditStatus
	case tpm2.CommandClear:
		commandFeatures |= TPMFeatureClear
	case tpm2.CommandClearControl:
		commandFeatures |= TPMFeatureClearControl
	case tpm2.CommandShutdown:
		commandFeatures |= TPMFeatureShutdown
	case tpm2.CommandHierarchyControl:
		commandFeatures |= TPMFeatureHierarchyControl
	}

	for _, h := range handles {
		switch {
		case h == tpm2.HandleOwner:
			commandFeatures |= TPMFeatureOwnerHierarchy
		case h == tpm2.HandleLockout:
			commandFeatures |= TPMFeatureLockoutHierarchy
		case h == tpm2.HandleEndorsement:
			commandFeatures |= TPMFeatureEndorsementHierarchy
		case h == tpm2.HandlePlatform || h == tpm2.HandlePlatformNV:
			commandFeatures |= TPMFeaturePlatformHierarchy
		case h.Type() == tpm2.HandleTypePCR:
			commandFeatures |= TPMFeaturePCR
		}
	}

	if ^t.requestedFeatures&commandFeatures != 0 {
		return 0, fmt.Errorf("command is trying to use a non-requested feature (permitted: 0x%08x, required: 0x%08x)", t.requestedFeatures, commandFeatures)
	}

	return t.tcti.Write(data)
}

func (t *TCTI) Close() error {
	return t.tcti.Close()
}

func (t *TCTI) SetLocality(locality uint8) error {
	return t.tcti.SetLocality(locality)
}

func (t *TCTI) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return t.tcti.MakeSticky(handle, sticky)
}

// Unwrap returns the real interface that this one wraps.
func (t *TCTI) Unwrap() tpm2.TCTI {
	return t.tcti
}
