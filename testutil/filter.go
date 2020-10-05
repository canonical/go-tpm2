// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

func commandMayModifyPersistentStorage(command tpm2.CommandCode) bool {
	switch command {
	case tpm2.CommandNVUndefineSpaceSpecial, tpm2.CommandNVUndefineSpace, tpm2.CommandNVDefineSpace, tpm2.CommandNVGlobalWriteLock,
		tpm2.CommandNVIncrement, tpm2.CommandNVSetBits, tpm2.CommandNVExtend, tpm2.CommandNVWrite, tpm2.CommandNVWriteLock,
		tpm2.CommandNVChangeAuth:
		return true
	case tpm2.CommandEvictControl:
		return true
	case tpm2.CommandClear:
		return true
	default:
		return false
	}
}

func commandMayMakeStClearChange(command tpm2.CommandCode) bool {
	switch command {
	case tpm2.CommandNVReadLock:
		return true
	default:
		return false
	}
}

var numberOfCommandAuthHandles = map[tpm2.CommandCode]int{
	tpm2.CommandNVUndefineSpaceSpecial:     2,
	tpm2.CommandEvictControl:               2,
	tpm2.CommandHierarchyControl:           1,
	tpm2.CommandNVUndefineSpace:            1, // 2 handles total
	tpm2.CommandClear:                      1,
	tpm2.CommandClearControl:               1,
	tpm2.CommandHierarchyChangeAuth:        1,
	tpm2.CommandNVDefineSpace:              1,
	tpm2.CommandCreatePrimary:              1,
	tpm2.CommandNVGlobalWriteLock:          1,
	tpm2.CommandGetCommandAuditDigest:      2,
	tpm2.CommandNVIncrement:                1, // 2 handles total
	tpm2.CommandNVSetBits:                  1, // 2 handles total
	tpm2.CommandNVExtend:                   1, // 2 handles total
	tpm2.CommandNVWrite:                    1, // 2 handles total
	tpm2.CommandNVWriteLock:                1, // 2 handles total
	tpm2.CommandDictionaryAttackLockReset:  1,
	tpm2.CommandDictionaryAttackParameters: 1,
	tpm2.CommandNVChangeAuth:               1,
	tpm2.CommandPCREvent:                   1,
	tpm2.CommandPCRReset:                   1,
	tpm2.CommandSequenceComplete:           1,
	tpm2.CommandSetCommandCodeAuditStatus:  1,
	tpm2.CommandIncrementalSelfTest:        0,
	tpm2.CommandSelfTest:                   0,
	tpm2.CommandStartup:                    0,
	tpm2.CommandShutdown:                   0,
	tpm2.CommandStirRandom:                 0,
	tpm2.CommandActivateCredential:         2,
	tpm2.CommandCertify:                    2,
	tpm2.CommandPolicyNV:                   1, // 3 handles total
	tpm2.CommandCertifyCreation:            1, // 2 handles total
	tpm2.CommandDuplicate:                  1, // 2 handles total
	tpm2.CommandGetTime:                    2,
	tpm2.CommandGetSessionAuditDigest:      2, // 3 handles total
	tpm2.CommandNVRead:                     1, // 2 handles total
	tpm2.CommandNVReadLock:                 1, // 2 handles total
	tpm2.CommandObjectChangeAuth:           1, // 2 handles total
	tpm2.CommandPolicySecret:               1, // 2 hanldes total
	tpm2.CommandCreate:                     1,
	tpm2.CommandImport:                     1,
	tpm2.CommandLoad:                       1,
	tpm2.CommandQuote:                      1,
	tpm2.CommandHMACStart:                  1,
	tpm2.CommandSequenceUpdate:             1,
	tpm2.CommandSign:                       1,
	tpm2.CommandUnseal:                     1,
	tpm2.CommandPolicySigned:               0, // 2 handles total
	tpm2.CommandContextLoad:                0,
	tpm2.CommandContextSave:                0, // 1 handle total
	tpm2.CommandFlushContext:               0,
	tpm2.CommandLoadExternal:               0,
	tpm2.CommandMakeCredential:             0, // 1 handle total
	tpm2.CommandNVReadPublic:               0, // 1 handle total
	tpm2.CommandPolicyAuthorize:            0, // 1 handle total
	tpm2.CommandPolicyAuthValue:            0, // 1 handle total
	tpm2.CommandPolicyCommandCode:          0, // 1 handle total
	tpm2.CommandPolicyCounterTimer:         0, // 1 handle total
	tpm2.CommandPolicyCpHash:               0, // 1 handle total
	tpm2.CommandPolicyNameHash:             0, // 1 handle total
	tpm2.CommandPolicyOR:                   0, // 1 handle total
	tpm2.CommandPolicyTicket:               0, // 1 handle total
	tpm2.CommandReadPublic:                 0, // 1 handle total
	tpm2.CommandStartAuthSession:           0, // 2 handles total
	tpm2.CommandVerifySignature:            0, // 1 handle total
	tpm2.CommandGetCapability:              0,
	tpm2.CommandGetRandom:                  0,
	tpm2.CommandGetTestResult:              0,
	tpm2.CommandPCRRead:                    0,
	tpm2.CommandPolicyPCR:                  0,
	tpm2.CommandPolicyRestart:              0, // 1 handle total
	tpm2.CommandReadClock:                  0,
	tpm2.CommandPCRExtend:                  1,
	tpm2.CommandEventSequenceComplete:      2,
	tpm2.CommandHashSequenceStart:          0,
	tpm2.CommandPolicyDuplicationSelect:    0, // 1 handle total
	tpm2.CommandPolicyGetDigest:            0, // 1 handle total
	tpm2.CommandTestParms:                  0,
	tpm2.CommandPolicyPassword:             0, // 1 handle total
	tpm2.CommandPolicyNvWritten:            0, // 1 handle total
	tpm2.CommandCreateLoaded:               1,
}

type commandHeader struct {
	Tag         tpm2.StructTag
	CommandSize uint32
	CommandCode tpm2.CommandCode
}

type tctiFilter struct {
	tcti              tpm2.TCTI
	requestedFeatures TPMFeatureFlags
}

func (t *tctiFilter) Read(data []byte) (int, error) {
	return t.tcti.Read(data)
}

func (t *tctiFilter) Write(data []byte) (int, error) {
	r := bytes.NewReader(data)

	var commandFeatures TPMFeatureFlags

	var h commandHeader
	if _, err := mu.UnmarshalFromReader(r, &h); err != nil {
		return 0, err
	}

	if commandMayModifyPersistentStorage(h.CommandCode) {
		commandFeatures |= TPMFeaturePersist
	}
	if commandMayMakeStClearChange(h.CommandCode) {
		commandFeatures |= TPMFeatureStClearChange
	}

	switch h.CommandCode {
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

	numHandles, ok := numberOfCommandAuthHandles[h.CommandCode]
	if !ok {
		return 0, errors.New("unsupported command")
	}

	for i := 0; i < numHandles; i++ {
		var h tpm2.Handle
		if _, err := mu.UnmarshalFromReader(r, &h); err != nil {
			return 0, err
		}
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

func (t *tctiFilter) Close() error {
	return t.tcti.Close()
}

func (t *tctiFilter) SetLocality(locality uint8) error {
	return t.tcti.SetLocality(locality)
}

func (t *tctiFilter) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return t.tcti.MakeSticky(handle, sticky)
}
