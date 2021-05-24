// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

func canonicalizeHandle(h tpm2.Handle) tpm2.Handle {
	if h.Type() != tpm2.HandleTypePolicySession {
		return h
	}
	return (h & 0xffffff) | (tpm2.Handle(tpm2.HandleTypeHMACSession) << 24)
}

type commandInfo struct {
	authHandles int
	cmdHandles  int
	rspHandle   bool

	nv bool
}

var commandInfoMap = map[tpm2.CommandCode]commandInfo{
	tpm2.CommandNVUndefineSpaceSpecial:     commandInfo{2, 2, false, true},
	tpm2.CommandEvictControl:               commandInfo{2, 2, false, true},
	tpm2.CommandHierarchyControl:           commandInfo{1, 1, false, true},
	tpm2.CommandNVUndefineSpace:            commandInfo{1, 2, false, true},
	tpm2.CommandClear:                      commandInfo{1, 1, false, true},
	tpm2.CommandClearControl:               commandInfo{1, 1, false, true},
	tpm2.CommandHierarchyChangeAuth:        commandInfo{1, 1, false, true},
	tpm2.CommandNVDefineSpace:              commandInfo{1, 1, false, true},
	tpm2.CommandCreatePrimary:              commandInfo{1, 1, true, false},
	tpm2.CommandNVGlobalWriteLock:          commandInfo{1, 1, false, true},
	tpm2.CommandGetCommandAuditDigest:      commandInfo{2, 2, false, true},
	tpm2.CommandNVIncrement:                commandInfo{1, 2, false, true},
	tpm2.CommandNVSetBits:                  commandInfo{1, 2, false, true},
	tpm2.CommandNVExtend:                   commandInfo{1, 2, false, true},
	tpm2.CommandNVWrite:                    commandInfo{1, 2, false, true},
	tpm2.CommandNVWriteLock:                commandInfo{1, 2, false, true},
	tpm2.CommandDictionaryAttackLockReset:  commandInfo{1, 1, false, true},
	tpm2.CommandDictionaryAttackParameters: commandInfo{1, 1, false, true},
	tpm2.CommandNVChangeAuth:               commandInfo{1, 1, false, true},
	tpm2.CommandPCREvent:                   commandInfo{1, 1, false, true},
	tpm2.CommandPCRReset:                   commandInfo{1, 1, false, true},
	tpm2.CommandSequenceComplete:           commandInfo{1, 1, false, false},
	tpm2.CommandSetCommandCodeAuditStatus:  commandInfo{1, 1, false, true},
	tpm2.CommandIncrementalSelfTest:        commandInfo{0, 0, false, true},
	tpm2.CommandSelfTest:                   commandInfo{0, 0, false, true},
	tpm2.CommandStartup:                    commandInfo{0, 0, false, true},
	tpm2.CommandShutdown:                   commandInfo{0, 0, false, true},
	tpm2.CommandStirRandom:                 commandInfo{0, 0, false, true},
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
	tpm2.CommandLoad:                       commandInfo{1, 1, true, false},
	tpm2.CommandQuote:                      commandInfo{1, 1, false, false},
	tpm2.CommandHMACStart:                  commandInfo{1, 1, true, false},
	tpm2.CommandSequenceUpdate:             commandInfo{1, 1, false, false},
	tpm2.CommandSign:                       commandInfo{1, 1, false, false},
	tpm2.CommandUnseal:                     commandInfo{1, 1, false, false},
	tpm2.CommandPolicySigned:               commandInfo{0, 2, false, false},
	tpm2.CommandContextLoad:                commandInfo{0, 0, true, false},
	tpm2.CommandContextSave:                commandInfo{0, 1, false, false},
	tpm2.CommandFlushContext:               commandInfo{0, 0, false, false},
	tpm2.CommandLoadExternal:               commandInfo{0, 0, true, false},
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
	tpm2.CommandStartAuthSession:           commandInfo{0, 2, true, false},
	tpm2.CommandVerifySignature:            commandInfo{0, 1, false, false},
	tpm2.CommandGetCapability:              commandInfo{0, 0, false, false},
	tpm2.CommandGetRandom:                  commandInfo{0, 0, false, false},
	tpm2.CommandGetTestResult:              commandInfo{0, 0, false, false},
	tpm2.CommandPCRRead:                    commandInfo{0, 0, false, false},
	tpm2.CommandPolicyPCR:                  commandInfo{0, 0, false, false},
	tpm2.CommandPolicyRestart:              commandInfo{0, 1, false, false},
	tpm2.CommandReadClock:                  commandInfo{0, 0, false, false},
	tpm2.CommandPCRExtend:                  commandInfo{1, 1, false, true},
	tpm2.CommandEventSequenceComplete:      commandInfo{2, 2, false, true},
	tpm2.CommandHashSequenceStart:          commandInfo{0, 0, true, false},
	tpm2.CommandPolicyDuplicationSelect:    commandInfo{0, 1, false, false},
	tpm2.CommandPolicyGetDigest:            commandInfo{0, 1, false, false},
	tpm2.CommandTestParms:                  commandInfo{0, 0, false, false},
	tpm2.CommandPolicyPassword:             commandInfo{0, 1, false, false},
	tpm2.CommandPolicyNvWritten:            commandInfo{0, 1, false, false},
	tpm2.CommandCreateLoaded:               commandInfo{1, 1, true, false},
}

type objectInfo struct {
	attrs tpm2.ObjectAttributes
}

type persistentObjectInfo struct {
	objectInfo
	auth tpm2.Handle
}

type sessionInfo struct{}

type nvIndexInfo struct {
	auth  tpm2.Handle
	attrs tpm2.NVAttributes
}

type savedObject struct {
	data tpm2.ContextData
	info objectInfo
}

type daParams struct {
	maxTries        uint32
	recoveryTime    uint32
	lockoutRecovery uint32
}

type cmdContext struct {
	command  tpm2.CommandCode
	handles  tpm2.HandleList
	authArea []tpm2.AuthCommand
	params   []byte

	response *bytes.Buffer
}

var savedObjects []savedObject

// TCTI is a special proxy inteface used for testing, which wraps a real interface.
// It tracks changes to the TPM state and restores it when the connection is closed,
// and also performs some permission checks to ensure that a test does not access
// functionality that it has not requested to use.
type TCTI struct {
	tcti              tpm2.TCTI
	permittedFeatures TPMFeatureFlags

	restorePermanentAttrs tpm2.PermanentAttributes
	restoreStClearAttrs   tpm2.StartupClearAttributes
	restoreDaParams       daParams

	currentCmd *cmdContext

	hierarchyAuths    map[tpm2.Handle]tpm2.Auth
	transientObjects  map[tpm2.Handle]objectInfo
	persistentObjects map[tpm2.Handle]persistentObjectInfo
	sessions          map[tpm2.Handle]sessionInfo
	nvIndexes         map[tpm2.Handle]nvIndexInfo

	didClearControl             bool
	didHierarchyControl         bool
	didDisablePlatformHierarchy bool
	didSetDaParams              bool
}

func (t *TCTI) processCommandDone() error {
	defer func() {
		t.currentCmd = nil
	}()

	cmdInfo := commandInfoMap[t.currentCmd.command]

	var handle tpm2.Handle
	var pHandle *tpm2.Handle

	// Unpack the response packet
	if cmdInfo.rspHandle {
		pHandle = &handle
	}
	resp := tpm2.ResponsePacket(t.currentCmd.response.Bytes())
	rc, pBytes, _, err := resp.Unmarshal(pHandle)
	if err != nil {
		return xerrors.Errorf("cannot unmarshal response: %w", err)
	}
	if rc != tpm2.Success {
		return nil
	}

	// Record new transient objects or sessions
	switch handle.Type() {
	case tpm2.HandleTypeHMACSession, tpm2.HandleTypePolicySession:
		handle = canonicalizeHandle(handle)
		t.sessions[canonicalizeHandle(handle)] = sessionInfo{}
	case tpm2.HandleTypeTransient:
		var attrs tpm2.ObjectAttributes

		switch t.currentCmd.command {
		case tpm2.CommandCreatePrimary:
			var inSensitive []byte
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &inSensitive, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			attrs = inPublic.Ptr.Attrs
		case tpm2.CommandLoad:
			var inPrivate tpm2.Private
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &inPrivate, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			attrs = inPublic.Ptr.Attrs
		case tpm2.CommandHMACStart:
			attrs = tpm2.AttrNoDA
		case tpm2.CommandContextLoad:
			var context tpm2.Context
			if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &context); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			for _, s := range savedObjects {
				if bytes.Equal(s.data, context.Blob) {
					attrs = s.info.attrs
					break
				}
			}
		case tpm2.CommandLoadExternal:
			var inPrivate []byte
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &inPrivate, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			attrs = inPublic.Ptr.Attrs
		case tpm2.CommandHashSequenceStart:
			attrs = tpm2.AttrNoDA
		case tpm2.CommandCreateLoaded:
			return errors.New("not supported yet")
		}

		t.transientObjects[handle] = objectInfo{attrs: attrs}
	}

	// Command specific updates
	switch t.currentCmd.command {
	case tpm2.CommandNVUndefineSpaceSpecial:
		// Drop undefined NV index
		delete(t.nvIndexes, t.currentCmd.handles[0])
	case tpm2.CommandEvictControl:
		auth := t.currentCmd.handles[0]
		object := t.currentCmd.handles[1]
		var persistent tpm2.Handle
		if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &persistent); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		switch object.Type() {
		case tpm2.HandleTypeTransient:
			// Record newly persisted object
			info, ok := t.transientObjects[object]
			if !ok {
				fmt.Fprintf(os.Stderr, "New persistent object %v was created from transient object %v which was not created by this test. Cannot determine object attributes\n", persistent, object)
			}
			t.persistentObjects[persistent] = persistentObjectInfo{objectInfo: info, auth: auth}
		case tpm2.HandleTypePersistent:
			// Drop evicted object
			delete(t.persistentObjects, persistent)
		default:
			panic("invalid handle type")
		}
	case tpm2.CommandHierarchyControl:
		t.didHierarchyControl = true

		var enable tpm2.Handle
		var state bool
		if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &enable, &state); err != nil {
			return xerrors.Errorf("cannot unmarshal params: %w", err)
		}

		if enable == tpm2.HandlePlatform && !state {
			t.didDisablePlatformHierarchy = true
		}
	case tpm2.CommandNVUndefineSpace:
		// Drop undefined NV index
		delete(t.nvIndexes, t.currentCmd.handles[1])
	case tpm2.CommandClear:
		delete(t.hierarchyAuths, tpm2.HandleOwner)
		delete(t.hierarchyAuths, tpm2.HandleEndorsement)
		delete(t.hierarchyAuths, tpm2.HandleLockout)

		for h, p := range t.persistentObjects {
			if p.auth == tpm2.HandleOwner {
				delete(t.persistentObjects, h)
			}
		}
		for h, n := range t.nvIndexes {
			if n.auth == tpm2.HandleOwner {
				delete(t.nvIndexes, h)
			}
		}

		t.didSetDaParams = false
	case tpm2.CommandClearControl:
		t.didClearControl = true
	case tpm2.CommandHierarchyChangeAuth:
		var newAuth tpm2.Auth
		// We can only restore this if the change was made without AttrCommandEncrypt. If the
		// command is encrypted, then the test needs to manually restore. Note that the
		// auth value was changed though so that the test harness will fail if it's not restored
		// manually.
		if t.currentCmd.authArea[0].SessionAttributes&tpm2.AttrCommandEncrypt == 0 {
			if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &newAuth); err != nil {
				return xerrors.Errorf("cannot unmarshal parameters: %w", err)
			}
		}
		t.hierarchyAuths[t.currentCmd.handles[0]] = newAuth
	case tpm2.CommandNVDefineSpace:
		// Record newly defined NV index
		var auth tpm2.Auth
		var nvPublic struct {
			Ptr *tpm2.NVPublic `tpm2:"sized"`
		}
		if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &auth, &nvPublic); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		index := nvPublic.Ptr.Index
		authHandle := t.currentCmd.handles[0]
		attrs := nvPublic.Ptr.Attrs
		t.nvIndexes[index] = nvIndexInfo{auth: authHandle, attrs: attrs}
	case tpm2.CommandDictionaryAttackParameters:
		t.didSetDaParams = true
	case tpm2.CommandStartup:
		t.didDisablePlatformHierarchy = false
		var startupType tpm2.StartupType
		if _, err := mu.UnmarshalFromBytes(t.currentCmd.params, &startupType); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		if startupType != tpm2.StartupState {
			delete(t.hierarchyAuths, tpm2.HandlePlatform)
			t.didHierarchyControl = false
		}
	case tpm2.CommandContextSave:
		handle := t.currentCmd.handles[0]
		switch handle.Type() {
		case tpm2.HandleTypeHMACSession, tpm2.HandleTypePolicySession:
		case tpm2.HandleTypeTransient:
			var context tpm2.Context
			if _, err := mu.UnmarshalFromBytes(pBytes, &context); err != nil {
				return xerrors.Errorf("cannot unmarshal response parameters: %w", err)
			}
			info, _ := t.transientObjects[handle]
			savedObjects = append(savedObjects, savedObject{info: info, data: context.Blob})
		default:
			panic("invalid handle type")
		}
	}

	return nil
}

func (t *TCTI) Read(data []byte) (int, error) {
	r := io.TeeReader(t.tcti, t.currentCmd.response)
	n, err := r.Read(data)

	if err == io.EOF {
		if err := t.processCommandDone(); err != nil {
			return n, err
		}
	}

	return n, err
}

func (t *TCTI) isDAExcempt(handle tpm2.Handle) bool {
	switch handle.Type() {
	case tpm2.HandleTypePCR:
		return true
	case tpm2.HandleTypeNVIndex:
		n, ok := t.nvIndexes[handle]
		if !ok {
			// This is an index not created by the test. Assume not excempt.
			fmt.Fprintf(os.Stderr, "Authorizing with NV index %v not created by this test - cannot determine if DA excempt\n", handle)
			return false
		}
		return n.attrs&tpm2.AttrNVNoDA > 0
	case tpm2.HandleTypePermanent:
		if handle == tpm2.HandleLockout {
			return false
		}
		return true
	case tpm2.HandleTypeTransient:
		o, ok := t.transientObjects[handle]
		if !ok {
			// This is an object not created by the test. Assume not excempt.
			fmt.Fprintf(os.Stderr, "Authorizing with object %v not created by this test - cannot determine if DA excempt\n", handle)
			return false
		}
		return o.attrs&tpm2.AttrNoDA > 0
	case tpm2.HandleTypePersistent:
		p, ok := t.persistentObjects[handle]
		if !ok {
			// This is an object not created by the test. Assume not excempt.
			fmt.Fprintf(os.Stderr, "Authorizing with object %v not created by this test - cannot determine if DA excempt\n", handle)
			return false
		}
		return p.attrs&tpm2.AttrNoDA > 0
	default:
		// This is really an error, but just pass the command to the
		// TPM and let it fail.
		return true
	}
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

	handles, authArea, pBytes, err := cmd.UnmarshalPayload(cmdInfo.cmdHandles)
	if err != nil {
		return 0, xerrors.Errorf("invalid command payload: %w", err)
	}

	permittedFeatures := t.permittedFeatures
	var commandFeatures TPMFeatureFlags

	if cmdInfo.nv {
		commandFeatures |= TPMFeatureNV
	}

	switch commandCode {
	case tpm2.CommandHierarchyControl:
		commandFeatures |= TPMFeatureStClearChange
		if permittedFeatures&TPMFeaturePlatformHierarchy > 0 {
			// We can reenable hierarchies, as long as the platform hierarchy
			// isn't being disabled.
			var enable tpm2.Handle
			var state bool
			if _, err := mu.UnmarshalFromBytes(pBytes, &enable, &state); err != nil {
				return 0, xerrors.Errorf("cannot unmarshal parameters: %w", err)
			}

			if enable != tpm2.HandlePlatform {
				permittedFeatures |= TPMFeatureStClearChange
			}
		}
	case tpm2.CommandClear:
		commandFeatures |= TPMFeatureClear
		// Make TPMFeatureClear imply TPMFeatureNV for this command.
		permittedFeatures |= TPMFeatureNV
	case tpm2.CommandClearControl:
		commandFeatures |= TPMFeatureClearControl
		// Make TPMFeatureClearControl imply TPMFeatureNV for this command.
		permittedFeatures |= TPMFeatureNV
		if permittedFeatures&TPMFeaturePlatformHierarchy > 0 {
			// We can revert changes to disableClear
			permittedFeatures |= TPMFeatureClearControl
		}
	case tpm2.CommandNVGlobalWriteLock:
		commandFeatures |= TPMFeatureNVGlobalWriteLock
		// Make TPMFeatureNVGlobalWriteLock imply TPMFeatureNV for this command.
		permittedFeatures |= TPMFeatureNV
	case tpm2.CommandSetCommandCodeAuditStatus:
		commandFeatures |= TPMFeatureSetCommandCodeAuditStatus
		// Make TPMFeatureSetCommandCodeAuditStatus imply TPMFeatureNV for this command.
		permittedFeatures |= TPMFeatureNV
	case tpm2.CommandShutdown:
		commandFeatures |= TPMFeatureShutdown
		// Make TPMFeatureShutdown imply TPMFeatureNV for this command.
		permittedFeatures |= TPMFeatureNV
	}

	for _, h := range handles[:cmdInfo.authHandles] {
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

		if !t.isDAExcempt(h) {
			commandFeatures |= TPMFeatureDAProtectedCapability
			if permittedFeatures&TPMFeatureLockoutHierarchy > 0 {
				// We can reset the DA counter
				permittedFeatures |= TPMFeatureDAProtectedCapability
			}
		}
	}

	if ^permittedFeatures&commandFeatures != 0 {
		return 0, fmt.Errorf("command %v is trying to use a non-requested feature (missing: 0x%08x)", commandCode, uint32(^permittedFeatures&commandFeatures))
	}

	t.currentCmd = &cmdContext{
		command:  commandCode,
		handles:  handles,
		authArea: authArea,
		params:   pBytes,
		response: new(bytes.Buffer)}

	n, err := t.tcti.Write(data)
	if err != nil {
		t.currentCmd = nil
	}
	return n, err
}

func (t *TCTI) restorePlatformHierarchyAuth(tpm *tpm2.TPMContext) error {
	auth, changed := t.hierarchyAuths[tpm2.HandlePlatform]
	if !changed {
		return nil
	}
	delete(t.hierarchyAuths, tpm2.HandlePlatform)

	if t.didDisablePlatformHierarchy {
		// Permitted via TPMFeaturesStClearChange
		return nil
	}

	platform := tpm.PlatformHandleContext()
	platform.SetAuthValue(auth)
	if err := tpm.HierarchyChangeAuth(platform, nil, nil); err != nil {
		return xerrors.Errorf("cannot clear auth value for %v: %w", tpm2.HandlePlatform, err)
	}
	return nil
}

func (t *TCTI) restoreHierarchies(errs []error, tpm *tpm2.TPMContext) []error {
	if !t.didHierarchyControl {
		return errs
	}

	if t.didDisablePlatformHierarchy {
		// Permitted via TPMFeatureStClearChange
		return errs
	}

	if t.permittedFeatures&TPMFeaturePlatformHierarchy == 0 {
		// Permitted via TPMFeatureStClearChange
		return errs
	}

	for _, hierarchy := range []tpm2.Handle{tpm2.HandleOwner, tpm2.HandleEndorsement, tpm2.HandlePlatformNV} {
		var state bool
		switch hierarchy {
		case tpm2.HandleOwner:
			state = t.restoreStClearAttrs&tpm2.AttrShEnable > 0
		case tpm2.HandleEndorsement:
			state = t.restoreStClearAttrs&tpm2.AttrEhEnable > 0
		case tpm2.HandlePlatformNV:
			state = t.restoreStClearAttrs&tpm2.AttrPhEnableNV > 0
		}

		if err := tpm.HierarchyControl(tpm.PlatformHandleContext(), hierarchy, state, nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot restore hierarchy %v: %w", hierarchy, err))
		}
	}

	return errs
}

func (t *TCTI) restoreHierarchyAuths(errs []error, tpm *tpm2.TPMContext) []error {
	for hierarchy, auth := range t.hierarchyAuths {
		rc := tpm.GetPermanentContext(hierarchy)
		rc.SetAuthValue(auth)
		if err := tpm.HierarchyChangeAuth(rc, nil, nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot clear auth value for %v: %w", hierarchy, err))
		}
	}

	return errs
}

func (t *TCTI) restoreDisableClear(tpm *tpm2.TPMContext) error {
	if !t.didClearControl {
		return nil
	}

	if t.permittedFeatures&TPMFeaturePlatformHierarchy == 0 {
		// Permitted via TPMFeatureClearControl
		return nil
	}

	if t.didDisablePlatformHierarchy {
		if t.permittedFeatures&TPMFeatureClearControl > 0 {
			return nil
		}
		return errors.New("cannot restore disableClear because the platform hierarchy was disabled")
	}

	disable := t.restorePermanentAttrs&tpm2.AttrDisableClear > 0
	if err := tpm.ClearControl(tpm.PlatformHandleContext(), disable, nil); err != nil {
		return xerrors.Errorf("cannot restore disableClear: %w", err)
	}

	return nil
}

func (t *TCTI) restoreDA(errs []error, tpm *tpm2.TPMContext) []error {
	if t.permittedFeatures&TPMFeatureLockoutHierarchy > 0 {
		if err := tpm.DictionaryAttackLockReset(tpm.LockoutHandleContext(), nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot reset DA counter: %w", err))
		}
		if t.didSetDaParams {
			if err := tpm.DictionaryAttackParameters(tpm.LockoutHandleContext(), t.restoreDaParams.maxTries, t.restoreDaParams.recoveryTime, t.restoreDaParams.lockoutRecovery, nil); err != nil {
				errs = append(errs, xerrors.Errorf("cannot restore DA parameters: %w", err))
			}
		}
	}

	return errs
}

func (t *TCTI) removeResources(errs []error, tpm *tpm2.TPMContext) []error {
	for h := range t.transientObjects {
		tpm.FlushContext(tpm2.CreatePartialHandleContext(h))
	}

	for h := range t.sessions {
		tpm.FlushContext(tpm2.CreatePartialHandleContext(h))
	}

	for h, p := range t.persistentObjects {
		auth := tpm.GetPermanentContext(p.auth)
		object, err := tpm.CreateResourceContextFromTPM(h)
		if err != nil {
			errs = append(errs, xerrors.Errorf("cannot create ResourceContext for persistent object: %w", err))
			continue
		}

		if _, err := tpm.EvictControl(auth, object, object.Handle(), nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot evict %v: %w", h, err))
		}
	}

	for h, n := range t.nvIndexes {
		if n.attrs&tpm2.AttrNVPolicyDelete > 0 {
			errs = append(errs, fmt.Errorf("the test needs to undefine index %v which has the TPMA_NV_POLICY_DELETE attribute set", h))
			continue
		}

		auth := tpm.GetPermanentContext(n.auth)
		index, err := tpm.CreateResourceContextFromTPM(h)
		if err != nil {
			errs = append(errs, xerrors.Errorf("cannot create ResourceContext for NV index: %w", err))
			continue
		}

		if err := tpm.NVUndefineSpace(auth, index, nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot undefine %v: %w", h, err))
		}
	}

	return errs
}

func (t *TCTI) Close() error {
	tpm, _ := tpm2.NewTPMContext(t.tcti)

	var errs []error

	// First, restore the auth value for the platform hierarchy
	if err := t.restorePlatformHierarchyAuth(tpm); err != nil {
		errs = append(errs, err)
	}

	// ...then use the platform hierarchy, if permitted, to reenable disabled
	// hierarchies.
	errs = t.restoreHierarchies(errs, tpm)

	errs = t.restoreHierarchyAuths(errs, tpm)

	if err := t.restoreDisableClear(tpm); err != nil {
		errs = append(errs, err)
	}

	errs = t.restoreDA(errs, tpm)

	errs = t.removeResources(errs, tpm)

	if err := t.tcti.Close(); err != nil {
		return err
	}

	if len(errs) > 0 {
		err := "cannot cleanup TPM state because of the following errors:\n"
		for _, e := range errs {
			err += "- " + e.Error() + "\n"
		}
		return errors.New(err)
	}

	return nil
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

// WrapTCTI wraps the supplied TCTI and authorizes it to use the specified features.
func WrapTCTI(tcti tpm2.TCTI, permittedFeatures TPMFeatureFlags) (*TCTI, error) {
	tpm, _ := tpm2.NewTPMContext(tcti)

	props, err := tpm.GetCapabilityTPMProperties(tpm2.PropertyPermanent, tpm2.CapabilityMaxProperties)
	if err != nil {
		return nil, xerrors.Errorf("cannot request properties from TPM: %w", err)
	}

	var daParams daParams
	var permanentAttrs tpm2.PermanentAttributes
	var stClearAttrs tpm2.StartupClearAttributes

	for _, prop := range props {
		switch prop.Property {
		case tpm2.PropertyPermanent:
			permanentAttrs = tpm2.PermanentAttributes(prop.Value)
		case tpm2.PropertyStartupClear:
			stClearAttrs = tpm2.StartupClearAttributes(prop.Value)
		case tpm2.PropertyMaxAuthFail:
			daParams.maxTries = prop.Value
		case tpm2.PropertyLockoutInterval:
			daParams.recoveryTime = prop.Value
		case tpm2.PropertyLockoutRecovery:
			daParams.lockoutRecovery = prop.Value
		}
	}

	return &TCTI{
		tcti:                  tcti,
		permittedFeatures:     permittedFeatures,
		restorePermanentAttrs: permanentAttrs,
		restoreStClearAttrs:   stClearAttrs,
		restoreDaParams:       daParams,
		hierarchyAuths:        make(map[tpm2.Handle]tpm2.Auth),
		transientObjects:      make(map[tpm2.Handle]objectInfo),
		persistentObjects:     make(map[tpm2.Handle]persistentObjectInfo),
		sessions:              make(map[tpm2.Handle]sessionInfo),
		nvIndexes:             make(map[tpm2.Handle]nvIndexInfo)}, nil
}
