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

type TCTIWrapper interface {
	Unwrap() tpm2.TCTI
}

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
	tpm2.CommandEvictControl:               commandInfo{1, 2, false, true},
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
	pub *tpm2.Public
	seq bool
}

type persistentObjectInfo struct {
	auth    tpm2.Handle
	pub     *tpm2.Public
	created bool
}

type sessionInfo struct{}

type nvIndexInfo struct {
	pub     *tpm2.NVPublic
	created bool
}

type savedObject struct {
	data tpm2.ContextData
	info *objectInfo
}

type daParams struct {
	maxTries        uint32
	recoveryTime    uint32
	lockoutRecovery uint32
}

type cmdContext struct {
	command  tpm2.CommandPacket
	response *bytes.Buffer
}

type cmdAuditStatus struct {
	alg      tpm2.HashAlgorithmId
	commands tpm2.CommandCodeList
}

var savedObjects []savedObject

// CommandRecord provides information about a command executed via
// the TCTI interface.
type CommandRecord struct {
	cmdInfo        *commandInfo
	commandPacket  tpm2.CommandPacket
	responsePacket tpm2.ResponsePacket
}

// GetCommandCode returns the command code associated with this record.
func (r *CommandRecord) GetCommandCode() (tpm2.CommandCode, error) {
	return r.commandPacket.GetCommandCode()
}

// UnmarshalCommand unmarshals the command packet associated with this
// record, returning the handles, auth area and parameters. The parameters
// will still be in the TPM wire format.
func (r *CommandRecord) UnmarshalCommand() (handles tpm2.HandleList, authArea []tpm2.AuthCommand, parameters []byte, err error) {
	return r.commandPacket.Unmarshal(r.cmdInfo.cmdHandles)
}

// UnmarshalResponse unmarshals the response packet associated with this
// record, returning the response code, handle, parameters and auth area.
// The parameters will still be in the TPM wire format. For commands that
// don't respond with a handle, the returned handle will be
// tpm2.HandleUnassigned.
func (r *CommandRecord) UnmarshalResponse() (rc tpm2.ResponseCode, handle tpm2.Handle, parameters []byte, authArea []tpm2.AuthResponse, err error) {
	handle = tpm2.HandleUnassigned
	var pHandle *tpm2.Handle
	if r.cmdInfo.rspHandle {
		pHandle = &handle
	}
	rc, parameters, authArea, err = r.responsePacket.Unmarshal(pHandle)
	if err != nil {
		return 0, handle, nil, nil, err
	}
	return rc, handle, parameters, authArea, nil
}

// TCTI is a special proxy inteface used for testing, which wraps a real interface.
// It tracks changes to the TPM state and restores it when the connection is closed,
// and also performs some permission checks to ensure that a test does not access
// functionality that it has not declared as permitted.
type TCTI struct {
	tcti              tpm2.TCTI
	permittedFeatures TPMFeatureFlags

	restorePermanentAttrs tpm2.PermanentAttributes
	restoreStClearAttrs   tpm2.StartupClearAttributes
	restoreDaParams       daParams
	restoreCmdAuditStatus cmdAuditStatus

	currentCmd *cmdContext

	hierarchyAuths    map[tpm2.Handle]tpm2.Auth
	transientObjects  map[tpm2.Handle]*objectInfo
	persistentObjects map[tpm2.Handle]*persistentObjectInfo
	sessions          map[tpm2.Handle]sessionInfo
	nvIndexes         map[tpm2.Handle]*nvIndexInfo

	didClearControl      bool
	didHierarchyControl  bool
	didSetDaParams       bool
	didSetCmdAuditStatus bool

	// CommandLog keeps a record of all of the commands executed via
	// this interface
	CommandLog            []*CommandRecord
	disableCommandLogging bool
}

func (t *TCTI) processCommandDone() error {
	currentCmd := t.currentCmd
	t.currentCmd = nil

	commandCode, _ := currentCmd.command.GetCommandCode()
	cmdInfo := commandInfoMap[commandCode]
	if !t.disableCommandLogging {
		t.CommandLog = append(t.CommandLog, &CommandRecord{&cmdInfo, currentCmd.command, tpm2.ResponsePacket(currentCmd.response.Bytes())})
	}

	cmdHandles, authArea, cpBytes, _ := currentCmd.command.Unmarshal(cmdInfo.cmdHandles)

	var rHandle tpm2.Handle
	var pHandle *tpm2.Handle

	// Unpack the response packet
	if cmdInfo.rspHandle {
		pHandle = &rHandle
	}
	resp := tpm2.ResponsePacket(currentCmd.response.Bytes())
	rc, rpBytes, _, err := resp.Unmarshal(pHandle)
	if err != nil {
		return xerrors.Errorf("cannot unmarshal response: %w", err)
	}
	if rc != tpm2.Success {
		return nil
	}

	// Record new transient objects or sessions
	switch rHandle.Type() {
	case tpm2.HandleTypeHMACSession, tpm2.HandleTypePolicySession:
		rHandle = canonicalizeHandle(rHandle)
		t.sessions[canonicalizeHandle(rHandle)] = sessionInfo{}
	case tpm2.HandleTypeTransient:
		var info objectInfo

		switch commandCode {
		case tpm2.CommandCreatePrimary:
			var inSensitive []byte
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(cpBytes, &inSensitive, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			info = objectInfo{pub: inPublic.Ptr}
		case tpm2.CommandLoad:
			var inPrivate tpm2.Private
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(cpBytes, &inPrivate, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			info = objectInfo{pub: inPublic.Ptr}
		case tpm2.CommandHMACStart:
			info = objectInfo{seq: true}
		case tpm2.CommandContextLoad:
			var context tpm2.Context
			if _, err := mu.UnmarshalFromBytes(cpBytes, &context); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			for _, s := range savedObjects {
				if bytes.Equal(s.data, context.Blob) {
					info = *s.info
					break
				}
			}
		case tpm2.CommandLoadExternal:
			var inPrivate []byte
			var inPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(cpBytes, &inPrivate, &inPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal params: %w", err)
			}
			info = objectInfo{pub: inPublic.Ptr}
		case tpm2.CommandHashSequenceStart:
			info = objectInfo{seq: true}
		case tpm2.CommandCreateLoaded:
			fmt.Fprintf(os.Stderr, "TPM2_CreateLoaded is not supported yet")
		}

		t.transientObjects[rHandle] = &info
	}

	// Command specific updates
	switch commandCode {
	case tpm2.CommandNVUndefineSpaceSpecial:
		// Drop undefined NV index
		delete(t.nvIndexes, cmdHandles[0])
	case tpm2.CommandEvictControl:
		auth := cmdHandles[0]
		object := cmdHandles[1]
		var persistent tpm2.Handle
		if _, err := mu.UnmarshalFromBytes(cpBytes, &persistent); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		switch object.Type() {
		case tpm2.HandleTypeTransient:
			// Record newly persisted object
			var pub *tpm2.Public
			if info, ok := t.transientObjects[object]; ok {
				pub = info.pub
			} else {
				fmt.Fprintf(os.Stderr, "New persistent object %v was created from transient object %v not known to the test fixture\n", persistent, object)
			}
			t.persistentObjects[persistent] = &persistentObjectInfo{auth: auth, pub: pub, created: true}
		case tpm2.HandleTypePersistent:
			// Drop evicted object
			delete(t.persistentObjects, persistent)
		default:
			panic("invalid handle type")
		}
	case tpm2.CommandHierarchyControl:
		t.didHierarchyControl = true
	case tpm2.CommandNVUndefineSpace:
		// Drop undefined NV index
		delete(t.nvIndexes, cmdHandles[1])
	case tpm2.CommandClear:
		delete(t.hierarchyAuths, tpm2.HandleOwner)
		delete(t.hierarchyAuths, tpm2.HandleEndorsement)
		delete(t.hierarchyAuths, tpm2.HandleLockout)

		for h, info := range t.persistentObjects {
			if info.auth == tpm2.HandleOwner {
				delete(t.persistentObjects, h)
			}
		}
		for h, info := range t.nvIndexes {
			if info.pub.Attrs&tpm2.AttrNVPlatformCreate == 0 {
				// This is an owner object
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
		if authArea[0].SessionAttributes&tpm2.AttrCommandEncrypt == 0 {
			if _, err := mu.UnmarshalFromBytes(cpBytes, &newAuth); err != nil {
				return xerrors.Errorf("cannot unmarshal parameters: %w", err)
			}
		}
		t.hierarchyAuths[cmdHandles[0]] = newAuth
	case tpm2.CommandNVDefineSpace:
		// Record newly defined NV index
		var auth tpm2.Auth
		var nvPublic struct {
			Ptr *tpm2.NVPublic `tpm2:"sized"`
		}
		if _, err := mu.UnmarshalFromBytes(cpBytes, &auth, &nvPublic); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		index := nvPublic.Ptr.Index
		t.nvIndexes[index] = &nvIndexInfo{pub: nvPublic.Ptr, created: true}
	case tpm2.CommandDictionaryAttackParameters:
		t.didSetDaParams = true
	case tpm2.CommandSetCommandCodeAuditStatus:
		t.didSetCmdAuditStatus = true
	case tpm2.CommandStartup:
		var startupType tpm2.StartupType
		if _, err := mu.UnmarshalFromBytes(cpBytes, &startupType); err != nil {
			return xerrors.Errorf("cannot unmarshal parameters: %w", err)
		}
		if startupType != tpm2.StartupState {
			delete(t.hierarchyAuths, tpm2.HandlePlatform)
			t.didHierarchyControl = false
		}
	case tpm2.CommandContextSave:
		handle := cmdHandles[0]
		switch handle.Type() {
		case tpm2.HandleTypeHMACSession, tpm2.HandleTypePolicySession:
		case tpm2.HandleTypeTransient:
			var context tpm2.Context
			if _, err := mu.UnmarshalFromBytes(rpBytes, &context); err != nil {
				return xerrors.Errorf("cannot unmarshal response parameters: %w", err)
			}
			if info, ok := t.transientObjects[handle]; ok {
				savedObjects = append(savedObjects, savedObject{data: context.Blob, info: info})
			}
		default:
			panic("invalid handle type")
		}
	case tpm2.CommandNVReadPublic:
		nvIndex := cmdHandles[0]
		var nvPublic struct {
			Ptr *tpm2.NVPublic `tpm2:"sized"`
		}
		if _, err := mu.UnmarshalFromBytes(rpBytes, &nvPublic); err != nil {
			return xerrors.Errorf("cannot unmarshal response parameters: %w", err)
		}
		if _, ok := t.nvIndexes[nvIndex]; !ok {
			t.nvIndexes[nvIndex] = &nvIndexInfo{}
		}
		t.nvIndexes[nvIndex].pub = nvPublic.Ptr
	case tpm2.CommandReadPublic:
		object := cmdHandles[0]
		if object.Type() == tpm2.HandleTypePersistent {
			var outPublic struct {
				Ptr *tpm2.Public `tpm2:"sized"`
			}
			if _, err := mu.UnmarshalFromBytes(rpBytes, &outPublic); err != nil {
				return xerrors.Errorf("cannot unmarshal response parameters: %w", err)
			}
			if _, ok := t.persistentObjects[object]; !ok {
				var auth tpm2.Handle
				if object < 0x81800000 {
					auth = tpm2.HandleOwner
				} else {
					auth = tpm2.HandlePlatform
				}
				t.persistentObjects[object] = &persistentObjectInfo{auth: auth}
			}
			t.persistentObjects[object].pub = outPublic.Ptr
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

func (t *TCTI) isDAExcempt(handle tpm2.Handle) (bool, error) {
	switch handle.Type() {
	case tpm2.HandleTypePCR:
		return true, nil
	case tpm2.HandleTypeNVIndex:
		info, ok := t.nvIndexes[handle]
		if !ok {
			// This is an index not created by the test.
			return false, fmt.Errorf("authorizing with NV index %v not known to the test fixture - cannot determine if DA excempt", handle)
		}
		return info.pub.Attrs&tpm2.AttrNVNoDA > 0, nil
	case tpm2.HandleTypePermanent:
		if handle == tpm2.HandleLockout {
			return false, nil
		}
		return true, nil
	case tpm2.HandleTypeTransient:
		info, ok := t.transientObjects[handle]
		if !ok || (!info.seq && info.pub == nil) {
			// This is an object not created by the test.
			return false, fmt.Errorf("authorizing with object %v not known to the test fixture - cannot determine if DA excempt", handle)
		}
		return info.seq || info.pub.Attrs&tpm2.AttrNoDA > 0, nil
	case tpm2.HandleTypePersistent:
		info, ok := t.persistentObjects[handle]
		if !ok || info.pub == nil {
			// This is an object not created by the test.
			return false, fmt.Errorf("authorizing with object %v not known to the test fixture - cannot determine if DA excempt", handle)
		}
		return info.pub.Attrs&tpm2.AttrNoDA > 0, nil
	default:
		// This is really an error, but just pass the command to the
		// TPM and let it fail.
		return true, nil
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

	handles, _, pBytes, err := cmd.Unmarshal(cmdInfo.cmdHandles)
	if err != nil {
		return 0, xerrors.Errorf("invalid command payload: %w", err)
	}

	var commandFeatures TPMFeatureFlags

	if cmdInfo.nv {
		commandFeatures |= TPMFeatureNV
	}

	switch commandCode {
	case tpm2.CommandHierarchyControl:
		commandFeatures |= TPMFeatureStClearChange
		if t.permittedFeatures&TPMFeaturePlatformHierarchy > 0 {
			// We can reenable hierarchies, as long as the platform hierarchy
			// isn't being disabled.
			var enable tpm2.Handle
			var state bool
			if _, err := mu.UnmarshalFromBytes(pBytes, &enable, &state); err != nil {
				return 0, xerrors.Errorf("cannot unmarshal parameters: %w", err)
			}

			if enable != tpm2.HandlePlatform {
				commandFeatures &^= TPMFeatureStClearChange
			}
		}
	case tpm2.CommandClear:
		commandFeatures |= TPMFeatureClear
		// Make TPMFeatureClear imply TPMFeatureNV for this command.
		commandFeatures &^= TPMFeatureNV
	case tpm2.CommandClearControl:
		commandFeatures |= TPMFeatureClearControl
		if t.permittedFeatures&TPMFeaturePlatformHierarchy > 0 {
			// We can revert changes to disableClear
			commandFeatures &^= TPMFeatureClearControl
		} else {
			// Make TPMFeatureClearControl imply TPMFeatureNV for this command.
			commandFeatures &^= TPMFeatureNV
		}
	case tpm2.CommandNVGlobalWriteLock:
		commandFeatures |= TPMFeatureNVGlobalWriteLock
		// Make TPMFeatureNVGlobalWriteLock imply TPMFeatureNV for this command.
		commandFeatures &^= TPMFeatureNV
	case tpm2.CommandSetCommandCodeAuditStatus:
		commandFeatures |= TPMFeatureSetCommandCodeAuditStatus
		if t.permittedFeatures&TPMFeatureEndorsementHierarchy > 0 {
			// We can revert changes to this. Note that reverting requires the use
			// of the storage or platform hierarchy too, which is checked implicitly.
			commandFeatures &^= TPMFeatureSetCommandCodeAuditStatus
		} else {
			// Make TPMFeatureSetCommandCodeAuditStatus imply TPMFeatureNV for this command.
			commandFeatures &^= TPMFeatureNV
		}
	case tpm2.CommandShutdown:
		commandFeatures |= TPMFeatureShutdown
		// Make TPMFeatureShutdown imply TPMFeatureNV for this command.
		commandFeatures &^= TPMFeatureNV
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

		daExcempt, err := t.isDAExcempt(h)
		if err != nil {
			return 0, err
		}
		if !daExcempt && t.permittedFeatures&TPMFeatureLockoutHierarchy == 0 {
			// We can't reset the DA counter
			commandFeatures |= TPMFeatureDAProtectedCapability
		}
	}

	if ^t.permittedFeatures&commandFeatures != 0 {
		return 0, fmt.Errorf("command %v is trying to use a non-requested feature (missing: 0x%08x)", commandCode, uint32(^t.permittedFeatures&commandFeatures))
	}

	t.currentCmd = &cmdContext{
		command:  cmd,
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

	platform := tpm.PlatformHandleContext()
	platform.SetAuthValue(auth)
	if err := tpm.HierarchyChangeAuth(platform, nil, nil); err != nil {
		if tpm2.IsTPMHandleError(err, tpm2.ErrorHierarchy, tpm2.CommandHierarchyChangeAuth, 1) {
			// Hierarchy was disabled which was permitted with TPMFeatureStClearChange, so
			// this is ok as it will be restored on the next TPM2_Startup(CLEAR).
			return nil
		}
		return xerrors.Errorf("cannot clear auth value for %v: %w", tpm2.HandlePlatform, err)
	}
	return nil
}

func (t *TCTI) restoreHierarchies(errs []error, tpm *tpm2.TPMContext) []error {
	if !t.didHierarchyControl {
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
			if tpm2.IsTPMHandleError(err, tpm2.ErrorHierarchy, tpm2.CommandHierarchyControl, 1) {
				// The platform hierarchy was disabled which was permitted with TPMFeatureStClearChange,
				// so this is ok as it will be restored on the next TPM2_Startup(CLEAR).
				break
			}
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

	disable := t.restorePermanentAttrs&tpm2.AttrDisableClear > 0
	if err := tpm.ClearControl(tpm.PlatformHandleContext(), disable, nil); err != nil {
		if t.permittedFeatures&TPMFeatureClearControl > 0 {
			return nil
		}
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

	for h, info := range t.persistentObjects {
		if !info.created {
			continue
		}

		auth := tpm.GetPermanentContext(info.auth)
		object, err := tpm2.CreateObjectResourceContextFromPublic(h, info.pub)
		if err != nil {
			errs = append(errs, xerrors.Errorf("cannot create ResourceContext for persistent object: %w", err))
			continue
		}

		if _, err := tpm.EvictControl(auth, object, object.Handle(), nil); err != nil {
			errs = append(errs, xerrors.Errorf("cannot evict %v: %w", h, err))
		}
	}

	for h, info := range t.nvIndexes {
		if !info.created {
			continue
		}

		if info.pub.Attrs&tpm2.AttrNVPolicyDelete > 0 {
			errs = append(errs, fmt.Errorf("the test needs to undefine index %v which has the TPMA_NV_POLICY_DELETE attribute set", h))
			continue
		}

		var auth tpm2.ResourceContext
		if info.pub.Attrs&tpm2.AttrNVPlatformCreate > 0 {
			auth = tpm.PlatformHandleContext()
		} else {
			auth = tpm.OwnerHandleContext()
		}
		index, err := tpm2.CreateNVIndexResourceContextFromPublic(info.pub)
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

func (t *TCTI) restoreCommandCodeAuditStatus(tpm *tpm2.TPMContext) error {
	if !t.didSetCmdAuditStatus {
		return nil
	}

	if t.permittedFeatures&TPMFeatureEndorsementHierarchy == 0 {
		// Permitted via TPMFeatureSetCommandCodeAuditStatus
		return nil
	}

	var auth tpm2.ResourceContext
	switch {
	case t.permittedFeatures&TPMFeatureOwnerHierarchy > 0:
		auth = tpm.OwnerHandleContext()
	case t.permittedFeatures&TPMFeaturePlatformHierarchy > 0:
		auth = tpm.PlatformHandleContext()
	default:
		panic("no appropriate permssion for TPM2_SetCommandCodeAuditStatus")
	}

	if err := tpm.SetCommandCodeAuditStatus(auth, t.restoreCmdAuditStatus.alg, nil, nil, nil); err != nil {
		if t.permittedFeatures&TPMFeatureSetCommandCodeAuditStatus > 0 {
			return nil
		}
		return xerrors.Errorf("cannot restore command code audit alg: %w", err)
	}

	clearList, err := tpm.GetCapabilityAuditCommands(tpm2.CommandFirst, tpm2.CapabilityMaxProperties)
	if err != nil {
		if t.permittedFeatures&TPMFeatureSetCommandCodeAuditStatus > 0 {
			return nil
		}
		return xerrors.Errorf("cannot obtain current audit commands: %w", err)
	}

	if err := tpm.SetCommandCodeAuditStatus(auth, tpm2.HashAlgorithmNull, nil, clearList, nil); err != nil {
		if t.permittedFeatures&TPMFeatureSetCommandCodeAuditStatus > 0 {
			return nil
		}
		return xerrors.Errorf("cannot clear audit commands: %w", err)
	}

	if err := tpm.SetCommandCodeAuditStatus(auth, tpm2.HashAlgorithmNull, t.restoreCmdAuditStatus.commands, nil, nil); err != nil {
		if t.permittedFeatures&TPMFeatureSetCommandCodeAuditStatus > 0 {
			return nil
		}
		return xerrors.Errorf("cannot restore audit commands: %w", err)
	}

	return nil
}

// Close will attempt to restore the state of the TPM and then close the connection.
//
// If any hierarchies were disabled by a test, they will be re-enabled if
// TPMFeaturePlatformHierarchy is permitted and the platform hierarchy hasn't been
// disabled. If TPMFeaturePlatformHierarchy isn't permitted or the platform hierarchy
// has been disabled, then disabled hierarchies cannot be re-enabled. Note that
// TPMFeatureStClearChange must be permitted in order to disable hierarchies
// without being able to reenable them again.
//
// If any hierarchy authorization values are set by a test, they will be cleared.
// If the authorization value for the owner or endorsement hierarchy cannot be
// cleared because the test disabled the hierarchy and it cannot be re-enabled, an
// error will be returned. If an authorization value cannot be cleared because it
// was set by a command using command parameter encryption, an error will be returned.
// The test must clear the authorization value itself in this case.
//
// If the TPM2_ClearControl command was used to disable the TPM2_Clear command, it
// will be re-enabled if TPMFeaturePlatformHierarchy is permitted. If
// TPMFeaturePlatformHierarchy isn't permitted, then the TPM2_Clear command won't be
// re-enabled. The TPMFeatureClearControl must be permitted in order to use the
// TPM2_ClearControl command in this case. If TPMFeaturePlatformHierarchy is permitted
// and TPMFeatureClearControl is not permitted, but the TPM2_Clear command cannot be
// re-enabled (eg, because the platform hierarchy was disabled), then an error will
// be returned.
//
// If TPMFeatureLockoutHierarchy is permitted, the DA counter will be reset. If
// TPMFeatureLockoutHierarchy is not permitted then the DA counter will not be reset.
// In this case, TPMFeatureDAProtectedCapability must be permitted in order to use any
// DA protected resource which might cause the DA counter to be incremented.
//
// Changes made by the TPM2_DictionaryAttackParameters command will be reverted.
//
// Any transient objects or sessions loaded into the TPM will be flushed.
//
// Any persistent resources created by the test will be evicted or undefined. If a
// persistent resource cannot be evicted or undefined (eg, because the corresponding
// hierarchy has been disabled and cannot be re-enabled), an error will be returned.
// If a NV index is defined with the TPMA_NV_POLICY_DELETE attribute set, an error
// will be returned. The test must undefine the index itself in this case. It is not
// possible for resources created by a test to remain in the TPM after calling this
// function without returning an error.
//
// If the TPM2_SetCommandCodeAuditStatus command was used and
// TPMFeatureEndorsementHierarchy is permitted, changes made by that command will
// be undone. If TPMFeatureEndorsementHierarchy is not permitted, then
// TPMFeatureSetCommandCodeAuditStatus must be permitted in order to use that
// command and in this case, changes made by it won't be undone. If changes
// can't be undone because, eg, the endorsement hierarchy was disabled and cannot
// be reenabled, and TPMFeatureSetCommandCodeAuditStatus is not permitted, then an
// error will be returned.
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

	if err := t.restoreCommandCodeAuditStatus(tpm); err != nil {
		errs = append(errs, err)
	}

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

// WrapTCTI wraps the supplied TCTI and authorizes it to use the specified features. If
// the supplied TCTI corresponds to a real TPM device, the caller should verify that the
// specified features are permitted by the current test environment by checking the value
// of the PermittedTPMFeatures variable before calling this, and should skip the current
// test if it needs to use features that are not permitted.
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

	var cmdAuditStatus cmdAuditStatus
	if permittedFeatures&TPMFeatureEndorsementHierarchy > 0 {
		commands, err := tpm.GetCapabilityAuditCommands(tpm2.CommandFirst, tpm2.CapabilityMaxProperties)
		if err != nil {
			return nil, xerrors.Errorf("cannot request audit commands from TPM: %w", err)
		}
		auditInfo, _, err := tpm.GetCommandAuditDigest(tpm.EndorsementHandleContext(), nil, nil, nil, nil, nil)
		if err != nil {
			return nil, xerrors.Errorf("cannot request audit info from TPM: %w", err)
		}
		cmdAuditStatus.alg = tpm2.HashAlgorithmId(auditInfo.Attested.CommandAudit.DigestAlg)
		cmdAuditStatus.commands = commands
	}

	return &TCTI{
		tcti:                  tcti,
		permittedFeatures:     permittedFeatures,
		restorePermanentAttrs: permanentAttrs,
		restoreStClearAttrs:   stClearAttrs,
		restoreDaParams:       daParams,
		restoreCmdAuditStatus: cmdAuditStatus,
		hierarchyAuths:        make(map[tpm2.Handle]tpm2.Auth),
		transientObjects:      make(map[tpm2.Handle]*objectInfo),
		persistentObjects:     make(map[tpm2.Handle]*persistentObjectInfo),
		sessions:              make(map[tpm2.Handle]sessionInfo),
		nvIndexes:             make(map[tpm2.Handle]*nvIndexInfo)}, nil
}
