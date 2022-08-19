// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"math"

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

func makeInvalidArgError(name, msg string) error {
	return fmt.Errorf("invalid %s argument: %s", name, msg)
}

type execMultipleHelperAction interface {
	last() bool
	run(sessions ...SessionContext) error
}

func execMultipleHelper(action execMultipleHelperAction, sessions ...SessionContext) error {
	// Ensure all sessions have the AttrContinueSession attribute
	sessionsOrig := make([]SessionContext, len(sessions))
	copy(sessionsOrig, sessions)

	hasPolicySession := false

	for i := range sessions {
		if sessions[i] == nil {
			continue
		}

		sessionData := sessions[i].(sessionContextInternal).Data()
		if sessionData == nil {
			return errors.New("unusable session context")
		}

		if sessionData.SessionType == SessionTypePolicy {
			hasPolicySession = true
		}

		sessions[i] = sessions[i].IncludeAttrs(AttrContinueSession)
	}

	for !action.last() {
		if hasPolicySession {
			return errors.New("cannot use a policy session for authorization")
		}

		if err := action.run(sessions...); err != nil {
			return err
		}
	}

	// This is the last iteration. Run this command with the original session
	// contexts so that the sessions are evicted if they don't have the
	// AttrContinueSession attribute set.
	return action.run(sessionsOrig...)
}

type readMultipleHelperContext struct {
	fn      func(size, offset uint16, sessions ...SessionContext) ([]byte, error)
	data    []byte
	maxSize uint16

	remaining uint16
	total     uint16
}

func (c *readMultipleHelperContext) last() bool {
	return c.remaining <= c.maxSize
}

func (c *readMultipleHelperContext) run(sessions ...SessionContext) error {
	sz := c.remaining
	if c.remaining > c.maxSize {
		sz = c.maxSize
	}

	tmpData, err := c.fn(sz, c.total, sessions...)
	if err != nil {
		return err
	}
	copy(c.data[c.total:], tmpData)

	c.total += sz
	c.remaining -= sz

	return nil
}

func readMultipleHelper(size, maxSize uint16, exec func(size, offset uint16, sessions ...SessionContext) ([]byte, error), sessions ...SessionContext) ([]byte, error) {
	context := &readMultipleHelperContext{
		fn:        exec,
		data:      make([]byte, size),
		maxSize:   maxSize,
		remaining: size}

	if err := execMultipleHelper(context, sessions...); err != nil {
		return nil, err
	}

	return context.data, nil
}

func isSessionAllowed(commandCode CommandCode) bool {
	switch commandCode {
	case CommandStartup:
		return false
	case CommandContextLoad:
		return false
	case CommandContextSave:
		return false
	case CommandFlushContext:
		return false
	default:
		return true
	}
}

type cmdContext struct {
	commandCode   CommandCode
	handles       []*CommandHandleContext
	params        []interface{}
	extraSessions []SessionContext
}

type rspContext struct {
	commandCode      CommandCode
	sessionParams    *sessionParams
	responseAuthArea []AuthResponse
	rpBytes          []byte

	err error
}

// TODO: Implement commands from the following sections of part 3 of the TPM library spec:
// Section 14 - Asymmetric Primitives
// Section 15 - Symmetric Primitives
// Section 19 - Ephemeral EC Keys
// Section 26 - Miscellaneous Management Functions
// Section 27 - Field Upgrade

// TPMContext is the main entry point by which commands are executed on a TPM
// device using this package. It provides convenience functions for supported
// commands and communicates with the underlying device via a transmission
// interface, which is provided to NewTPMContext. Convenience functions are
// wrappers around TPMContext.StartCommand, which may be used directly for
// custom commands or commands that aren't supported directly by this package.
//
// Methods that execute commands on the TPM may return errors from the TPM in
// some cases. These are in the form of *TPMError, *TPMWarning, *TPMHandleError,
// *TPMSessionError, *TPMParameterError and *TPMVendorError types.
//
// Some methods make use of resources on the TPM, and use of these resources
// may require authorization with one of 3 roles - user, admin or duplication.
// The supported authorization mechanism depends on the resource and role, and
// is summarized below:
//
//  - HandleTypePCR:
//   - user role:
//    - passphrase / HMAC session (if no auth policy is set)
//    - policy session (if auth policy is set)
//  - HandleTypeNVIndex:
//   - user role: passphrase / HMAC session / policy session depending on attributes.
//   - admin role: policy session
//  - HandleTypePermanent:
//   - user role:
//    - passphrase / HMAC session
//    - policy session (if auth policy is set)
//  - HandleTypeTransient / HandleTypePersistent:
//   - user role:
//    - passphrase / HMAC session (if AttrUserWithAuth is set)
//    - policy session
//   - admin role:
//    - passphrase / HMAC session (if AttrAdminWithPolicy is not set)
//    - policy session
//   - duplication role: policy session
//
// Some methods also accept a variable number of optional SessionContext
// arguments - these are for sessions that don't provide authorization for a
// corresponding TPM resource. These sessions may be used for the purposes of
// session based parameter encryption or command auditing.
type TPMContext struct {
	tcti                  TCTI
	permanentResources    map[Handle]*permanentContext
	maxSubmissions        uint
	propertiesInitialized bool
	maxBufferSize         uint16
	maxDigestSize         uint16
	maxNVBufferSize       uint16
	minPcrSelectSize      uint8
	exclusiveSession      sessionContextInternal
	pendingResponse       *rspContext
}

// Close calls Close on the transmission interface.
func (t *TPMContext) Close() error {
	if err := t.tcti.Close(); err != nil {
		return &TctiError{"close", err}
	}

	return nil
}

// RunCommandBytes is a low-level interface for executing a command. The caller is responsible for
// supplying a properly serialized command packet, which can be created with MarshalCommandPacket.
//
// If successful, this function will return the response packet. No checking is performed on this
// response packet. An error will only be returned if the transmission interface returns an error.
//
// Most users will want to use one of the many convenience functions provided by TPMContext
// instead, or TPMContext.StartCommand if one doesn't already exist.
func (t *TPMContext) RunCommandBytes(packet CommandPacket) (ResponsePacket, error) {
	if _, err := t.tcti.Write(packet); err != nil {
		return nil, &TctiError{"write", err}
	}

	resp, err := ioutil.ReadAll(t.tcti)
	if err != nil {
		return nil, &TctiError{"read", err}
	}

	return ResponsePacket(resp), nil
}

// RunCommand is a low-level interface for executing a command. The caller supplies the command
// code, list of command handles, command auth area and marshalled command parameters. The
// caller should also supply a pointer to a response handle if the command returns one. On
// success, the response parameter bytes and response auth area are returned. This function does
// no checking of the auth response.
//
// If the TPM returns a response indicating that the command should be retried, this function
// will retry up to a maximum number of times defined by the number supplied to
// TPMContext.SetMaxSubmissions.
//
// A *TctiError will be returned if the transmission interface returns an error.
//
// One of *TPMWarning, *TPMError, *TPMParameterError, *TPMHandleError or *TPMSessionError
// will be returned if the TPM returns a response code other than ResponseSuccess.
//
// There's almost no need for most users to use this API directly. Most users will want to use
// one of the many convenience functions provided by TPMContext instead, or TPMContext.StartCommand
// if one doesn't already exist.
func (t *TPMContext) RunCommand(commandCode CommandCode, cHandles HandleList, cAuthArea []AuthCommand, cpBytes []byte, rHandle *Handle) (rpBytes []byte, rAuthArea []AuthResponse, err error) {
	cmd, err := MarshalCommandPacket(commandCode, cHandles, cAuthArea, cpBytes)
	if err != nil {
		return nil, nil, xerrors.Errorf("cannot serialize command packet: %w", err)
	}

	for tries := uint(1); ; tries++ {
		var err error
		resp, err := t.RunCommandBytes(cmd)
		if err != nil {
			return nil, nil, err
		}

		var rc ResponseCode
		rc, rpBytes, rAuthArea, err = resp.Unmarshal(rHandle)
		if err != nil {
			return nil, nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot unmarshal response packet: %v", err)}
		}

		err = DecodeResponseCode(commandCode, rc)
		if _, invalidRc := err.(InvalidResponseCodeError); invalidRc {
			return nil, nil, &InvalidResponseError{commandCode, err.Error()}
		}
		if err == nil {
			if len(rAuthArea) != len(cAuthArea) {
				return nil, nil, &InvalidResponseError{commandCode, fmt.Sprintf("unexpected number of auth responses (got %d, expected %d)",
					len(rAuthArea), len(cAuthArea))}
			}

			break
		}

		if tries >= t.maxSubmissions {
			return nil, nil, err
		}
		if !(IsTPMWarning(err, WarningYielded, commandCode) || IsTPMWarning(err, WarningTesting, commandCode) || IsTPMWarning(err, WarningRetry, commandCode)) {
			return nil, nil, err
		}
	}

	return rpBytes, rAuthArea, nil
}

func (t *TPMContext) processResponseAuth(r *rspContext) (err error) {
	if r != t.pendingResponse {
		return r.err
	}

	defer func() {
		r.err = err
	}()

	t.pendingResponse = nil

	if isSessionAllowed(r.commandCode) && t.exclusiveSession != nil {
		t.exclusiveSession.Data().IsExclusive = false
		t.exclusiveSession = nil
	}

	if err := r.sessionParams.processResponseAuthArea(r.responseAuthArea, r.rpBytes); err != nil {
		return &InvalidResponseError{r.commandCode, fmt.Sprintf("cannot process response auth area: %v", err)}
	}

	for _, s := range r.sessionParams.sessions {
		if s.session.IsExclusive() {
			t.exclusiveSession = s.session
			break
		}
	}

	return nil
}

func (t *TPMContext) completeResponse(r *rspContext, responseParams ...interface{}) error {
	if err := t.processResponseAuth(r); err != nil {
		return err
	}

	rpBuf := bytes.NewReader(r.rpBytes)

	if _, err := mu.UnmarshalFromReader(rpBuf, responseParams...); err != nil {
		return &InvalidResponseError{r.commandCode, fmt.Sprintf("cannot unmarshal response parameters: %v", err)}
	}

	if rpBuf.Len() > 0 {
		return &InvalidResponseError{r.commandCode, fmt.Sprintf("response parameter area contains %d trailing bytes", rpBuf.Len())}
	}

	return nil
}

func (t *TPMContext) runCommandContext(c *cmdContext, responseHandle *Handle) (*rspContext, error) {
	var handles HandleList
	var handleNames []Name
	var sessionParams sessionParams

	for _, h := range c.handles {
		handles = append(handles, h.handle.Handle())
		handleNames = append(handleNames, h.handle.Name())

		if h.session != nil {
			if err := sessionParams.appendSessionForResource(h.session, h.handle.(ResourceContext)); err != nil {
				return nil, fmt.Errorf("cannot process HandleContext for command %s at index %d: %v", c.commandCode, len(handles), err)
			}
		}
	}
	if err := sessionParams.appendExtraSessions(c.extraSessions...); err != nil {
		return nil, fmt.Errorf("cannot process non-auth SessionContext parameters for command %s: %v", c.commandCode, err)
	}

	if sessionParams.hasDecryptSession() && (len(c.params) == 0 || !isParamEncryptable(c.params[0])) {
		return nil, fmt.Errorf("command %s does not support command parameter encryption", c.commandCode)
	}

	cpBytes, err := mu.MarshalToBytes(c.params...)
	if err != nil {
		return nil, xerrors.Errorf("cannot marshal parameters for command %s: %w", c.commandCode, err)
	}

	cAuthArea, err := sessionParams.buildCommandAuthArea(c.commandCode, handleNames, cpBytes)
	if err != nil {
		return nil, xerrors.Errorf("cannot build auth area for command %s: %w", c.commandCode, err)
	}

	if t.pendingResponse != nil {
		t.processResponseAuth(t.pendingResponse)
	}

	rpBytes, rAuthArea, err := t.RunCommand(c.commandCode, handles, cAuthArea, cpBytes, responseHandle)
	if err != nil {
		return nil, err
	}

	r := &rspContext{
		commandCode:      c.commandCode,
		sessionParams:    &sessionParams,
		responseAuthArea: rAuthArea,
		rpBytes:          rpBytes}
	t.pendingResponse = r
	return r, nil
}

// StartCommand is the high-level function for beginning the process of executing a command. It
// returns a CommandContext that can be used to assemble a command, properly serialize a command
// packet and then submit the packet for execution via TPMContext.RunCommand.
//
// Most users will want to use one of the many convenience functions provided by TPMContext,
// which are just wrappers around this.
func (t *TPMContext) StartCommand(commandCode CommandCode) *CommandContext {
	return &CommandContext{
		tpm: t,
		cmdContext: cmdContext{
			commandCode: commandCode}}
}

// SetMaxSubmissions sets the maximum number of times that CommandContext will attempt to
// submit a command before failing with an error. The default value is 5.
func (t *TPMContext) SetMaxSubmissions(max uint) {
	t.maxSubmissions = max
}

// InitProperties executes a TPM2_GetCapability command to initialize properties used internally by TPMContext. This is normally done
// automatically by functions that require these properties when they are used for the first time, but this function is provided so
// that the command can be audited, and so the exclusivity of an audit session can be preserved.
func (t *TPMContext) InitProperties(sessions ...SessionContext) error {
	props, err := t.GetCapabilityTPMProperties(PropertyFixed, CapabilityMaxProperties, sessions...)
	if err != nil {
		return err
	}

	for _, prop := range props {
		switch prop.Property {
		case PropertyInputBuffer, PropertyMaxDigest, PropertyNVBufferMax:
			if prop.Value > math.MaxUint16 {
				return &InvalidResponseError{Command: CommandGetCapability, msg: fmt.Sprintf("property %v out of range", prop.Property)}
			}

			value := uint16(prop.Value)

			switch prop.Property {
			case PropertyInputBuffer:
				t.maxBufferSize = value
			case PropertyMaxDigest:
				t.maxDigestSize = value
			case PropertyNVBufferMax:
				t.maxNVBufferSize = value
			}
		case PropertyPCRSelectMin:
			if prop.Value > math.MaxUint8 {
				return &InvalidResponseError{Command: CommandGetCapability, msg: "property TPM_PT_PCR_SELECT_MIN out of range"}
			}
			t.minPcrSelectSize = uint8(prop.Value)
		}
	}

	if t.maxBufferSize == 0 {
		t.maxBufferSize = 1024
	}
	if t.maxDigestSize == 0 {
		return &InvalidResponseError{Command: CommandGetCapability, msg: "missing or invalid TPM_PT_MAX_DIGEST property"}
	}
	if t.maxNVBufferSize == 0 {
		return &InvalidResponseError{Command: CommandGetCapability, msg: "missing or invalid TPM_PT_NV_BUFFER_MAX property"}
	}
	if t.minPcrSelectSize == 0 {
		return &InvalidResponseError{Command: CommandGetCapability, msg: "missing or invalid TPM_PT_PCR_SELECT_MIN property"}
	}
	t.propertiesInitialized = true
	return nil
}

func (t *TPMContext) initPropertiesIfNeeded() error {
	if t.propertiesInitialized {
		return nil
	}
	return t.InitProperties()
}

func newTpmContext(tcti TCTI) *TPMContext {
	r := new(TPMContext)
	r.tcti = tcti
	r.permanentResources = make(map[Handle]*permanentContext)
	r.maxSubmissions = 5

	return r
}

// NewTPMContext creates a new instance of TPMContext, which communicates with the
// TPM using the transmission interface provided via the tcti parameter. The
// transmission interface must not be nil - it is expected that the caller checks
// the error returned from the function that is used to create it.
func NewTPMContext(tcti TCTI) *TPMContext {
	if tcti == nil {
		panic("nil transmission interface")
	}

	t := new(TPMContext)
	t.tcti = tcti
	t.permanentResources = make(map[Handle]*permanentContext)
	t.maxSubmissions = 5

	return t
}
