// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

	"golang.org/x/xerrors"
)

func makeInvalidParamError(name, msg string) error {
	return fmt.Errorf("invalid %s parameter: %s", name, msg)
}

func wrapMarshallingError(commandCode CommandCode, context string, err error) error {
	return fmt.Errorf("cannot marshal %s for command %s: %v", context, commandCode, err)
}

func handleUnmarshallingError(context *cmdContext, scope string, err error) error {
	var s invalidSelectorError
	if xerrors.Is(err, io.EOF) || xerrors.Is(err, io.ErrUnexpectedEOF) || xerrors.As(err, &s) {
		return &InvalidResponseError{context.commandCode, fmt.Sprintf("cannot unmarshal %s: %v", scope, err)}
	}

	return fmt.Errorf("cannot unmarshal %s for command %s: %v", scope, context.commandCode, err)
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

type responseAuthAreaRawSlice struct {
	Data []authResponse `tpm2:"raw"`
}

type commandHeader struct {
	Tag         StructTag
	CommandSize uint32
	CommandCode CommandCode
}

type responseHeader struct {
	Tag          StructTag
	ResponseSize uint32
	ResponseCode ResponseCode
}

type cmdContext struct {
	commandCode   CommandCode
	sessionParams []*sessionParam
	responseCode  ResponseCode
	responseTag   StructTag
	responseBytes []byte
}

type separatorSentinel struct{}

// Separator is a sentinel value used to separate command handles, command parameters, response handle pointers and response
// parameter pointers in the variable length params argument in TPMContext.RunCommand.
var Separator separatorSentinel

// SessionAttributes is a set of flags that specify the usage and behaviour of a session.
type SessionAttributes int

const (
	// AttrContinueSession specifies that the session should not be flushed from the TPM after it is used. If a session is used without
	// this flag, it will be flushed from the TPM after the command completes. In this case, the ResourceContext associated with the
	// session will be invalidated.
	AttrContinueSession SessionAttributes = 1 << iota

	// AttrAuditExclusive is used with AttrAudit and specifies that the command should only be executed if the session is exclusive
	// at the start of the command. A session becomes exclusive when it is used for auditing for the first time, or if the AttrAuditReset
	// attribute is provided. A session will remain exclusive until the TPM executes any command where the exclusive session isn't used
	// for auditing, if that command allows for audit sessions to be provided.
	AttrAuditExclusive

	// AttrAuditReset is used with AttrAudit and specifies that the audit digest of the session should be reset and the session should
	// become exclusive. A session will remain exclusive until the TPM executes any command where the exclusive session isn't used for
	// auditing, if that command allows for audit sessions to be provided.
	AttrAuditReset

	// AttrCommandEncrypt specifies that the session should be used for encryption of the first command parameter before being sent
	// from the host to the TPM. This can only be used for parameters that have types corresponding to TPM2B prefixed TCG types,
	// and requires a session that was configured with a valid symmetric algorithm via the symmetric argument of
	// TPMContext.StartAuthSession.
	AttrCommandEncrypt

	// AttrResponseEncrypt specifies that the session should be used for encryption of the first response parameter before being sent
	// from the TPM to the host. This can only be used for parameters that have types corresponding to TPM2B prefixed TCG types, and
	// requires a session that was configured with a valid symmetric algorithm via the symmetric argument of TPMContext.StartAuthSession.
	// This package automatically decrypts the received encrypted response parameter.
	AttrResponseEncrypt

	// AttrAudit indicates that the session should be used for auditing. If this is the first time that the session is used for auditing,
	// then this attribute will result in the session becoming exclusive. A session will remain exclusive until the TPM executes any
	// command where the exclusive session isn't used for auditing, if that command allows for audit sessions to be provided.
	AttrAudit
)

// Session wraps a session ResourceContext with some additional parameters that define how a command should use the session.
type Session struct {
	Context ResourceContext // A ResourceContext that corresponds to a loaded session on the TPM

	// AuthValue is the authorization value of the resource that the session is being used to provide an authorisation for. For HMAC
	// sessions, AuthValue will be included in the HMAC key if the session associated with Context is not bound, or the session is
	// used to provide authorization for a resource to which it isn't bound. In this case, AuthValue must match the authorization
	// value of the resource that this session is being used to provide authorization for. If the resource that this session is
	// being used to provide authorization for is the one that is bound to the session, then AuthValue can be omitted. If it is
	// provided, then it must match the authorization value of the resource to which the session is bound.
	//
	// For policy sessions, AuthValue is not included in the HMAC key unless the TPMContext.PolicyAuthValue function has been called
	// on the session associated with Context. If Context corresponds to a policy session and TPMContext.PolicyPassword has been
	// executed on it, the value of AuthValue will be included in cleartext in the HMAC field of the generated command authorization.
	// In both of these cases, AuthValue must match the authorization value of the resource for which the session is being used to
	// provide authorization for.
	//
	// If the Attrs field has the AttrCommandEncrypt or AttrResponseEncrypt flags set and the session is also being used to provide
	// authorization, then the authorization value of the resource for which the session is providing authorization is included in
	// the derivation of the symmetric key. In this case, AuthValue must match the authorization value of the resource for which this
	// session is providing authorization and cannot be omitted, even if the session is bound to the resource for which it is providing
	// an authorization.
	AuthValue []byte

	Attrs SessionAttributes // Session usage attributes

	includeAuthValue bool
}

func (s *Session) WithAuthValue(authValue []byte) *Session {
	return &Session{Context: s.Context, AuthValue: authValue, Attrs: s.Attrs}
}

func (s *Session) WithAttrs(attrs SessionAttributes) *Session {
	return &Session{Context: s.Context, AuthValue: s.AuthValue, Attrs: attrs}
}

func (s *Session) AddAttrs(attrs SessionAttributes) *Session {
	return &Session{Context: s.Context, AuthValue: s.AuthValue, Attrs: s.Attrs | attrs}
}

func (s *Session) RemoveAttrs(attrs SessionAttributes) *Session {
	return &Session{Context: s.Context, AuthValue: s.AuthValue, Attrs: s.Attrs &^ attrs}
}

// HandleWithAuth associates a Handle with an authorization, and is provided to TPMContext.RunCommand in the command handle area.
//
// Auth can be one of the following types:
//  * string, []byte, or nil for plaintext password authorization.
//  * *Session for session based authorization (HMAC or policy).
type HandleWithAuth struct {
	Handle Handle
	Auth   interface{}
}

// ResourceWithAuth associates a ResourceContext with an authorization, and is provided to TPMContext.RunCommand in the command handle
// area.
//
// Auth can be one of the following types:
//  * string, []byte, or nil for plaintext password authorization.
//  * *Session for session based authorization (HMAC or policy).
type ResourceWithAuth struct {
	Context ResourceContext
	Auth    interface{}
}

// TODO: Implement commands from the following sections of part 3 of the TPM library spec:
// Section 13 - Duplication Commands
// Section 14 - Asymmetric Primitives
// Section 15 - Symmetric Primitives
// Section 17 - Hash/HMAC/Event Sequences
// Section 19 - Ephemeral EC Keys
// Section 20 - Signing and Signature Verification
// Section 21 - Command Audit
// Section 26 - Miscellaneous Management Functions
// Section 27 - Field Upgrade

// TPMContext is the main entry point by which commands are executed on a TPM device using this package. It communicates with the
// underlying device via a transmission interface, which is an implementation of io.ReadWriteCloser provided to NewTPMContext.
//
// TPMContext maintains some host-side state of TPM resources that are loaded and created by this API, in the form of ResourceContext
// objects that correspond to a TPM resource.
//
// Methods that execute commands on the TPM will return errors where the TPM responds with them. These are in the form of *TPMError,
// *TPMWarning, *TPMHandleError, *TPMSessionError, *TPMParameterError and *TPMVendorError types.
//
// Many methods that execute commands on the TPM require Handle or ResourceContext arguments that correspond to resources on the TPM.
// Where those require authorization, the method also requires a corresponding authorization argument, the type of which is the empty
// interface (in most cases). Valid types for these authorization arguments are:
//  * string, []byte, or nil for plaintext password authorization, where an authorization value is transmitted in cleartext to the
//    TPM.
//  * *Session for session based authorization (HMAC or policy).
//
// Some methods also accept a variable number of optional *Session arguments - these are for sessions that don't provide authorization
// for a corresponding TPM resource. These sessions may be used for session based parameter encryption or (in the future) command
// auditing.
type TPMContext struct {
	tcti             io.ReadWriteCloser
	resources        map[Handle]ResourceContext
	maxSubmissions   uint
	maxNVBufferSize  uint16
	exclusiveSession ResourceContext
}

// Close invalidates all non-permanent ResourceContext instances tracked by this TPMContext and then calls Close on the
// transmission interface.
func (t *TPMContext) Close() error {
	for _, rc := range t.resources {
		t.evictResourceContext(rc)
	}

	if err := t.tcti.Close(); err != nil {
		return &TctiError{"close", err}
	}

	return nil
}

// RunCommandBytes is a low-level interface for executing the command defined by the specified commandCode. It will construct an
// appropriate header, but the caller is responsible for providing the rest of the serialized command structure in commandBytes.
// Valid values for tag are TagNoSessions if the authorization area is empty, else it must be TagSessions.
//
// If successful, this function will return the ResponseCode and StructTag from the response header along with the rest of the
// response structure (everything except for the header). It will not return an error if the TPM responds with an error as long as
// the returned response structure is correctly formed, but will return an error if marshalling of the command header or
// unmarshalling of the response header fails, or the transmission interface returns an error.
func (t *TPMContext) RunCommandBytes(tag StructTag, commandCode CommandCode, commandBytes []byte) (ResponseCode, StructTag, []byte, error) {
	cHeader := commandHeader{tag, 0, commandCode}
	cHeader.CommandSize = uint32(binary.Size(cHeader) + len(commandBytes))

	bytes, err := MarshalToBytes(cHeader, RawBytes(commandBytes))
	if err != nil {
		return 0, 0, nil, wrapMarshallingError(commandCode, "complete command packet", err)
	}

	if _, err := t.tcti.Write(bytes); err != nil {
		return 0, 0, nil, &TctiError{"write", err}
	}

	var rHeader responseHeader
	rHeaderSize := uint32(binary.Size(rHeader))
	rHeaderBytes := make([]byte, rHeaderSize)
	if n, err := io.ReadFull(t.tcti, rHeaderBytes); err != nil {
		if xerrors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("insufficient bytes for response header (got %d, "+
				"expected %d)", n, rHeaderSize)}
		}
		return 0, 0, nil, &TctiError{"read", err}
	}

	if _, err := UnmarshalFromBytes(rHeaderBytes, &rHeader); err != nil {
		panic(fmt.Sprintf("cannot unmarshal response header: %v", err))
	}

	if rHeader.ResponseSize < rHeaderSize {
		return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("invalid responseSize value (%d)", rHeader.ResponseSize)}
	}

	responseBytes := make([]byte, rHeader.ResponseSize-rHeaderSize)
	if n, err := io.ReadFull(t.tcti, responseBytes); err != nil {
		if xerrors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("insufficient bytes for response payload (got %d, "+
				"expected %d)", n, len(responseBytes))}
		}
		return 0, 0, nil, &TctiError{"read", err}
	}

	return rHeader.ResponseCode, rHeader.Tag, responseBytes, nil
}

func (t *TPMContext) runCommandWithoutProcessingResponse(commandCode CommandCode, sessionParams []*sessionParam, resources, params []interface{}) (*cmdContext, error) {
	handles := make([]interface{}, 0, len(resources))
	handleNames := make([]Name, 0, len(resources))

	for i, resource := range resources {
		switch r := resource.(type) {
		case ResourceContext:
			if err := t.checkResourceContextParam(r); err != nil {
				return nil, fmt.Errorf("cannot process ResourceContext for command %s at index %d: %v", commandCode, i, err)
			}
			handles = append(handles, r.Handle())
			handleNames = append(handleNames, r.Name())
		case Handle:
			handles = append(handles, r)
			handleNames = append(handleNames, permanentContext(r).Name())
		case nil:
			handles = append(handles, HandleNull)
			handleNames = append(handleNames, permanentContext(HandleNull).Name())
		default:
			return nil, fmt.Errorf("cannot process command handle parameter for command %s at index %d: invalid type (%s)",
				commandCode, i, reflect.TypeOf(resource))
		}
	}

	if hasDecryptSession(sessionParams) && (len(params) == 0 || !isParamEncryptable(params[0])) {
		return nil, fmt.Errorf("command %s does not support command parameter encryption", commandCode)
	}

	cBytes := new(bytes.Buffer)

	if err := MarshalToWriter(cBytes, handles...); err != nil {
		return nil, wrapMarshallingError(commandCode, "command handles", err)
	}

	cpBytes, err := MarshalToBytes(params...)
	if err != nil {
		return nil, wrapMarshallingError(commandCode, "command parameters", err)
	}

	tag := TagNoSessions
	if len(sessionParams) > 0 {
		tag = TagSessions
		authArea, err := buildCommandAuthArea(t, sessionParams, commandCode, handleNames, cpBytes)
		if err != nil {
			return nil, fmt.Errorf("cannot build command auth area for command %s: %v", commandCode, err)
		}
		if err := MarshalToWriter(cBytes, &authArea); err != nil {
			return nil, wrapMarshallingError(commandCode, "command auth area", err)
		}
	}

	if err := MarshalToWriter(cBytes, RawBytes(cpBytes)); err != nil {
		return nil, wrapMarshallingError(commandCode, "raw command parameter bytes", err)
	}

	var responseCode ResponseCode
	var responseTag StructTag
	var responseBytes []byte

	for tries := uint(1); ; tries++ {
		var err error
		responseCode, responseTag, responseBytes, err = t.RunCommandBytes(tag, commandCode, cBytes.Bytes())
		if err != nil {
			return nil, err
		}

		err = DecodeResponseCode(commandCode, responseCode)
		if err == nil {
			break
		}

		if tries >= t.maxSubmissions {
			return nil, err
		}
		if e, ok := err.(*TPMWarning); !ok || !(e.Code == WarningYielded || e.Code == WarningTesting || e.Code == WarningRetry) {
			return nil, err
		}
	}

	return &cmdContext{
		commandCode:   commandCode,
		sessionParams: sessionParams,
		responseCode:  responseCode,
		responseTag:   responseTag,
		responseBytes: responseBytes}, nil
}

func (t *TPMContext) processResponse(context *cmdContext, handles, params []interface{}) error {
	for i, handle := range handles {
		_, isHandle := handle.(*Handle)
		if !isHandle {
			return fmt.Errorf("cannot process response handle parameter for command %s at index %d: invalid type (%s)",
				context.commandCode, i, reflect.TypeOf(handle))
		}
	}

	buf := bytes.NewReader(context.responseBytes)

	if len(handles) > 0 {
		if err := UnmarshalFromReader(buf, handles...); err != nil {
			return handleUnmarshallingError(context, "response handles", err)
		}
	}

	rpBuf := buf
	var rpBytes []byte

	if context.responseTag == TagSessions {
		var parameterSize uint32
		if err := UnmarshalFromReader(buf, &parameterSize); err != nil {
			return handleUnmarshallingError(context, "parameterSize field", err)
		}
		rpBytes = make([]byte, parameterSize)
		if n, err := io.ReadFull(buf, rpBytes); err != nil {
			if err == io.ErrUnexpectedEOF {
				return &InvalidResponseError{context.commandCode, fmt.Sprintf("insufficient bytes for response parameters (got %d, expected %d)",
					n, parameterSize)}
			}
			return handleUnmarshallingError(context, "response parameters",
				fmt.Errorf("error reading parameters to temporary buffer: %v", err))
		}

		authArea := responseAuthAreaRawSlice{make([]authResponse, len(context.sessionParams))}
		if err := UnmarshalFromReader(buf, &authArea); err != nil {
			return handleUnmarshallingError(context, "response auth area", err)
		}
		if err := processResponseAuthArea(t, authArea.Data, context.sessionParams, context.commandCode, context.responseCode,
			rpBytes); err != nil {
			return &InvalidResponseError{context.commandCode, fmt.Sprintf("cannot process response auth area: %v", err)}
		}

		rpBuf = bytes.NewReader(rpBytes)
	}

	var exclusive ResourceContext
	for _, s := range context.sessionParams {
		if s.session == nil {
			continue
		}
		if s.session.Context.(*sessionContext).exclusive {
			exclusive = s.session.Context
			break
		}
	}
	if exclusive != t.exclusiveSession && (exclusive != nil || isSessionAllowed(context.commandCode)) {
		if t.exclusiveSession != nil {
			t.exclusiveSession.(*sessionContext).exclusive = false
		}
		t.exclusiveSession = exclusive
	}

	if len(params) > 0 {
		if err := UnmarshalFromReader(rpBuf, params...); err != nil {
			return handleUnmarshallingError(context, "response parameters", err)
		}
	}

	if buf.Len() > 0 {
		return &InvalidResponseError{context.commandCode, fmt.Sprintf("response contains %d trailing bytes", buf.Len())}
	}

	return nil
}

// RunCommand is the high-level generic interface for executing the command specified by commandCode. All of the methods on TPMContext
// exported by this package that execute commands on the TPM are essentially wrappers around this function. It takes care of
// marshalling command handles and command parameters, as well as constructing and marshalling the authorization area and choosing
// the correct StructTag value. It takes care of unmarshalling response handles and response parameters, as well as unmarshalling the
// response authorization area and performing checks on the authorization response.
//
// The variable length params argument provides a mechanism for the caller to provide command handles, command parameters, response
// handle pointers and response parameter pointers (in that order), with each group of arguments being separated by the Separator
// sentinel value.
//
// Command handles are provided as Handle or ResourceContext types if they do not require an authorization. For command handles that
// require an authorization, they are provided using the HandleWithAuth type (for a Handle) or the ResourceWithAuth type (for a
// ResourceContext). Both HandleWithAuth and ResourceWithAuth reference the corresponding authorization. If a ResourceContext
// references a non-permanent handle and is not tracked by this TPMContext, then this function will return an error. Providing a nil
// value will automatically by converted to a handle with the value of HandleNull. The Handle type must only be used for permanent
// resources - if the Handle type is used to reference non-permanent resources, then computation of the resource name will be
// incorrect and the correct name is required for the correct computation of session HMACs.
//
// Command parameters are provided as the go equivalent types for the types defined in the TPM Library Specification.
//
// Response handles are provided as pointers to Handle values.
//
// Response parameters are provided as pointers to values of the go equivalent types for the types defined in the TPM Library
// Specification.
//
// If the TPM responds with a warning that indicates the command could not be started and should be retried, this function will
// resubmit the command a finite number of times before returning an error. The maximum number of retries can be set via
// TPMContext.SetMaxSubmissions.
//
// The caller can provide additional sessions that aren't associated with a handle (and therefore not used for authorization) via
// the sessions parameter, for the purposes of command auditing or session based parameter encryption.
//
// In addition to returning an error if any marshalling or unmarshalling fails, or if the transmission backend returns an error,
// this function will also return an error if the TPM responds with any ResponseCode other than Success.
func (t *TPMContext) RunCommand(commandCode CommandCode, sessions []*Session, params ...interface{}) error {
	commandHandles := make([]interface{}, 0, len(params))
	commandParams := make([]interface{}, 0, len(params))
	responseHandles := make([]interface{}, 0, len(params))
	responseParams := make([]interface{}, 0, len(params))
	sessionParams := make([]*sessionParam, 0, 3)

	sentinels := 0
	for _, param := range params {
		if param == Separator {
			sentinels++
			continue
		}

		switch sentinels {
		case 0:
			var err error
			var typeName string
			switch p := param.(type) {
			case HandleWithAuth:
				commandHandles = append(commandHandles, p.Handle)
				sessionParams, err = t.validateAndAppendSessionParam(sessionParams, p)
				typeName = "HandleWithAuth"
			case ResourceWithAuth:
				commandHandles = append(commandHandles, p.Context)
				sessionParams, err = t.validateAndAppendSessionParam(sessionParams, p)
				typeName = "ResourceWithAuth"
			default:
				commandHandles = append(commandHandles, param)
			}
			if err != nil {
				return fmt.Errorf("cannot process %s for command %s at index %d: %v", typeName, commandCode, len(commandHandles), err)
			}
		case 1:
			commandParams = append(commandParams, param)
		case 2:
			responseHandles = append(responseHandles, param)
		case 3:
			responseParams = append(responseParams, param)
		}
	}

	sessionParams, err := t.validateAndAppendSessionParam(sessionParams, sessions)
	if err != nil {
		return fmt.Errorf("cannot process non-auth *Session parameters for command %s: %v", commandCode, err)
	}

	ctx, err := t.runCommandWithoutProcessingResponse(commandCode, sessionParams, commandHandles, commandParams)
	if err != nil {
		return err
	}

	return t.processResponse(ctx, responseHandles, responseParams)
}

// SetMaxSubmissions sets the maximum number of times that RunCommand will attempt to submit a command before failing with an error.
// The default value is 5.
func (t *TPMContext) SetMaxSubmissions(max uint) {
	t.maxSubmissions = max
}

func newTpmContext(tcti io.ReadWriteCloser) *TPMContext {
	r := new(TPMContext)
	r.tcti = tcti
	r.resources = make(map[Handle]ResourceContext)
	r.maxSubmissions = 5

	return r
}

// NewTPMContext creates a new instance of TPMContext, which communicates with the TPM using the transmission interface provided
// via the tcti parameter.
//
// If the tcti parameter is nil, this function will try to autodetect a TPM interface using the following order:
//  * Linux TPM device (/dev/tpmrm0)
//  * Linux TPM device (/dev/tpm0)
//  * TPM simulator (localhost:2321 for the TPM command server and localhost:2322 for the platform server)
// It will return an error if a TPM interface cannot be detected.
//
// If the tcti parameter is not nil, this function never returns an error.
func NewTPMContext(tcti io.ReadWriteCloser) (*TPMContext, error) {
	if tcti == nil {
		for _, path := range []string{"/dev/tpmrm0", "/dev/tpm0"} {
			var err error
			tcti, err = OpenTPMDevice(path)
			if err == nil {
				break
			}
		}
	}
	if tcti == nil {
		tcti, _ = OpenMssim("localhost", 2321, 2322)
	}

	if tcti == nil {
		return nil, errors.New("cannot find TPM interface to auto-open")
	}

	return newTpmContext(tcti), nil
}
