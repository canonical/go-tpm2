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

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

func makeInvalidArgError(name, msg string) error {
	return fmt.Errorf("invalid %s argument: %s", name, msg)
}

func wrapMarshallingError(commandCode CommandCode, context string, err error) error {
	return fmt.Errorf("cannot marshal %s for command %s: %v", context, commandCode, err)
}

func handleUnmarshallingError(commandCode CommandCode, context string, err error) error {
	var s *mu.InvalidSelectorError
	if xerrors.Is(err, io.EOF) || xerrors.Is(err, io.ErrUnexpectedEOF) || xerrors.As(err, &s) {
		return &InvalidResponseError{commandCode, fmt.Sprintf("cannot unmarshal %s: %v", context, err)}
	}

	return fmt.Errorf("cannot unmarshal %s for command %s: %v", context, commandCode, err)
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
	commandCode      CommandCode
	sessionParams    *sessionParams
	responseCode     ResponseCode
	responseTag      StructTag
	responseAuthArea []authResponse
	rpBytes          []byte
}

type delimiterSentinel struct{}

// Delimiter is a sentinel value used to delimit command handle, command parameter, response handle pointer and response
// parameter pointer blocks in the variable length params argument in TPMContext.RunCommand.
var Delimiter delimiterSentinel

// ResourceContextWithAuth associates a ResourceContext with a session for authorization, and is provided to TPMContext.RunCommand in
// the command handle area for any handles that require an authorization.
type ResourceContextWithSession struct {
	Context ResourceContext
	Session SessionContext
}

// TODO: Implement commands from the following sections of part 3 of the TPM library spec:
// Section 14 - Asymmetric Primitives
// Section 15 - Symmetric Primitives
// Section 17 - Hash/HMAC/Event Sequences
// Section 19 - Ephemeral EC Keys
// Section 26 - Miscellaneous Management Functions
// Section 27 - Field Upgrade

// TPMContext is the main entry point by which commands are executed on a TPM device using this package. It communicates with the
// underlying device via a transmission interface, which is an implementation of io.ReadWriteCloser provided to NewTPMContext.
//
// Methods that execute commands on the TPM will return errors where the TPM responds with them. These are in the form of *TPMError,
// *TPMWarning, *TPMHandleError, *TPMSessionError, *TPMParameterError and *TPMVendorError types.
//
// Some methods also accept a variable number of optional SessionContext arguments - these are for sessions that don't provide
// authorization for a corresponding TPM resource. These sessions may be used for the purposes of session based parameter encryption
// or command auditing.
type TPMContext struct {
	tcti                  TCTI
	permanentResources    map[Handle]*permanentContext
	maxSubmissions        uint
	propertiesInitialized bool
	maxBufferSize         int
	maxDigestSize         int
	maxNVBufferSize       int
	exclusiveSession      *sessionContext
}

// Close calls Close on the transmission interface.
func (t *TPMContext) Close() error {
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

	cmd := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(cmd, cHeader, mu.RawBytes(commandBytes)); err != nil {
		panic(fmt.Sprintf("cannot marshal complete command packet bytes: %v", err))
	}

	if _, err := cmd.WriteTo(t.tcti); err != nil {
		return 0, 0, nil, &TctiError{"write", err}
	}

	var rHeader responseHeader
	rHeaderSize := uint32(binary.Size(rHeader))
	if n, err := mu.UnmarshalFromReader(t.tcti, &rHeader); err != nil {
		if xerrors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("insufficient bytes for response header (got %d, expected %d)", n, rHeaderSize)}
		}
		return 0, 0, nil, &TctiError{"read", err}
	}

	if rHeader.ResponseSize < rHeaderSize {
		return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("invalid responseSize value (%d)", rHeader.ResponseSize)}
	}

	responseBytes := make([]byte, rHeader.ResponseSize-rHeaderSize)
	if n, err := io.ReadFull(t.tcti, responseBytes); err != nil {
		if xerrors.Is(err, io.ErrUnexpectedEOF) {
			return 0, 0, nil, &InvalidResponseError{commandCode, fmt.Sprintf("insufficient bytes for response payload (got %d, expected %d)", n, len(responseBytes))}
		}
		return 0, 0, nil, &TctiError{"read", err}
	}

	return rHeader.ResponseCode, rHeader.Tag, responseBytes, nil
}

func (t *TPMContext) runCommandWithoutProcessingAuthResponse(commandCode CommandCode, sessionParams *sessionParams, resources, params, outHandles []interface{}) (*cmdContext, error) {
	handles := make([]interface{}, 0, len(resources))
	handleNames := make([]Name, 0, len(resources))

	for i, resource := range resources {
		switch r := resource.(type) {
		case HandleContext:
			if r == nil {
				handles = append(handles, HandleNull)
				handleNames = append(handleNames, makeDummyContext(HandleNull).Name())
			} else {
				handles = append(handles, r.Handle())
				handleNames = append(handleNames, r.Name())
			}
		case nil:
			handles = append(handles, HandleNull)
			handleNames = append(handleNames, makeDummyContext(HandleNull).Name())
		default:
			return nil, fmt.Errorf("cannot process command handle context parameter for command %s at index %d: invalid type (%s)", commandCode, i, reflect.TypeOf(resource))
		}
	}

	for i, handle := range outHandles {
		_, isHandle := handle.(*Handle)
		if !isHandle {
			return nil, fmt.Errorf("cannot process response handle parameter for command %s at index %d: invalid type (%s)", commandCode, i, reflect.TypeOf(handle))
		}
	}

	if sessionParams.hasDecryptSession() && (len(params) == 0 || !isParamEncryptable(params[0])) {
		return nil, fmt.Errorf("command %s does not support command parameter encryption", commandCode)
	}

	cBytes := new(bytes.Buffer)

	if _, err := mu.MarshalToWriter(cBytes, handles...); err != nil {
		panic(fmt.Sprintf("cannot marshal command handles: %v", err))
	}

	cpBytes := new(bytes.Buffer)
	if _, err := mu.MarshalToWriter(cpBytes, params...); err != nil {
		return nil, xerrors.Errorf("cannot marshal command parameters for command %s: %w", commandCode, err)
	}

	tag := TagNoSessions
	if len(sessionParams.sessions) > 0 {
		tag = TagSessions
		authArea, err := sessionParams.buildCommandAuthArea(commandCode, handleNames, cpBytes.Bytes())
		if err != nil {
			return nil, xerrors.Errorf("cannot build command auth area for command %s: %w", commandCode, err)
		}
		if _, err := mu.MarshalToWriter(cBytes, &authArea); err != nil {
			panic(fmt.Sprintf("cannot marshal command auth area: %v", err))
		}
	}

	if _, err := cpBytes.WriteTo(cBytes); err != nil {
		panic(fmt.Sprintf("cannot write command parameter bytes to command buffer: %v", err))
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

	buf := bytes.NewReader(responseBytes)

	if len(outHandles) > 0 {
		if _, err := mu.UnmarshalFromReader(buf, outHandles...); err != nil {
			return nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot unmarshal response handles: %v", err)}
		}
	}

	var authArea responseAuthAreaRawSlice
	var rpBytes []byte

	switch responseTag {
	case TagSessions:
		var parameterSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &parameterSize); err != nil {
			return nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot unmarshal response parameterSize: %v", err)}
		}
		rpBytes = make([]byte, parameterSize)
		if _, err := io.ReadFull(buf, rpBytes); err != nil {
			return nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot read response parameter area: %v", err)}
		}

		authArea.Data = make([]authResponse, len(sessionParams.sessions))
		if _, err := mu.UnmarshalFromReader(buf, &authArea); err != nil {
			return nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot unmarshal response auth area: %v", err)}
		}
	case TagNoSessions:
		rpBytes = make([]byte, buf.Len())
		if _, err := io.ReadFull(buf, rpBytes); err != nil {
			return nil, &InvalidResponseError{commandCode, fmt.Sprintf("cannot read response parameter area: %v", err)}
		}
	default:
		return nil, &InvalidResponseError{commandCode, fmt.Sprintf("unexpected response tag: %v", responseTag)}
	}

	if buf.Len() > 0 {
		return nil, &InvalidResponseError{commandCode, fmt.Sprintf("response payload contains %d trailing bytes", buf.Len())}
	}

	return &cmdContext{
		commandCode:      commandCode,
		sessionParams:    sessionParams,
		responseCode:     responseCode,
		responseTag:      responseTag,
		responseAuthArea: authArea.Data,
		rpBytes:          rpBytes}, nil
}

func (t *TPMContext) processAuthResponse(cmd *cmdContext, params []interface{}) error {
	if cmd.responseTag == TagSessions {
		if err := cmd.sessionParams.processResponseAuthArea(cmd.responseAuthArea, cmd.responseCode, cmd.rpBytes); err != nil {
			return &InvalidResponseError{cmd.commandCode, fmt.Sprintf("cannot process response auth area: %v", err)}
		}
	}

	if isSessionAllowed(cmd.commandCode) {
		if t.exclusiveSession != nil {
			t.exclusiveSession.Data().IsExclusive = false
		}
		var exclusive *sessionContext
		for _, s := range cmd.sessionParams.sessions {
			if s.session == nil {
				continue
			}
			if s.session.Data().IsExclusive {
				exclusive = s.session
				break
			}
		}
		t.exclusiveSession = exclusive
		if t.exclusiveSession != nil {
			t.exclusiveSession.Data().IsExclusive = true
		}
	}

	rpBuf := bytes.NewReader(cmd.rpBytes)

	if len(params) > 0 {
		if _, err := mu.UnmarshalFromReader(rpBuf, params...); err != nil {
			return &InvalidResponseError{cmd.commandCode, fmt.Sprintf("cannot unmarshal response parameters: %v", err)}
		}
	}

	if rpBuf.Len() > 0 {
		return &InvalidResponseError{cmd.commandCode, fmt.Sprintf("response parameter area contains %d trailing bytes", rpBuf.Len())}
	}

	return nil
}

// RunCommandWithResponseCallback is a high-level generic interface for executing the command specified by commandCode. It differs
// from RunCommand with the addition of an optional callback which is executed after receiving a response from the TPM, but before
// the response is decoded and the session state is updated. This is useful for commands that change the authorization value of a
// supplied entity, where the response HMAC may be generated based on the new authorization value. It takes care of marshalling
// command handles and command parameters, as well as constructing and marshalling the authorization area and choosing the correct
// StructTag value. It takes care of unmarshalling response handles and response parameters, as well as unmarshalling the response
// authorization area and performing checks on the authorization response.
//
// The variable length params argument provides a mechanism for the caller to provide command handles, command parameters, response
// handle pointers and response parameter pointers (in that order), with each group of arguments being separated by the Delimiter
// sentinel value.
//
// Command handles are provided as HandleContext types if they do not require an authorization. For command handles that require an
// authorization, they are provided using the ResourceContextWithSession type. This links the ResourceContext to an optional
// authorization session. If the authorization value of the TPM entity is required as part of the authorization, this will be obtained
// from the supplied ResourceContext. A nil HandleContext will automatically be converted to a handle with the value of HandleNull.
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
// The caller can provide additional sessions that aren't associated with a TPM entity (and therefore not used for authorization) via
// the sessions parameter, for the purposes of command auditing or session based parameter encryption.
//
// In addition to returning an error if any marshalling or unmarshalling fails, or if the transmission backend returns an error,
// this function will also return an error if the TPM responds with any ResponseCode other than Success.
func (t *TPMContext) RunCommandWithResponseCallback(commandCode CommandCode, sessions []SessionContext, responseCb func(), params ...interface{}) error {
	var commandHandles []interface{}
	var commandParams []interface{}
	var responseHandles []interface{}
	var responseParams []interface{}
	var sessionParams sessionParams

	sentinels := 0
	for _, param := range params {
		if param == Delimiter {
			sentinels++
			continue
		}

		switch sentinels {
		case 0:
			switch p := param.(type) {
			case ResourceContextWithSession:
				commandHandles = append(commandHandles, p.Context)
				if err := sessionParams.validateAndAppendAuth(p); err != nil {
					return fmt.Errorf("cannot process ResourceContextWithSession for command %s at index %d: %v", commandCode, len(commandHandles), err)
				}
			default:
				commandHandles = append(commandHandles, param)
			}
		case 1:
			commandParams = append(commandParams, param)
		case 2:
			responseHandles = append(responseHandles, param)
		case 3:
			responseParams = append(responseParams, param)
		}
	}

	if err := sessionParams.validateAndAppendExtra(sessions); err != nil {
		return fmt.Errorf("cannot process non-auth SessionContext parameters for command %s: %v", commandCode, err)
	}

	ctx, err := t.runCommandWithoutProcessingAuthResponse(commandCode, &sessionParams, commandHandles, commandParams, responseHandles)
	if err != nil {
		return err
	}

	if responseCb != nil {
		responseCb()
	}

	return t.processAuthResponse(ctx, responseParams)
}

// RunCommand is the high-level generic interface for executing the command specified by commandCode. All of the methods on TPMContext
// exported by this package that execute commands on the TPM are essentially wrappers around this function. It takes care of
// marshalling command handles and command parameters, as well as constructing and marshalling the authorization area and choosing
// the correct StructTag value. It takes care of unmarshalling response handles and response parameters, as well as unmarshalling the
// response authorization area and performing checks on the authorization response.
//
// The variable length params argument provides a mechanism for the caller to provide command handles, command parameters, response
// handle pointers and response parameter pointers (in that order), with each group of arguments being separated by the Delimiter
// sentinel value.
//
// Command handles are provided as HandleContext types if they do not require an authorization. For command handles that require an
// authorization, they are provided using the ResourceContextWithSession type. This links the ResourceContext to an optional
// authorization session. If the authorization value of the TPM entity is required as part of the authorization, this will be obtained
// from the supplied ResourceContext. A nil HandleContext will automatically be converted to a handle with the value of HandleNull.
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
// The caller can provide additional sessions that aren't associated with a TPM entity (and therefore not used for authorization) via
// the sessions parameter, for the purposes of command auditing or session based parameter encryption.
//
// In addition to returning an error if any marshalling or unmarshalling fails, or if the transmission backend returns an error,
// this function will also return an error if the TPM responds with any ResponseCode other than Success.
func (t *TPMContext) RunCommand(commandCode CommandCode, sessions []SessionContext, params ...interface{}) error {
	return t.RunCommandWithResponseCallback(commandCode, sessions, nil, params...)
}

// SetMaxSubmissions sets the maximum number of times that RunCommand will attempt to submit a command before failing with an error.
// The default value is 5.
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
		case PropertyInputBuffer:
			t.maxBufferSize = int(prop.Value)
		case PropertyMaxDigest:
			t.maxDigestSize = int(prop.Value)
		case PropertyNVBufferMax:
			t.maxNVBufferSize = int(prop.Value)
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
func NewTPMContext(tcti TCTI) (*TPMContext, error) {
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
