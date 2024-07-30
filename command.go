// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/canonical/go-tpm2/mu"
)

// CommandHeader is the header for a TPM command.
type CommandHeader struct {
	Tag         StructTag
	CommandSize uint32
	CommandCode CommandCode
}

// WriteCommandPacket serializes a complete TPM command packet from the provided arguments
// to the supplied writer. The parameters argument must already be serialized to the TPM
// wire format.
//
// This will return an error if the supplied arguments cannot be represented correctly
// by the TPM wire format.
func WriteCommandPacket(w io.Writer, command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) error {
	header := CommandHeader{CommandCode: command}
	var payload []byte

	switch {
	case len(authArea) > 0:
		header.Tag = TagSessions

		aBytes, err := mu.MarshalToBytes(mu.Raw(authArea))
		if err != nil {
			return fmt.Errorf("cannot marshal authArea: %w", err)
		}
		if int64(len(aBytes)) > math.MaxUint32 {
			return errors.New("authArea is too large")
		}
		payload = mu.MustMarshalToBytes(mu.Raw(handles), uint32(len(aBytes)), mu.Raw(aBytes), mu.Raw(parameters))
	case len(authArea) == 0:
		header.Tag = TagNoSessions

		payload = mu.MustMarshalToBytes(mu.Raw(handles), mu.Raw(parameters))
	}

	if int64(len(payload)) > math.MaxUint32-int64(binary.Size(header)) {
		return errors.New("total payload is too large")
	}

	header.CommandSize = uint32(binary.Size(header) + len(payload))

	_, err := mu.MarshalToWriter(w, header, mu.Raw(payload))
	return err
}

// ReadCommandPacket reads a command packet from the supplied reader, returning the command code,
// handles, auth area and parameters. The parameters will still be in the TPM wire format. The number
// of command handles associated with the command must be supplied by the caller.
func ReadCommandPacket(r io.Reader, numHandles int) (command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte, err error) {
	var header CommandHeader
	if _, err := mu.UnmarshalFromReader(r, &header); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("cannot unmarshal header: %w", err)
	}

	lr := io.LimitReader(r, int64(header.CommandSize)-int64(binary.Size(header)))

	handles = make(HandleList, numHandles)
	if _, err := mu.UnmarshalFromReader(lr, mu.Raw(&handles)); err != nil {
		return 0, nil, nil, nil, fmt.Errorf("cannot unmarshal handles: %w", err)
	}

	switch header.Tag {
	case TagSessions:
		var authSize uint32
		if _, err := mu.UnmarshalFromReader(lr, &authSize); err != nil {
			return 0, nil, nil, nil, fmt.Errorf("cannot unmarshal auth area size: %w", err)
		}
		// TODO: Make mu.UnmarshalFromReader return io.EOF when no bytes are read instead.
		alr := &io.LimitedReader{R: lr, N: int64(authSize)}
		for alr.N > 0 {
			var auth AuthCommand
			if _, err := mu.UnmarshalFromReader(alr, &auth); err != nil {
				return 0, nil, nil, nil, fmt.Errorf("cannot unmarshal auth at index %d: %w", len(authArea), err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
	default:
		return 0, nil, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	parameters, err = io.ReadAll(lr)
	if err != nil {
		return 0, nil, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
	}

	return header.CommandCode, handles, authArea, parameters, nil
}

// CommandPacket corresponds to a complete command packet including header and payload.
//
// Deprecated: use [ReadCommandPacket].
type CommandPacket []byte

// GetCommandCode returns the command code contained within this packet.
//
// Deprecated: just supply a [CommandHeader] to [mu.UnmarshalFromBytes] or
// [mu.UnmarshalFromReader].
func (p CommandPacket) GetCommandCode() (CommandCode, error) {
	var header CommandHeader
	if _, err := mu.UnmarshalFromBytes(p, &header); err != nil {
		return 0, fmt.Errorf("cannot unmarshal header: %w", err)
	}
	return header.CommandCode, nil
}

// Unmarshal unmarshals this command packet, returning the handles, auth area and parameters. The
// parameters will still be in the TPM wire format. The number of command handles associated with
// the command must be supplied by the caller.
//
// Deprecated: use [ReadCommandPacket].
func (p CommandPacket) Unmarshal(numHandles int) (handles HandleList, authArea []AuthCommand, parameters []byte, err error) {
	r := bytes.NewReader(p)

	_, handles, authArea, parameters, err = ReadCommandPacket(r, numHandles)
	if err != nil {
		return nil, nil, nil, err
	}

	if r.Len() > 0 {
		return nil, nil, nil, errors.New("trailing bytes")
	}

	return handles, authArea, parameters, nil
}

// MarshalCommandPacket serializes a complete TPM packet from the provided arguments. The
// parameters argument must already be serialized to the TPM wire format.
//
// This will return an error if the supplied parameters cannot be represented correctly
// by the TPM wire format.
func MarshalCommandPacket(command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) (CommandPacket, error) {
	buf := new(bytes.Buffer)
	if err := WriteCommandPacket(buf, command, handles, authArea, parameters); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// MustMarshalCommandPacket serializes a complete TPM packet from the provided arguments.
// The parameters argument must already be serialized to the TPM wire format.
//
// This will panic if the supplied parameters cannot be represented correctly by the TPM
// wire format.
func MustMarshalCommandPacket(commandCode CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) CommandPacket {
	b, err := MarshalCommandPacket(commandCode, handles, authArea, parameters)
	if err != nil {
		panic(err)
	}
	return b
}

// ResponseHeader is the header for the TPM's response to a command.
type ResponseHeader struct {
	Tag          StructTag
	ResponseSize uint32
	ResponseCode ResponseCode
}

// ReadResponsePacket reads a response packet from the supplied reader, returning the response code,
// parameters, and auth area. The parameters will still be in the TPM wire format. The response handle
// will be written to the memory pointed to by the supplied handle argument if provided.
func ReadResponsePacket(r io.Reader, handle *Handle) (rc ResponseCode, parameters []byte, authArea []AuthResponse, err error) {
	var header ResponseHeader
	if _, err := mu.UnmarshalFromReader(r, &header); err != nil {
		return 0, nil, nil, fmt.Errorf("cannot unmarshal header: %w", err)
	}

	switch header.Tag {
	case TagRspCommand:
		// Only valid with the response code TPM_RC_BAD_TAG, expected from TPM1.2 devices in
		// response to receiving a TPM2 device with an unrecognized tag.
		if header.ResponseCode != ResponseBadTag {
			return 0, nil, nil, fmt.Errorf("received error for response with tag TPM_ST_RSP_COMMAND: %w", InvalidResponseCodeError(header.ResponseCode))
		}
	case TagSessions:
		if header.ResponseCode != ResponseSuccess {
			// All error responses have the TPM_ST_NO_SESSIONS tag
			return 0, nil, nil, fmt.Errorf("received error for response with tag TPM_ST_SESSIONS: %w", InvalidResponseCodeError(header.ResponseCode))
		}
	case TagNoSessions:
		if header.ResponseCode != ResponseSuccess && header.ResponseSize != uint32(binary.Size(header)) {
			return 0, nil, nil, fmt.Errorf("invalid response size for unsuccessful response (%d)", header.ResponseSize)
		}
	default:
		return 0, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	// TODO: Make mu.UnmarshalFromReader return io.EOF when no bytes are read instead.
	lr := &io.LimitedReader{R: r, N: int64(header.ResponseSize) - int64(binary.Size(header))}

	switch header.Tag {
	case TagSessions, TagNoSessions:
		if header.ResponseCode == ResponseSuccess && handle != nil {
			// Read the response handle in the case of success and where a handle is expected
			if _, err := mu.UnmarshalFromReader(lr, handle); err != nil {
				return 0, nil, nil, fmt.Errorf("cannot unmarshal handle: %w", err)
			}
		}
	default:
	}

	switch header.Tag {
	case TagRspCommand:
	case TagSessions:
		var parameterSize uint32
		if _, err := mu.UnmarshalFromReader(lr, &parameterSize); err != nil {
			return 0, nil, nil, fmt.Errorf("cannot unmarshal parameterSize: %w", err)
		}

		parameters = make([]byte, parameterSize)
		if _, err := io.ReadFull(lr, parameters); err != nil {
			return 0, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
		}

		for lr.N > 0 {
			var auth AuthResponse
			if _, err := mu.UnmarshalFromReader(lr, &auth); err != nil {
				return 0, nil, nil, fmt.Errorf("cannot unmarshal auth at index %d: %w", len(authArea), err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
		parameters, err = io.ReadAll(lr)
		if err != nil || lr.N > 0 {
			if err == nil {
				err = io.ErrUnexpectedEOF
			}
			return 0, nil, nil, fmt.Errorf("cannot read parameters: %w", err)
		}
	}

	return header.ResponseCode, parameters, authArea, nil
}

// WriteResponsePacket serializes a complete TPM response packet from the provided arguments
// to the supplied writer. The parameters argument must already be serialized to the TPM
// wire format. If handle is nil, then no response handle is serialized.
//
// This will return an error if the supplied arguments cannot be represented correctly
// by the TPM wire format.
//
// This will return an error if the supplied arguments are inconsistent, eg, an error
// response code with a non-zero parameters length or non-zero authArea length.
func WriteResponsePacket(w io.Writer, rc ResponseCode, handle *Handle, parameters []byte, authArea []AuthResponse) error {
	header := ResponseHeader{ResponseCode: rc}

	switch {
	case rc == ResponseBadTag && len(authArea) == 0:
		// This is any response expected from a TPM1.2 device in response to a TPM2 command because of the invalid command tag
		header.Tag = TagRspCommand
	case rc != ResponseSuccess && len(authArea) == 0:
		// Any other non-success response
		header.Tag = TagNoSessions
	case rc == ResponseSuccess && len(authArea) == 0:
		// Success response without sessions
		header.Tag = TagNoSessions
	case rc == ResponseSuccess && len(authArea) > 0:
		// Success response with sessions
		header.Tag = TagSessions
	default:
		return errors.New("inconsistent ResponseCode and authArea arguments")
	}

	payload := new(bytes.Buffer)

	if rc != ResponseSuccess {
		if len(parameters) > 0 {
			// Error responses don't have parameters
			return errors.New("inconsistent ResponseCode and parameters arguments")
		}
		header.ResponseSize = uint32(binary.Size(header))
		return nil
	}

	// This is a success response.
	// Serialize the response handle if provided.
	if handle != nil {
		mu.MustMarshalToWriter(payload, handle)
	}

	switch header.Tag {
	case TagNoSessions:
		if _, err := payload.Write(parameters); err != nil {
			panic(fmt.Errorf("cannot write parameters: %w", err))
		}
	case TagSessions:
		if int64(len(parameters)) > math.MaxUint32 {
			return errors.New("parameter area is too large")
		}
		mu.MustMarshalToWriter(payload, uint32(len(parameters)))
		if _, err := payload.Write(parameters); err != nil {
			panic(fmt.Errorf("cannot write parameters: %w", err))
		}
		if _, err := mu.MarshalToWriter(payload, mu.Raw(authArea)); err != nil {
			return fmt.Errorf("cannot marshal authArea: %w", err)
		}
	}

	if int64(payload.Len()) > math.MaxUint32-int64(binary.Size(header)) {
		return errors.New("total payload is too large")
	}

	header.ResponseSize = uint32(binary.Size(header) + payload.Len())

	_, err := mu.MarshalToWriter(w, header, mu.Raw(payload.Bytes()))
	return err
}

// ResponsePacket corresponds to a complete response packet including header and payload.
//
// Deprecated: use [ReadResponsePacket].
type ResponsePacket []byte

// Unmarshal deserializes the response packet and returns the response code, handle, parameters
// and auth area. The parameters will still be in the TPM wire format. The caller supplies a
// pointer to which the response handle will be written. The pointer must be supplied if the
// command returns a handle, and must be nil if the command does not return a handle, else
// the response will be incorrectly unmarshalled.
//
// Deprecated: use [ReadResponsePacket].
func (p ResponsePacket) Unmarshal(handle *Handle) (rc ResponseCode, parameters []byte, authArea []AuthResponse, err error) {
	r := bytes.NewReader(p)

	rc, parameters, authArea, err = ReadResponsePacket(r, handle)
	if err != nil {
		return 0, nil, nil, err
	}

	if r.Len() > 0 {
		return 0, nil, nil, errors.New("trailing bytes")
	}

	return rc, parameters, authArea, nil
}

// CommandHandleContext is used to supply a [HandleContext] to a [CommandContext].
type CommandHandleContext struct {
	handle  HandleContext
	session SessionContext
}

// Handle returns the HandleContext.
func (c *CommandHandleContext) Handle() HandleContext {
	return c.handle
}

// Session returns the SessionContext if the handle requires authorization.
func (c *CommandHandleContext) Session() SessionContext {
	return c.session
}

// UseResourceContextWithAuth creates a CommandHandleContext for a [ResourceContext] that
// requires authorization in a command. The supplied [SessionContext] is the session used for
// authorization and determines the type of authorization used for the specified resource:
//
//   - If SessionContext is nil, then passphrase authorization is used.
//   - If SessionContext is a HMAC session, then HMAC authorization is used.
//   - If SessionContext is a policy session, then policy authorization is used.
//
// If the authorization value of the resource is required as part of the authorization (eg, for
// passphrase authorization, a HMAC session that is not bound to the specified resource, or a
// policy session that contains the TPM2_PolicyPassword or TPM2_PolicyAuthValue assertion), it is
// obtained from the supplied ResourceContext, and should be set by calling
// [ResourceContext].SetAuthValue before the command is executed.
//
// Resources that require authorization will require authorization with one of 3 roles, depending
// on the command: user, admin or duplication. The role determines the required authorization
// type, which is dependent on the type of the resource.
//
// Where a command requires authorization with the user role for a resource, the following
// authorization types are permitted:
//
//   - [HandleTypePCR]: passphrase or HMAC session if no auth policy is set, or a policy session if
//     an auth policy is set.
//   - [HandleTypeNVIndex]: passphrase, HMAC session or policy session depending on attributes.
//   - [HandleTypePermanent]: passphrase or HMAC session. A policy session can also be used if an
//     auth policy is set.
//   - [HandleTypeTransient] / [HandleTypePersistent]: policy session. Passphrase or HMAC session
//     can also be used if AttrWithUserAuth is set.
//
// Where a command requires authorization with the admin role for a resource, the following
// authorization types are permitted:
//
//   - [HandleTypeNVIndex]: policy session.
//   - [HandleTypeTransient] / [HandleTypePersistent]: policy session. Passphrase or HMAC session
//     can also be used if AttrAdminWithPolicy is not set.
//
// Where a command requires authorization with the duplication role for a resource, a policy
// session is required.
//
// Where a policy session is used for a resource that requires authorization with the admin or
// duplication role, the session must contain the TPM2_PolicyCommandCode assertion.
//
// If the ResourceContext is nil, then [HandleNull] is used.
func UseResourceContextWithAuth(r ResourceContext, s SessionContext) *CommandHandleContext {
	if r == nil {
		r = nullResource()
	}
	if s == nil {
		s = pwSession()
	}
	return &CommandHandleContext{handle: r, session: s}
}

// UseHandleContext creates a CommandHandleContext for any [HandleContext] that does not require
// authorization. If the HandleContext is nil, then [HandleNull] is used.
func UseHandleContext(h HandleContext) *CommandHandleContext {
	if h == nil {
		h = nullResource()
	}
	return &CommandHandleContext{handle: h}
}

type commandDispatcher interface {
	RunCommand(c *cmdContext, responseHandle *Handle) (*rspContext, error)
	CompleteResponse(r *rspContext, responseParams ...interface{}) error
}

// CommandContext provides an API for building a command to execute via a [TPMContext].
type CommandContext struct {
	dispatcher commandDispatcher
	cmd        cmdContext
}

// ResponseContext contains the context required to validate a response and obtain response
// parameters.
type ResponseContext struct {
	dispatcher commandDispatcher
	rsp        *rspContext
}

// Complete performs validation of the response auth area and updates internal [SessionContext]
// state. If a response HMAC is invalid, an error will be returned. The caller supplies a command
// dependent number of pointers to the response parameters.
//
// If a SessionContext supplied to the original [CommandContext] has the [AttrResponseEncrypt]
// attribute set, then the first response parameter will be decrypted using the properties of that
// SessionContext.
func (c *ResponseContext) Complete(responseParams ...interface{}) error {
	return c.dispatcher.CompleteResponse(c.rsp, responseParams...)
}

// AddHandles appends the supplied command handle contexts to this command.
func (c *CommandContext) AddHandles(handles ...*CommandHandleContext) *CommandContext {
	c.cmd.Handles = append(c.cmd.Handles, handles...)
	return c
}

// AddParams appends the supplied command parameters to this command.
func (c *CommandContext) AddParams(params ...interface{}) *CommandContext {
	c.cmd.Params = append(c.cmd.Params, params...)
	return c
}

// AddExtraSessions adds the supplied additional session contexts to this command. These sessions
// are not used for authorization of any resources, but can be used for command or response
// parameter encryption, or command auditing.
func (c *CommandContext) AddExtraSessions(sessions ...SessionContext) *CommandContext {
	c.cmd.ExtraSessions = append(c.cmd.ExtraSessions, sessions...)
	return c
}

// RunWithoutProcessingResponse executes the command defined by this context using the [TPMContext]
// that created it. The caller supplies a pointer to the response handle if the command returns
// one.
//
// If a [SessionContext] used for this command has the [AttrCommandEncrypt] attribute set, then the
// first command parameter will be encrypted using the properties of that SessionContext.
//
// If the TPM returns a response indicating that the command should be retried, this function will
// retry up to a maximum number of times defined by the number supplied to
// [TPMContext.SetMaxSubmissions].
//
// This performs no validation of the response auth area. Instead, a ResponseContext is returned
// and the caller is expected to call [ResponseContext.Complete]. This is useful for commands that
// change an authorization value, where the response HMAC is computed with a key based on the new
// value.
//
// A *[TransportError] will be returned if the transmission interface returns an error.
//
// One of *[TPMWarning], *[TPMError], *[TPMParameterError], *[TPMHandleError] or *[TPMSessionError]
// will be returned if the TPM returns a response code other than [ResponseSuccess].
func (c *CommandContext) RunWithoutProcessingResponse(responseHandle *Handle) (*ResponseContext, error) {
	r, err := c.dispatcher.RunCommand(&c.cmd, responseHandle)
	if err != nil {
		return nil, err
	}
	return &ResponseContext{
		dispatcher: c.dispatcher,
		rsp:        r}, nil
}

// Run executes the command defined by this context using the [TPMContext] that created it. The
// caller supplies a pointer to the response handle if the command returns one, and a command
// dependent number of pointers to response parameters.
//
// If a [SessionContext] used for this command has the [AttrCommandEncrypt] attribute set, then
// the first command parameter will be encrypted using the properties of that SessionContext.
//
// If a SessionContext used for this command has the [AttrResponseEncrypt] attribute set, then the
// first response parameter will be decrypted using the properties of that SessionContext.
//
// If the TPM returns a response indicating that the command should be retried, this function will
// retry up to a maximum number of times defined by the number supplied to
// [TPMContext.SetMaxSubmissions].
//
// This performs validation of the response auth area and updates internal SessionContext state.
// If a response HMAC is invalid, an error will be returned.
//
// A *[TransportError] will be returned if the transmission interface returns an error.
//
// One of *[TPMWarning], *[TPMError], *[TPMParameterError], *[TPMHandleError] or *[TPMSessionError]
// will be returned if the TPM returns a response code other than [ResponseSuccess].
func (c *CommandContext) Run(responseHandle *Handle, responseParams ...interface{}) error {
	r, err := c.RunWithoutProcessingResponse(responseHandle)
	if err != nil {
		return err
	}
	return r.Complete(responseParams...)
}
