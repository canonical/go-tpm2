// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

const (
	maxResponseSize int = 4096
)

// CommandHeader is the header for a TPM command.
type CommandHeader struct {
	Tag         StructTag
	CommandSize uint32
	CommandCode CommandCode
}

// CommandPacket corresponds to a complete command packet including header and payload.
type CommandPacket []byte

// GetCommandCode returns the command code contained within this packet.
func (p CommandPacket) GetCommandCode() (CommandCode, error) {
	var header CommandHeader
	if _, err := mu.UnmarshalFromBytes(p, &header); err != nil {
		return 0, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	return header.CommandCode, nil
}

// Unmarshal unmarshals this command packet, returning the handles, auth area and
// parameters. The parameters will still be in the TPM wire format. The number of command
// handles associated with the command must be supplied by the caller.
func (p CommandPacket) Unmarshal(numHandles int) (handles HandleList, authArea []AuthCommand, parameters []byte, err error) {
	buf := bytes.NewReader(p)

	var header CommandHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	if header.CommandSize != uint32(len(p)) {
		return nil, nil, nil, fmt.Errorf("invalid commandSize value (got %d, packet length %d)", header.CommandSize, len(p))
	}

	handles = make(HandleList, numHandles)
	if _, err := mu.UnmarshalFromReader(buf, mu.Raw(&handles)); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot unmarshal handles: %w", err)
	}

	switch header.Tag {
	case TagSessions:
		var authSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &authSize); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot unmarshal auth area size: %w", err)
		}
		r := &io.LimitedReader{R: buf, N: int64(authSize)}
		for r.N > 0 {
			if len(authArea) >= 3 {
				return nil, nil, nil, fmt.Errorf("%d trailing byte(s) in auth area", r.N)
			}

			var auth AuthCommand
			if _, err := mu.UnmarshalFromReader(r, &auth); err != nil {
				return nil, nil, nil, xerrors.Errorf("cannot unmarshal auth: %w", err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
	default:
		return nil, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	parameters, err = ioutil.ReadAll(buf)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
	}

	return handles, authArea, parameters, nil
}

// MarshalCommandPacket serializes a complete TPM packet from the provided arguments. The
// parameters argument must already be serialized to the TPM wire format.
func MarshalCommandPacket(command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) CommandPacket {
	header := CommandHeader{CommandCode: command}
	var payload mu.RawBytes

	switch {
	case len(authArea) > 0:
		header.Tag = TagSessions

		aBytes := mu.MustMarshalToBytes(mu.Raw(authArea))
		payload = mu.MustMarshalToBytes(mu.Raw(handles), uint32(len(aBytes)), mu.RawBytes(aBytes), mu.RawBytes(parameters))
	case len(authArea) == 0:
		header.Tag = TagNoSessions

		payload = mu.MustMarshalToBytes(mu.Raw(handles), mu.RawBytes(parameters))
	}

	header.CommandSize = uint32(binary.Size(header) + len(payload))

	return mu.MustMarshalToBytes(header, payload)
}

// ResponseHeader is the header for the TPM's response to a command.
type ResponseHeader struct {
	Tag          StructTag
	ResponseSize uint32
	ResponseCode ResponseCode
}

// ResponsePacket corresponds to a complete response packet including header and payload.
type ResponsePacket []byte

// Unmarshal deserializes the response packet and returns the response code, handle, parameters
// and auth area. The parameters will still be in the TPM wire format. The caller supplies a
// pointer to which the response handle will be written. The pointer must be supplied if the
// command returns a handle, and must be nil if the command does not return a handle, else
// the response will be incorrectly unmarshalled.
func (p ResponsePacket) Unmarshal(handle *Handle) (rc ResponseCode, parameters []byte, authArea []AuthResponse, err error) {
	if len(p) > maxResponseSize {
		return 0, nil, nil, fmt.Errorf("packet too large (%d bytes)", len(p))
	}

	buf := bytes.NewReader(p)

	var header ResponseHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return 0, nil, nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	if header.ResponseSize != uint32(buf.Size()) {
		return 0, nil, nil, fmt.Errorf("invalid responseSize value (got %d, packet length %d)", header.ResponseSize, len(p))
	}

	if header.ResponseCode != ResponseSuccess && buf.Len() != 0 {
		return header.ResponseCode, nil, nil, fmt.Errorf("%d trailing byte(s) in unsuccessful response", buf.Len())
	}

	switch header.Tag {
	case TagRspCommand:
		if header.ResponseCode != ResponseBadTag {
			return 0, nil, nil, fmt.Errorf("unexpected TPM1.2 response code 0x%08x", header.ResponseCode)
		}
	case TagSessions:
		if header.ResponseCode != ResponseSuccess {
			return 0, nil, nil, fmt.Errorf("unexpcted response code 0x%08x for TPM_ST_SESSIONS response", header.ResponseCode)
		}
		fallthrough
	case TagNoSessions:
		if header.ResponseCode == ResponseSuccess && handle != nil {
			if _, err := mu.UnmarshalFromReader(buf, handle); err != nil {
				return 0, nil, nil, xerrors.Errorf("cannot unmarshal handle: %w", err)
			}
		}
	default:
		return 0, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	switch header.Tag {
	case TagRspCommand:
	case TagSessions:
		var parameterSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &parameterSize); err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot unmarshal parameterSize: %w", err)
		}

		parameters = make([]byte, parameterSize)
		if _, err := io.ReadFull(buf, parameters); err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
		}

		for buf.Len() > 0 {
			if len(authArea) >= 3 {
				return 0, nil, nil, fmt.Errorf("%d trailing byte(s)", buf.Len())
			}

			var auth AuthResponse
			if _, err := mu.UnmarshalFromReader(buf, &auth); err != nil {
				return 0, nil, nil, xerrors.Errorf("cannot unmarshal auth: %w", err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
		parameters, err = ioutil.ReadAll(buf)
		if err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
		}
	}

	return header.ResponseCode, parameters, authArea, nil
}

// CommandHandleContext is used to supply a HandleContext to a CommandContext.
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

// UseResourceContextWithAuth creates a CommandHandleContext for a ResourceContext that
// requires authorization. The supplied SessionContext is the session used for authorization
// and may be nil - in this case, passphrase authorization is used. If the authorization
// value of the resource is required as part of the authorization, it is obtained from
// the supplied ResourceContext, and should be set by calling ResourceContext.SetAuthValue.
// If the ResourceContext is nil, then HandleNull is used.
func UseResourceContextWithAuth(r ResourceContext, s SessionContext) *CommandHandleContext {
	if r == nil {
		r = nullContext
	}
	if s == nil {
		s = pwSession
	}
	return &CommandHandleContext{handle: r, session: s}
}

// UseHandleContext creates a CommandHandleContext for any HandleContext that does not
// require authorization. If the HandleContext is nil, then HandleNull is used.
func UseHandleContext(h HandleContext) *CommandHandleContext {
	if h == nil {
		h = nullContext
	}
	return &CommandHandleContext{handle: h}
}

// CommandContext provides an API for building a command to execute via a TPMContext.
type CommandContext struct {
	tpm           *TPMContext
	commandCode   CommandCode
	handles       []*CommandHandleContext
	params        []interface{}
	extraSessions []SessionContext
}

// ResponseContext contains the context required to validate a response and obtain
// response parameters.
type ResponseContext struct {
	tpm              *TPMContext
	commandCode      CommandCode
	sessionParams    *sessionParams
	responseAuthArea []AuthResponse
	rpBytes          []byte
}

// Complete performs validation of the response auth area and updates internal SessionContext
// state. If a response HMAC is invalid, an error will be returned. The caller supplies a
// command dependent number of pointers to the response parameters.
func (c *ResponseContext) Complete(responseParams ...interface{}) error {
	c.tpm.updateExclusiveSession(c)

	if len(c.responseAuthArea) > 0 {
		if err := c.sessionParams.processResponseAuthArea(c.responseAuthArea, c.rpBytes); err != nil {
			return &InvalidResponseError{c.commandCode, fmt.Sprintf("cannot process response auth area: %v", err)}
		}
	}

	rpBuf := bytes.NewReader(c.rpBytes)

	if _, err := mu.UnmarshalFromReader(rpBuf, responseParams...); err != nil {
		return &InvalidResponseError{c.commandCode, fmt.Sprintf("cannot unmarshal response parameters: %v", err)}
	}

	if rpBuf.Len() > 0 {
		return &InvalidResponseError{c.commandCode, fmt.Sprintf("response parameter area contains %d trailing bytes", rpBuf.Len())}
	}

	return nil
}

// AddHandles appends the supplied command handle contexts to this command.
func (c *CommandContext) AddHandles(handles ...*CommandHandleContext) *CommandContext {
	c.handles = append(c.handles, handles...)
	return c
}

// AddParams appends the supplied command parameters to this command.
func (c *CommandContext) AddParams(params ...interface{}) *CommandContext {
	c.params = append(c.params, params...)
	return c
}

// AddExtraSessions adds the supplied additional session contexts to this command. These
// sessions are not used for authorization of any resources.
func (c *CommandContext) AddExtraSessions(sessions ...SessionContext) *CommandContext {
	c.extraSessions = append(c.extraSessions, sessions...)
	return c
}

// RunWithoutProcessingResponse executes the command defined by this context using the
// TPMContext that created it. The caller supplies a pointer to the response handle if the
// command returns one.
//
// If the TPM returns a response indicating that the command should be retried, this function
// will retry up to a maximum number of times defined by the number supplied to
// TPMContext.SetMaxSubmissions.
//
// This performs no validation of the response auth area. Instead, a ResponseContext is
// returned and the caller is expected to call ResponseContext.Complete. This is useful for
// commands that change an authorization value, where the response HMAC is computed with a
// key based on the new value.
//
// A *TctiError will be returned if the transmission interface returns an error.
//
// One of *TPMWarning, *TPMError, *TPMParameterError, *TPMHandleError or *TPMSessionError
// will be returned if the TPM returns a response code other than ResponseSuccess.
func (c *CommandContext) RunWithoutProcessingResponse(responseHandle *Handle) (*ResponseContext, error) {
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

	rpBytes, rAuthArea, err := c.tpm.RunCommand(c.commandCode, handles, cAuthArea, cpBytes, responseHandle)
	if err != nil {
		return nil, err
	}

	return &ResponseContext{
		tpm:              c.tpm,
		commandCode:      c.commandCode,
		sessionParams:    &sessionParams,
		responseAuthArea: rAuthArea,
		rpBytes:          rpBytes}, nil
}

// Run executes the command defined by this context using the TPMContext that created it.
// The caller supplies a pointer to the response handle if the command returns one, and
// a command dependent number of pointers to response parameters.
//
// If the TPM returns a response indicating that the command should be retried, this function
// will retry up to a maximum number of times defined by the number supplied to
// TPMContext.SetMaxSubmissions.
//
// This performs validation of the response auth area and updates internal SessionContext
// state. If a response HMAC is invalid, an error will be returned.
//
// A *TctiError will be returned if the transmission interface returns an error.
//
// One of *TPMWarning, *TPMError, *TPMParameterError, *TPMHandleError or *TPMSessionError
// will be returned if the TPM returns a response code other than ResponseSuccess.
func (c *CommandContext) Run(responseHandle *Handle, responseParams ...interface{}) error {
	r, err := c.RunWithoutProcessingResponse(responseHandle)
	if err != nil {
		return err
	}
	return r.Complete(responseParams...)
}
