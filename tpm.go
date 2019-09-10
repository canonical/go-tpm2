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
)

func concat(chunks ...[]byte) []byte {
	return bytes.Join(chunks, nil)
}

func makeInvalidParamError(name, msg string) error {
	return fmt.Errorf("invalid %s parameter: %s", name, msg)
}

func wrapMarshallingError(commandCode CommandCode, context string, err error) error {
	return fmt.Errorf("cannot marshal %s for command %s: %v", context, commandCode, err)
}

func wrapUnmarshallingError(commandCode CommandCode, context string, err error) error {
	return UnmarshallingError{Command: commandCode, context: context, err: err}
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

var Separator separatorSentinel

type SessionAttributes int

const (
	AttrContinueSession SessionAttributes = 1 << iota
	AttrCommandEncrypt
	AttrResponseEncrypt
)

type Session struct {
	Context   ResourceContext
	AuthValue []byte
	Attrs     SessionAttributes

	includeAuthValue bool
}

type HandleWithAuth struct {
	Handle Handle
	Auth   interface{}
}

type ResourceWithAuth struct {
	Context ResourceContext
	Auth    interface{}
}

// TODO: Implement commands from the following sections of part 3 of the TPM library spec:
// Section 13 - Duplication Commands
// Section 14 - Asymmetric Primitives
// Section 15 - Symmetrict Primitives
// Section 17 - Hash/HMAC/Event Sequences
// Section 19 - Ephemeral EC Keys
// Section 20 - Signing and Signature Verification
// Section 21 - Command Audit
// Section 26 - Miscellaneous Management Functions
// Section 27 - Field Upgrade

type TPMContext struct {
	tcti           io.ReadWriteCloser
	resources      map[Handle]ResourceContext
	maxSubmissions uint
}

func (t *TPMContext) Close() error {
	for _, rc := range t.resources {
		t.evictResourceContext(rc)
	}

	return t.tcti.Close()
}

func (t *TPMContext) RunCommandBytes(tag StructTag, commandCode CommandCode, commandBytes []byte) (ResponseCode,
	StructTag, []byte, error) {
	cHeader := commandHeader{tag, 0, commandCode}
	cHeader.CommandSize = uint32(binary.Size(cHeader) + len(commandBytes))

	cHeaderBytes, err := MarshalToBytes(cHeader)
	if err != nil {
		return 0, 0, nil, wrapMarshallingError(commandCode, "command header", err)
	}

	if _, err := t.tcti.Write(concat(cHeaderBytes, commandBytes)); err != nil {
		return 0, 0, nil, TPMWriteError{Command: commandCode, Err: err}
	}

	var rHeader responseHeader
	rHeaderBytes := make([]byte, binary.Size(rHeader))
	if _, err := io.ReadFull(t.tcti, rHeaderBytes); err != nil {
		return 0, 0, nil, TPMReadError{Command: commandCode, Err: err}
	}

	if _, err := UnmarshalFromBytes(rHeaderBytes, &rHeader); err != nil {
		return 0, 0, nil, wrapUnmarshallingError(commandCode, "response header", err)
	}

	responseBytes := make([]byte, int(rHeader.ResponseSize)-len(rHeaderBytes))
	if _, err := io.ReadFull(t.tcti, responseBytes); err != nil {
		return 0, 0, nil, TPMReadError{Command: commandCode, Err: err}
	}

	return rHeader.ResponseCode, rHeader.Tag, responseBytes, nil
}

func (t *TPMContext) runCommandWithoutProcessingResponse(commandCode CommandCode, sessionParams []*sessionParam,
	params ...interface{}) (*cmdContext, error) {
	commandHandles := make([]interface{}, 0, len(params))
	commandHandleNames := make([]Name, 0, len(params))
	commandParams := make([]interface{}, 0, len(params))

	sentinels := 0
	for _, param := range params {
		if param == Separator {
			sentinels++
			continue
		}

		switch sentinels {
		case 0:
			switch p := param.(type) {
			case ResourceContext:
				if err := t.checkResourceContextParam(p); err != nil {
					return nil, wrapMarshallingError(commandCode, "command handles",
						fmt.Errorf("invalid resource context at index %d: %v",
							len(commandHandles), err))
				}
				commandHandles = append(commandHandles, p.Handle())
				commandHandleNames = append(commandHandleNames, p.Name())
			case Handle:
				commandHandles = append(commandHandles, p)
				commandHandleNames =
					append(commandHandleNames, permanentContext(p).Name())
			default:
				return nil, wrapMarshallingError(commandCode, "command handles",
					fmt.Errorf("invalid parameter type (%s)", reflect.TypeOf(param)))
			}
		case 1:
			commandParams = append(commandParams, param)
		}
	}

	if hasDecryptSession(sessionParams) && len(commandParams) > 0 && !isParamEncryptable(commandParams[0]) {
		return nil, fmt.Errorf("command %v does not support command parameter encryption", commandCode)
	}

	var chBytes []byte
	var cpBytes []byte
	var caBytes []byte

	var err error

	if len(commandHandles) > 0 {
		chBytes, err = MarshalToBytes(commandHandles...)
		if err != nil {
			return nil, wrapMarshallingError(commandCode, "command handles", err)
		}
	}

	if len(commandParams) > 0 {
		cpBytes, err = MarshalToBytes(commandParams...)
		if err != nil {
			return nil, wrapMarshallingError(commandCode, "command parameters", err)
		}
	}

	tag := TagNoSessions
	if len(sessionParams) > 0 {
		tag = TagSessions
		authArea, err := buildCommandAuthArea(t, sessionParams, commandCode, commandHandleNames, cpBytes)
		if err != nil {
			return nil, wrapMarshallingError(commandCode, "command auth area",
				fmt.Errorf("error whilst building auth area: %v", err))
		}
		caBytes, err = MarshalToBytes(&authArea)
		if err != nil {
			return nil, wrapMarshallingError(commandCode, "command auth area", err)
		}
	}

	var responseCode ResponseCode
	var responseTag StructTag
	var responseBytes []byte

	for tries := uint(1); ; tries++ {
		var err error
		responseCode, responseTag, responseBytes, err =
			t.RunCommandBytes(tag, commandCode, concat(chBytes, caBytes, cpBytes))
		if err != nil {
			return nil, err
		}

		err = DecodeResponseCode(commandCode, responseCode)
		if err == nil {
			break
		}

		warning, isWarning := err.(TPMWarning)
		if tries >= t.maxSubmissions || !isWarning || !(warning.Code == WarningYielded ||
			warning.Code == WarningTesting || warning.Code == WarningRetry) {
			return nil, err
		}
	}

	return &cmdContext{commandCode: commandCode,
		sessionParams: sessionParams,
		responseCode:  responseCode,
		responseTag:   responseTag,
		responseBytes: responseBytes}, nil
}

func (t *TPMContext) processResponse(context *cmdContext, params ...interface{}) error {
	responseHandles := make([]interface{}, 0, len(params))
	responseParams := make([]interface{}, 0, len(params))

	sentinels := 0
	for _, param := range params {
		if param == Separator {
			sentinels++
			continue
		}

		switch sentinels {
		case 0:
			_, isHandle := param.(*Handle)
			if !isHandle {
				return wrapUnmarshallingError(context.commandCode, "response handles",
					fmt.Errorf("invalid response handle parameter type (%s)",
						reflect.TypeOf(param)))
			}
			responseHandles = append(responseHandles, param)
		case 1:
			responseParams = append(responseParams, param)
		}
	}

	buf := bytes.NewReader(context.responseBytes)

	if len(responseHandles) > 0 {
		if err := UnmarshalFromReader(buf, responseHandles...); err != nil {
			return wrapUnmarshallingError(context.commandCode, "response handles", err)
		}
	}

	rpBuf := buf
	var rpBytes []byte

	if context.responseTag == TagSessions {
		var parameterSize uint32
		if err := UnmarshalFromReader(buf, &parameterSize); err != nil {
			return wrapUnmarshallingError(context.commandCode, "parameter size", err)
		}
		rpBytes = make([]byte, parameterSize)
		_, err := io.ReadFull(buf, rpBytes)
		if err != nil {
			return wrapUnmarshallingError(context.commandCode, "response parameters",
				fmt.Errorf("error reading parameters to temporary buffer: %v", err))
		}

		authArea := responseAuthAreaRawSlice{make([]authResponse, len(context.sessionParams))}
		if err := UnmarshalFromReader(buf, &authArea); err != nil {
			return wrapUnmarshallingError(context.commandCode, "response auth area", err)
		}
		if err := processResponseAuthArea(t, authArea.Data, context.sessionParams, context.commandCode,
			context.responseCode, rpBytes); err != nil {
			return err
		}

		rpBuf = bytes.NewReader(rpBytes)
	}

	if len(responseParams) > 0 {
		if err := UnmarshalFromReader(rpBuf, responseParams...); err != nil {
			return wrapUnmarshallingError(context.commandCode, "response parameters", err)
		}
	}

	return nil
}

func (t *TPMContext) RunCommand(commandCode CommandCode, sessions []*Session, params ...interface{}) error {
	commandArgs := make([]interface{}, 0, len(params))
	responseArgs := make([]interface{}, 0, len(params))
	sessionParams := make([]*sessionParam, 0, len(params))

	sentinels := 0
	for _, param := range params {
		switch sentinels {
		case 0:
			var err error
			if hwa, isHwa := param.(HandleWithAuth); isHwa {
				commandArgs = append(commandArgs, hwa.Handle)
				sessionParams, err = t.validateAndAppendSessionParam(sessionParams, hwa)
			} else if rwa, isRwa := param.(ResourceWithAuth); isRwa {
				commandArgs = append(commandArgs, rwa.Context)
				sessionParams, err = t.validateAndAppendSessionParam(sessionParams, rwa)
			} else {
				commandArgs = append(commandArgs, param)
			}
			if err != nil {
				return wrapMarshallingError(commandCode, "command handles and auth area",
					fmt.Errorf("error whilst processing resource context or handle with "+
						"authorization at index %d: %v", len(commandArgs), err))
			}
			if param == Separator {
				sentinels++
			}
		case 1:
			if param == Separator {
				sentinels++
			} else {
				commandArgs = append(commandArgs, param)
			}
		case 2:
			responseArgs = append(responseArgs, param)
			if param == Separator {
				sentinels++
			}
		case 3:
			if param == Separator {
				sentinels++
			} else {
				responseArgs = append(responseArgs, param)
			}
		}
	}

	sessionParams, err := t.validateAndAppendSessionParam(sessionParams, sessions)
	if err != nil {
		return wrapMarshallingError(commandCode, "command auth area",
			fmt.Errorf("error whilst processing non-auth session parameter: %v", err))
	}

	ctx, err := t.runCommandWithoutProcessingResponse(commandCode, sessionParams, commandArgs...)
	if err != nil {
		return err
	}

	return t.processResponse(ctx, responseArgs...)
}

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
