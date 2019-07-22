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

type separatorSentinel struct{}

var Separator separatorSentinel

type SessionAttributes int

const (
	AttrContinueSession SessionAttributes = 1 << iota
)

type Session struct {
	Handle    ResourceContext
	AuthValue []byte
	Attrs     SessionAttributes
}

type HandleWithAuth struct {
	Handle Handle
	Auth   interface{}
}

type ResourceWithAuth struct {
	Handle ResourceContext
	Auth   interface{}
}

type TPMContext interface {
	Close() error

	RunCommandBytes(tag StructTag, commandCode CommandCode, in []byte) (ResponseCode, StructTag, []byte,
		error)
	RunCommandAndReturnRawResponse(commandCode CommandCode, params ...interface{}) (ResponseCode, StructTag,
		[]byte, error)
	ProcessResponse(commandCode CommandCode, responseCode ResponseCode, responseTag StructTag,
		response []byte, params ...interface{}) error

	RunCommand(commandCode CommandCode, params ...interface{}) error

	SetMaxSubmissions(max uint)
	WrapHandle(handle Handle) (ResourceContext, error)

	// Section 9 - Start-up
	Startup(startupType StartupType) error
	Shutdown(shutdownType StartupType) error

	// Section 10 - Testing
	SelfTest(fullTest bool) error
	IncrementalSelfTest(toTest AlgorithmList) (AlgorithmList, error)
	GetTestResult() (MaxBuffer, ResponseCode, error)

	// Section 11 - Session Commands
	StartAuthSession(tpmKey, bind ResourceContext, sessionType SessionType, symmetric *SymDef,
		authHash AlgorithmId, authValue []byte) (ResourceContext, error)
	// PolicyRestart(sessionHandle ResourceContext) error

	// Section 12 - Object Commands
	Create(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data,
		creationPCR PCRSelectionList, parentHandleAuth interface{}) (Private, *Public, *CreationData,
		Digest, *TkCreation, error)
	Load(parentHandle ResourceContext, inPrivate Private, inPublic *Public,
		parentHandleAuth interface{}) (ResourceContext, Name, error)
	LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle) (ResourceContext, Name, error)
	ReadPublic(objectHandle ResourceContext) (*Public, Name, Name, error)
	//ActivateCredential(activateHandle, keyHandle ResourceContext, credentialBlob IDObject,
	//	secret EncryptedSecret, activateHandleAuth, keyHandleAuth interface{}) (Digest, error)
	//MakeCredential(handle ResourceContext, credential Digest, objectName Name) (IDObject,
	//	EncryptedSecret, error)
	Unseal(itemHandle ResourceContext, itemHandleAuth interface{}) (SensitiveData, error)
	ObjectChangeAuth(objectHandle, parentHandle ResourceContext, newAuth Auth,
		objectHandleAuth interface{}) (Private, error)
	CreateLoaded(parentHandle ResourceContext, inSensitive *SensitiveCreate, inPublic *Public,
		parentHandleAuth interface{}) (ResourceContext, Private, *Public, Name, error)

	// Section 13 - Duplication Commands
	// Section 14 - Asymmetric Primitives
	// Section 15 - Symmetrict Primitives
	// Section 16 - Random Number Generator
	// Section 17 - Hash/HMAC/Event Sequences
	// Section 18 - Attestation Commands
	// Section 19 - Ephemeral EC Keys
	// Section 20 - Signing and Signature Verification
	// Section 21 - Command Audit

	// Section 22 - Integrity Collection (PCR)
	PCRExtend(pcrHandle Handle, digests TaggedHashList, pcrHandleAuth interface{}) error
	PCREvent(pcrHandle Handle, eventData Event, pcrHandleAuth interface{}) (TaggedHashList, error)
	PCRRead(pcrSelectionIn PCRSelectionList) (uint32, PCRSelectionList, DigestList, error)

	// Section 23 - Enhanced Authorization (EA) Commands
	// PolicySigned(authObject, policySession ResourceContext, includeNonceTPM bool, cpHashA Digest,
	//	policyRef Nonce, expiration int32, auth *Signature) (Timeout, *TkAuth, error)
	// PolicySecret(authHandle, policySession ResourceContext, cpHashA Digest, policyRef Nonce,
	//	expiration int32) (Timeout, *TkAuth, error)
	// PolicyTicket(policySession ResourceContext, timeout Timeout, cpHashA Digest, policyRef Nonce,
	//	authName Name, ticket *TkAuth) error
	PolicyOR(policySession ResourceContext, pHashList DigestList) error
	PolicyPCR(policySession ResourceContext, pcrDigest Digest, pcrs PCRSelectionList) error
	// PolicyLocality(policySession ResourceContext, loclity Locality) error
	// PolicyNV(authHandle, nvIndex, policySession ResourceContext, operandB Operand, offset uint16,
	//	operation ArithmeticOp) error
	// PolicyCounterTimer(policySession ResourceContext, operandB Operand, offset uint16,
	//	operation ArithmeticOp) error
	// PolicyCommandCode(policySession ResourceContext, code CommandCode) error
	// PolicyPhysicalPresence(policySession ResourceContext) error
	// PolicyCpHash(policySession ResourceContext, cpHashA Digest) error
	// PolicyNameHash(policySession ResourceContext, nameHash Digest) error
	// PolicyDuplicationSelect(policySession ResourceContext, objectName, newParentName Name,
	//	includeObject bool) error
	// PolicyAuthorize(policySession ResourceContext, approvedPolicy Digest, policyRef Nonce, keySign Name,
	//	checkTicket *TkVerified) error
	// PolicyAuthValue(policySession ResourceContext) error
	// PolicyPassword(policySession ResourceContext) error
	PolicyGetDigest(policySession ResourceContext) (Digest, error)
	// PolicyNvWritten(policySession ResourceContext, writtenSet bool) error
	// PolicyTemplate(policySession ResourceContext, templateHash Digest) error
	// PolicyAuthorizeNV(authHandle, nvIndex, policySession ResourceContext) error

	// Section 24 - Hierarchy Commands
	CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data,
		creationPCR PCRSelectionList, primaryObjectAuth interface{}) (ResourceContext, *Public,
		*CreationData, Digest, *TkCreation, Name, error)
	Clear(authHandle Handle, authHandleAuth interface{}) error
	ClearControl(authHandle Handle, disable bool, authHandleAuth interface{}) error
	HierarchyChangeAuth(authHandle Handle, newAuth Auth, authHandleAuth interface{}) error

	// Section 25 - Dictionary Attack Functions
	// Section 26 - Miscellaneous Management Functions
	// Section 27 - Field Upgrade

	// Section 28 - Context Management
	ContextSave(saveHandle ResourceContext) (*Context, error)
	ContextLoad(context *Context) (ResourceContext, error)
	FlushContext(flushHandle ResourceContext) error
	EvictControl(auth Handle, objectHandle ResourceContext, persistentHandle Handle,
		authAuth interface{}) (ResourceContext, error)

	// Section 29 - Clocks and Timers

	// Section 30 - Capability Commands
	GetCapability(capability Capability, property, propertyCount uint32) (*CapabilityData, error)
	GetCapabilityAlgs(first AlgorithmId, propertyCount uint32) (AlgorithmPropertyList, error)
	GetCapabilityCommands(first CommandCode, propertyCount uint32) (CommandAttributesList, error)
	GetCapabilityPPCommands(first CommandCode, propertyCount uint32) (CommandCodeList, error)
	GetCapabilityAuditCommands(first CommandCode, propertyCount uint32) (CommandCodeList, error)
	GetCapabilityHandles(handleType Handle, propertyCount uint32) (HandleList, error)
	GetCapabilityPCRs() (PCRSelectionList, error)
	GetCapabilityTPMProperties(first Property, propertyCount uint32) (TaggedTPMPropertyList, error)
	GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32) (TaggedPCRPropertyList, error)
	GetCapabilityECCCurves() (ECCCurveList, error)
	GetCapabilityAuthPolicies(first Handle, propertyCount uint32) (TaggedPolicyList, error)

	// Section 31 - Non-volatile Storage
	NVReadPublic(nvIndex ResourceContext) (*NVPublic, Name, error)
}

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

type tpmContext struct {
	tcti           io.ReadWriteCloser
	resources      map[Handle]ResourceContext
	maxSubmissions uint
}

func (t *tpmContext) Close() error {
	for _, rc := range t.resources {
		rc.(resourceContextPrivate).setTpmContext(nil)
	}

	return t.tcti.Close()
}

func (t *tpmContext) RunCommandBytes(tag StructTag, commandCode CommandCode,
	commandBytes []byte) (ResponseCode, StructTag, []byte, error) {
	cHeader := commandHeader{tag, 0, commandCode}
	cHeader.CommandSize = uint32(binary.Size(cHeader) + len(commandBytes))

	cHeaderBytes, err := MarshalToBytes(cHeader)
	if err != nil {
		return 0, 0, nil, wrapMarshallingError(commandCode, "command header", err)
	}

	var rHeader responseHeader
	var responseBytes []byte

	for tries := uint(1); ; tries++ {
		if _, err := t.tcti.Write(concat(cHeaderBytes, commandBytes)); err != nil {
			return 0, 0, nil, TPMWriteError{Command: commandCode, Err: err}
		}

		rHeaderBytes := make([]byte, binary.Size(rHeader))
		if _, err := io.ReadFull(t.tcti, rHeaderBytes); err != nil {
			return 0, 0, nil, TPMReadError{Command: commandCode, Err: err}
		}

		if _, err := UnmarshalFromBytes(rHeaderBytes, &rHeader); err != nil {
			return 0, 0, nil, wrapUnmarshallingError(commandCode, "response header", err)
		}

		responseBytes = make([]byte, int(rHeader.ResponseSize)-len(rHeaderBytes))
		if _, err := io.ReadFull(t.tcti, responseBytes); err != nil {
			return 0, 0, nil, TPMReadError{Command: commandCode, Err: err}
		}

		err := DecodeResponseCode(commandCode, rHeader.ResponseCode)
		if err == nil {
			break
		}

		warning, isWarning := err.(TPMWarning)
		if tries >= t.maxSubmissions || !isWarning || !(warning.Code == WarningYielded ||
			warning.Code == WarningTesting || warning.Code == WarningRetry) {
			return rHeader.ResponseCode, rHeader.Tag, nil, err
		}
	}

	return rHeader.ResponseCode, rHeader.Tag, responseBytes, nil
}

func (t *tpmContext) RunCommandAndReturnRawResponse(commandCode CommandCode,
	params ...interface{}) (ResponseCode, StructTag, []byte, error) {
	commandHandles := make([]interface{}, 0, len(params))
	commandHandleNames := make([]Name, 0, len(params))
	commandParams := make([]interface{}, 0, len(params))
	sessionParams := make([]interface{}, 0, len(params))

	sentinels := 0
	for _, param := range params {
		if param == Separator {
			sentinels++
			continue
		}

		switch sentinels {
		case 0:
			wrapHandle := func(handle Handle) ResourceContext {
				return &permanentContext{handle: handle}
			}

			switch p := param.(type) {
			case HandleWithAuth:
				rc := wrapHandle(p.Handle)
				commandHandles = append(commandHandles, p.Handle)
				commandHandleNames = append(commandHandleNames, rc.Name())
				sessionParams = append(sessionParams, p)
			case ResourceWithAuth:
				commandHandles = append(commandHandles, p.Handle.Handle())
				commandHandleNames = append(commandHandleNames, p.Handle.Name())
				sessionParams = append(sessionParams, p)
			default:
				rc, isRc := param.(ResourceContext)
				if !isRc {
					handle, isHandle := param.(Handle)
					if !isHandle {
						return 0, 0, nil, wrapMarshallingError(
							commandCode, "command handles",
							fmt.Errorf("invalid handle parameter type (%s)",
								reflect.TypeOf(param)))
					}
					rc = wrapHandle(handle)
				}
				commandHandles = append(commandHandles, rc.Handle())
				commandHandleNames = append(commandHandleNames, rc.Name())
			}
		case 1:
			commandParams = append(commandParams, param)
		case 2:
			sessionParams = append(sessionParams, param)
		}
	}

	var chBytes []byte
	var cpBytes []byte
	var caBytes []byte

	var err error

	if len(commandHandles) > 0 {
		chBytes, err = MarshalToBytes(commandHandles...)
		if err != nil {
			return 0, 0, nil, wrapMarshallingError(commandCode, "command handles", err)
		}
	}

	if len(commandParams) > 0 {
		cpBytes, err = MarshalToBytes(commandParams...)
		if err != nil {
			return 0, 0, nil, wrapMarshallingError(commandCode, "command parameters", err)
		}
	}

	tag := TagNoSessions
	if len(sessionParams) > 0 {
		tag = TagSessions
		authArea, err := buildCommandAuthArea(t, commandCode, commandHandleNames, cpBytes,
			sessionParams...)
		if err != nil {
			return 0, 0, nil, err
		}
		caBytes, err = MarshalToBytes(&authArea)
		if err != nil {
			return 0, 0, nil, wrapMarshallingError(commandCode, "command auth area", err)
		}
	}

	responseCode, responseTag, responseBytes, err :=
		t.RunCommandBytes(tag, commandCode, concat(chBytes, caBytes, cpBytes))
	if err != nil {
		return 0, 0, nil, err
	}

	return responseCode, responseTag, responseBytes, nil
}

func (t *tpmContext) ProcessResponse(commandCode CommandCode, responseCode ResponseCode, responseTag StructTag,
	response []byte, params ...interface{}) error {
	responseHandles := make([]interface{}, 0, len(params))
	responseParams := make([]interface{}, 0, len(params))
	sessionParams := make([]interface{}, 0, len(params))

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
				return wrapUnmarshallingError(commandCode, "response handles",
					fmt.Errorf("invalid response handle parameter type (%s)",
						reflect.TypeOf(param)))
			}
			responseHandles = append(responseHandles, param)
		case 1:
			responseParams = append(responseParams, param)
		case 2:
			sessionParams = append(sessionParams, param)
		}
	}

	buf := bytes.NewReader(response)

	if len(responseHandles) > 0 {
		if err := UnmarshalFromReader(buf, responseHandles...); err != nil {
			return wrapUnmarshallingError(commandCode, "response handles", err)
		}
	}

	rpBuf := buf
	var rpBytes []byte

	if responseTag == TagSessions {
		var parameterSize uint32
		if err := UnmarshalFromReader(buf, &parameterSize); err != nil {
			return wrapUnmarshallingError(commandCode, "parameter size", err)
		}
		rpBytes = make([]byte, parameterSize)
		_, err := io.ReadFull(buf, rpBytes)
		if err != nil {
			return wrapUnmarshallingError(commandCode, "response parameters",
				fmt.Errorf("error reading parameters to temporary buffer: %v", err))
		}
		rpBuf = bytes.NewReader(rpBytes)
	}

	if len(responseParams) > 0 {
		if err := UnmarshalFromReader(rpBuf, responseParams...); err != nil {
			return wrapUnmarshallingError(commandCode, "response parameters", err)
		}
	}

	if responseTag == TagSessions {
		authArea := make([]authResponse, len(sessionParams))
		if err := UnmarshalFromReader(buf, RawSlice(authArea)); err != nil {
			return wrapUnmarshallingError(commandCode, "response auth area", err)
		}
		if err := processAuthResponseArea(t, responseCode, commandCode, rpBytes, authArea,
			sessionParams...); err != nil {
			return err
		}
	}

	return nil
}

func (t *tpmContext) RunCommand(commandCode CommandCode, params ...interface{}) error {
	commandArgs := make([]interface{}, 0, len(params))
	responseArgs := make([]interface{}, 0, len(params))
	authSessions := make([]interface{}, 0, len(params))

	sentinels := 0
	for _, param := range params {
		switch sentinels {
		case 0:
			commandArgs = append(commandArgs, param)
			if param == Separator {
				sentinels++
			} else if hwa, isHwa := param.(HandleWithAuth); isHwa {
				authSessions = append(authSessions, hwa)
			} else if rwa, isRwa := param.(ResourceWithAuth); isRwa {
				authSessions = append(authSessions, rwa)
			}
		case 1:
			commandArgs = append(commandArgs, param)
			if param == Separator {
				sentinels++
			}
		case 2:
			responseArgs = append(responseArgs, param)
			if param == Separator {
				sentinels++
			}
		case 3:
			responseArgs = append(responseArgs, param)
			if param == Separator {
				sentinels++
				responseArgs = append(responseArgs, authSessions...)
			}
		case 4:
			commandArgs = append(commandArgs, param)
			responseArgs = append(responseArgs, param)
			if param == Separator {
				sentinels++
			}
		}
	}

	if sentinels < 4 {
		for i := 4; i > sentinels && i > 2; i-- {
			responseArgs = append(responseArgs, Separator)
		}
		responseArgs = append(responseArgs, authSessions...)
	}

	responseCode, responseTag, responseBytes, err :=
		t.RunCommandAndReturnRawResponse(commandCode, commandArgs...)
	if err != nil {
		return err
	}

	return t.ProcessResponse(commandCode, responseCode, responseTag, responseBytes, responseArgs...)
}

func (t *tpmContext) SetMaxSubmissions(max uint) {
	t.maxSubmissions = max
}

func newTpmContext(tcti io.ReadWriteCloser) *tpmContext {
	r := new(tpmContext)
	r.tcti = tcti
	r.resources = make(map[Handle]ResourceContext)
	r.maxSubmissions = 5

	return r
}

func NewTPMContext(tcti io.ReadWriteCloser) (TPMContext, error) {
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
		return nil, errors.New("cannot find TPM interface to auto-open")
	}

	return newTpmContext(tcti), nil
}
