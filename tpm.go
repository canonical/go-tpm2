package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	maxCommandSize int = 4096
)

type Format struct {
	NumOfHandles int
	NumOfParams  int
}

type TPM interface {
	Close() error

	RunCommandBytesRaw(tag StructTag, commandCode CommandCode, in []byte) (ResponseCode, StructTag, []byte,
		error)
	RunCommandBytes(tag StructTag, commandCode CommandCode, in []byte) (StructTag, []byte, error)
	RunCommand(commandCode CommandCode, commandFormat, responseFormat Format, params ...interface{}) error

	WrapHandle(handle Handle) (Resource, error)

	// Start-up
	Startup(startupType StartupType) error
	Shutdown(shutdownType StartupType) error

	// Testing
	SelfTest(fullTest bool) error
	IncrementalSelfTest(toTest AlgorithmList) (AlgorithmList, error)
	GetTestResult() (MaxBuffer, ResponseCode, error)

	// Object Commands
	Create(parentHandle Resource, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data,
		creationPCR PCRSelectionList, session interface{}) (Private, *Public, *CreationData, Digest,
		*TkCreation, error)
	Load(parentHandle Resource, inPrivate Private, inPublic *Public, session interface{}) (Resource, Name,
		error)
	LoadExternal(inPrivate *Sensitive, inPublic *Public, hierarchy Handle) (Resource, Name, error)
	ReadPublic(objectHandle Resource) (*Public, Name, Name, error)

	// Hierarchy Commands
	CreatePrimary(primaryObject Handle, inSensitive *SensitiveCreate, inPublic *Public, outsideInfo Data,
		creationPCR PCRSelectionList, session interface{}) (Resource, *Public, *CreationData, Digest,
		*TkCreation, Name, error)
	Clear(authHandle Handle, session interface{}) error
	ClearControl(authHandle Handle, disable bool, session interface{}) error
	HierarchyChangeAuth(authHandle Handle, newAuth Auth, session interface{}) error

	// Context Management
	FlushContext(flushHandle Resource) error
	EvictControl(auth Handle, objectHandle Resource, persistentHandle Handle, session interface{}) (Resource,
		error)

	// Capability Commands
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

	// Non-volatile Storage
	NVReadPublic(nvIndex Resource) (*NVPublic, Name, error)
}

func concat(chunks ...[]byte) []byte {
	return bytes.Join(chunks, nil)
}

func wrapMarshallingError(err error) error {
	return MarshallingError{err: err}
}

func wrapUnmarshallingError(err error) error {
	return UnmarshallingError{err: err}
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

type tpmImpl struct {
	tpm       io.ReadWriteCloser
	resources map[Handle]Resource
}

func (t *tpmImpl) Close() error {
	if err := t.tpm.Close(); err != nil {
		return err
	}

	for _, resource := range t.resources {
		resource.(resourcePrivate).SetTpm(nil)
	}

	return nil
}

func (t *tpmImpl) RunCommandBytesRaw(tag StructTag, commandCode CommandCode, commandBytes []byte) (ResponseCode,
	StructTag, []byte, error) {
	cHeader := commandHeader{tag, 0, commandCode}
	cHeader.CommandSize = uint32(binary.Size(cHeader) + len(commandBytes))

	headerBytes, err := MarshalToBytes(cHeader)
	if err != nil {
		return 0, 0, nil, wrapMarshallingError(err)
	}

	if _, err := t.tpm.Write(concat(headerBytes, commandBytes)); err != nil {
		return 0, 0, nil, TPMWriteError{IOError: err}
	}

	responseBytes := make([]byte, maxCommandSize)
	responseLen, err := t.tpm.Read(responseBytes)
	if err != nil {
		return 0, 0, nil, TPMReadError{IOError: err}
	}
	responseBytes = responseBytes[:responseLen]

	var rHeader responseHeader
	rHeaderLen, err := UnmarshalFromBytes(responseBytes, &rHeader)
	if err != nil {
		return 0, 0, nil, wrapUnmarshallingError(err)
	}

	responseBytes = responseBytes[rHeaderLen:]

	return rHeader.ResponseCode, rHeader.Tag, responseBytes, nil
}

func (t *tpmImpl) RunCommandBytes(tag StructTag, commandCode CommandCode, commandBytes []byte) (StructTag,
	[]byte, error) {
	responseCode, responseTag, responseBytes, err := t.RunCommandBytesRaw(tag, commandCode, commandBytes)
	if err != nil {
		return 0, nil, err
	}

	if err := DecodeResponseCode(responseCode); err != nil {
		return 0, nil, err
	}

	return responseTag, responseBytes, nil
}

func (t *tpmImpl) RunCommand(commandCode CommandCode, commandFormat, responseFormat Format,
	params ...interface{}) error {
	i := 0
	commandHandles := params[i : i+commandFormat.NumOfHandles]
	i += commandFormat.NumOfHandles
	commandParams := params[i : i+commandFormat.NumOfParams]
	i += commandFormat.NumOfParams
	responseHandles := params[i : i+responseFormat.NumOfHandles]
	i += responseFormat.NumOfHandles
	responseParams := params[i : i+responseFormat.NumOfParams]
	i += responseFormat.NumOfParams
	commandAuthParams := params[i:]

	var chBytes []byte
	var cpBytes []byte
	var caBytes []byte

	var err error

	if len(commandHandles) > 0 {
		chBytes, err = MarshalToBytes(commandHandles...)
		if err != nil {
			return wrapMarshallingError(err)
		}
	}

	if len(commandParams) > 0 {
		cpBytes, err = MarshalToBytes(commandParams...)
		if err != nil {
			return wrapMarshallingError(err)
		}
	}

	tag := TagNoSessions
	if len(commandAuthParams) > 0 {
		tag = TagSessions
		authArea, err := buildCommandAuthArea(commandAuthParams...)
		if err != nil {
			return err
		}
		caBytes, err = MarshalToBytes(&authArea)
		if err != nil {
			return wrapMarshallingError(err)
		}
	}

	responseTag, responseBytes, err := t.RunCommandBytes(tag, commandCode, concat(chBytes, caBytes, cpBytes))
	if err != nil {
		return err
	}

	responseBuf := bytes.NewReader(responseBytes)

	if len(responseHandles) > 0 {
		if err := UnmarshalFromReader(responseBuf, responseHandles...); err != nil {
			return wrapUnmarshallingError(err)
		}
	}

	var parameterSize uint32
	if responseTag == TagSessions {
		if err := UnmarshalFromReader(responseBuf, &parameterSize); err != nil {
			return wrapUnmarshallingError(err)
		}
	}
	// TODO: Verify parameterSize

	if len(responseParams) > 0 {
		if err := UnmarshalFromReader(responseBuf, responseParams...); err != nil {
			return wrapUnmarshallingError(err)
		}
	}

	if len(commandAuthParams) > 0 && responseTag == TagSessions {
		authArea := make([]authResponse, len(commandAuthParams))
		if err := UnmarshalFromReader(responseBuf, RawSlice(authArea)); err != nil {
			return wrapUnmarshallingError(err)
		}
		if err := processAuthResponse(authArea); err != nil {
			return err
		}
	}

	return nil
}

func newTPMImpl(t io.ReadWriteCloser) *tpmImpl {
	r := new(tpmImpl)
	r.tpm = t
	r.resources = make(map[Handle]Resource)

	return r
}

func OpenTPM(path string) (TPM, error) {
	tpm, err := openLinuxTPMDevice(path)
	if err != nil {
		return nil, fmt.Errorf("cannot open TPM: %v", err)
	}

	return newTPMImpl(tpm), nil
}
