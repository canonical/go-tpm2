// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"encoding/binary"
	"fmt"

	"github.com/canonical/go-tpm2/mu"
)

// Section 30 - Capability Commands

// GetCapability executes the TPM2_GetCapability command, which returns various properties of the TPM and its current state. The
// capability parameter indicates the category of data to be returned. The property parameter indicates the first value of the
// selected category to be returned. The propertyCount parameter indicates the number of values to be returned.
//
// If no property in the TPM corresponds to the value of property, then the next property is returned.
//
// The underlying implementation of TPM2_GetCapability is not required to (or may not be able to) return all of the requested
// values in a single request. This function will re-execute the TPM2_GetCapability command until all of the requested properties
// have been returned. As a consequence, any SessionContext instances provided should have the AttrContinueSession attribute defined.
//
// If capability is CapabilityHandles and property does not correspond to a valid handle type, a *TPMParameterError error with
// an error code of ErrorHandle is returned for parameter index 2.
func (t *TPMContext) GetCapability(capability Capability, property, propertyCount uint32, sessions ...SessionContext) (capabilityData *CapabilityData, err error) {
	capabilityData = &CapabilityData{Capability: capability, Data: &CapabilitiesU{}}

	nextProperty := property
	remaining := propertyCount

	for {
		var moreData bool
		var data CapabilityData

		if err := t.RunCommand(CommandGetCapability, sessions,
			Delimiter,
			capability, nextProperty, remaining, Delimiter,
			Delimiter,
			&moreData, &data); err != nil {
			return nil, err
		}

		if data.Capability != capability {
			return nil, &InvalidResponseError{CommandGetCapability,
				fmt.Sprintf("TPM responded with data for the wrong capability (got %s)", data.Capability)}
		}

		var l int
		var p uint32
		switch data.Capability {
		case CapabilityAlgs:
			capabilityData.Data.Algorithms = append(capabilityData.Data.Algorithms, data.Data.Algorithms...)
			l = len(data.Data.Algorithms)
			if l > 0 {
				p = uint32(data.Data.Algorithms[l-1].Alg)
			}
		case CapabilityHandles:
			capabilityData.Data.Handles = append(capabilityData.Data.Handles, data.Data.Handles...)
			l = len(data.Data.Handles)
			if l > 0 {
				p = uint32(data.Data.Handles[l-1])
			}
		case CapabilityCommands:
			capabilityData.Data.Command = append(capabilityData.Data.Command, data.Data.Command...)
			l = len(data.Data.Command)
			if l > 0 {
				p = uint32(data.Data.Command[l-1].CommandCode())
			}
		case CapabilityPPCommands:
			capabilityData.Data.PPCommands = append(capabilityData.Data.PPCommands, data.Data.PPCommands...)
			l = len(data.Data.PPCommands)
			if l > 0 {
				p = uint32(data.Data.PPCommands[l-1])
			}
		case CapabilityAuditCommands:
			capabilityData.Data.AuditCommands = append(capabilityData.Data.AuditCommands, data.Data.AuditCommands...)
			l = len(data.Data.AuditCommands)
			if l > 0 {
				p = uint32(data.Data.AuditCommands[l-1])
			}
		case CapabilityPCRs:
			if moreData {
				return nil, &InvalidResponseError{CommandGetCapability,
					fmt.Sprintf("TPM did not respond with all requested properties for capability %s", data.Capability)}
			}
			return &data, nil
		case CapabilityTPMProperties:
			capabilityData.Data.TPMProperties = append(capabilityData.Data.TPMProperties, data.Data.TPMProperties...)
			l = len(data.Data.TPMProperties)
			if l > 0 {
				p = uint32(data.Data.TPMProperties[l-1].Property)
			}
		case CapabilityPCRProperties:
			capabilityData.Data.PCRProperties = append(capabilityData.Data.PCRProperties, data.Data.PCRProperties...)
			l = len(data.Data.PCRProperties)
			if l > 0 {
				p = uint32(data.Data.PCRProperties[l-1].Tag)
			}
		case CapabilityECCCurves:
			capabilityData.Data.ECCCurves = append(capabilityData.Data.ECCCurves, data.Data.ECCCurves...)
			l = len(data.Data.ECCCurves)
			if l > 0 {
				p = uint32(data.Data.ECCCurves[l-1])
			}
		case CapabilityAuthPolicies:
			capabilityData.Data.AuthPolicies = append(capabilityData.Data.AuthPolicies, data.Data.AuthPolicies...)
			l = len(data.Data.AuthPolicies)
			if l > 0 {
				p = uint32(data.Data.AuthPolicies[l-1].Handle)
			}
		}

		nextProperty += p + 1
		remaining -= uint32(l)

		if !moreData || remaining <= 0 {
			break
		}
	}

	return capabilityData, nil
}

// GetCapabilityAlgs is a helper function that wraps around TPMContext.GetCapability, and returns properties of the algorithms
// supported by the TPM. The first parameter indicates the first algorithm for which to return properties. If this algorithm isn't
// supported, then the properties of the next supported algorithm are returned instead. The propertyCount parameter indicates the
// number of algorithms for which to return properties.
func (t *TPMContext) GetCapabilityAlgs(first AlgorithmId, propertyCount uint32, sessions ...SessionContext) (algs AlgorithmPropertyList, err error) {
	data, err := t.GetCapability(CapabilityAlgs, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Algorithms, nil
}

// GetCapabilityCommands is a helper function that wraps around TPMContext.GetCapability, and returns attributes of the commands
// supported by the TPM. The first parameter indicates the first command for which to return attributes. If this command isn't
// supported, then the attributes of the next supported command are returned instead. The propertyCount parameter indicates the
// number of commands for which to return attributes.
func (t *TPMContext) GetCapabilityCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (commands CommandAttributesList, err error) {
	data, err := t.GetCapability(CapabilityCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Command, nil
}

// GetCapabilityPPCommands is a helper function that wraps around TPMContext.GetCapability, and returns a list of commands that
// require physical presence for platform authorization. The first parameter indicates the command code at which the returned list
// should start. The propertyCount parameter indicates the maximum number of command codes to return.
func (t *TPMContext) GetCapabilityPPCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (ppCommands CommandCodeList, err error) {
	data, err := t.GetCapability(CapabilityPPCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PPCommands, nil
}

// GetCapabilityPPCommands is a helper function that wraps around TPMContext.GetCapability, and returns a list of commands that are
// currently set for command audit. The first parameter indicates the command code at which the returned list should start. The
// propertyCount parameter indicates the maximum number of command codes to return.
func (t *TPMContext) GetCapabilityAuditCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (auditCommands CommandCodeList, err error) {
	data, err := t.GetCapability(CapabilityAuditCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuditCommands, nil
}

// GetCapabilityHandles is a helper function that wraps around TPMContext.GetCapability, and returns a list of handles of resources
// on the TPM. The firstHandle parameter indicates the type of handles to be returned (represented by the most-significant byte),
// and also the handle at which the list should start. The propertyCount parameter indicates the maximum number of handles to return.
func (t *TPMContext) GetCapabilityHandles(firstHandle Handle, propertyCount uint32, sessions ...SessionContext) (handles HandleList, err error) {
	data, err := t.GetCapability(CapabilityHandles, uint32(firstHandle), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Handles, nil
}

// GetCapabilityPCRs is a helper function that wraps around TPMContext.GetCapability, and returns the current allocation of PCRs on
// the TPM.
func (t *TPMContext) GetCapabilityPCRs(sessions ...SessionContext) (pcrs PCRSelectionList, err error) {
	data, err := t.GetCapability(CapabilityPCRs, 0, CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AssignedPCR, nil
}

// GetCapabilityTPMProperties is a helper function that wraps around TPMContext.GetCapability, and returns the values of properties of
// the TPM. The first parameter indicates the first property for which to return a value. If the property does not exist, then the
// value of the next available property is returned. The propertyCount parameter indicates the number of properties for which to
// return values.
func (t *TPMContext) GetCapabilityTPMProperties(first Property, propertyCount uint32, sessions ...SessionContext) (tpmProperties TaggedTPMPropertyList, err error) {
	data, err := t.GetCapability(CapabilityTPMProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.TPMProperties, nil
}

// GetCapabilityPCRProperties is a helper function that wraps around TPMContext.GetCapability, and returns the values of PCR
// properties. The first parameter indicates the first property for which to return a value. If the property does not exist, then
// the value of the next available property is returned. The propertyCount parameter indicates the number of properties for which to
// return values. Each returned property value is a list of PCR indexes associated with a property.
func (t *TPMContext) GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32, sessions ...SessionContext) (pcrProperties TaggedPCRPropertyList, err error) {
	data, err := t.GetCapability(CapabilityPCRProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PCRProperties, nil
}

// GetCapabilityECCCurves is a helper function that wraps around TPMContext.GetCapability, and returns a list of ECC curves supported
// by the TPM.
func (t *TPMContext) GetCapabilityECCCurves(sessions ...SessionContext) (eccCurves ECCCurveList, err error) {
	data, err := t.GetCapability(CapabilityECCCurves, uint32(ECCCurveFirst), CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.ECCCurves, nil
}

// GetCapabilityAuthPolicies is a helper function that wraps around TPMContext.GetCapability, and returns auth policy digests
// associated with permanent handles. The first parameter indicates the first handle for which to return an auth policy. If the
// handle doesn't exist, then the auth policy for the next available handle is returned. The propertyCount parameter indicates the
// number of permanent handles for which to return an auth policy.
func (t *TPMContext) GetCapabilityAuthPolicies(first Handle, propertyCount uint32, sessions ...SessionContext) (authPolicies TaggedPolicyList, err error) {
	data, err := t.GetCapability(CapabilityAuthPolicies, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuthPolicies, nil
}

// TPMManufacturer corresponds to the TPM manufacturer and is returned when querying the value PropertyManufacturer with
// TPMContext.GetCapabilityTPMProperties
type TPMManufacturer uint32

// GetManufacturer is a helper function that wraps around TPMContext.GetCapability in order to obtain the ID of the TPM manufacturer.
func (t *TPMContext) GetManufacturer(sessions ...SessionContext) (manufacturer TPMManufacturer, err error) {
	props, err := t.GetCapabilityTPMProperties(PropertyManufacturer, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(props) == 0 || props[0].Property != PropertyManufacturer {
		return 0, &InvalidResponseError{Command: CommandGetCapability, msg: "expected TPM_PT_MANUFACTURER property"}
	}
	return TPMManufacturer(props[0].Value), nil
}

// IsTPM2 determines whether this TPMContext is connected to a TPM2 device. It does this by attempting to execute a TPM2_GetCapability
// command, and verifying that the response packet has the expected tag.
//
// On success, this will return true if TPMContext is connected to a TPM2 device, or false if it is connected to a TPM1.2 device. An
// error will be returned if communication with the device fails or the response packet is badly formed.
func (t *TPMContext) IsTPM2() (isTpm2 bool, err error) {
	cpBytes, err := mu.MarshalToBytes(CapabilityTPMProperties, uint32(PropertyTotalCommands), uint32(0))
	if err != nil {
		panic(fmt.Sprintf("cannot marshal command parameter bytes: %v", err))
	}

	cmd := MarshalCommandPacket(CommandGetCapability, nil, nil, cpBytes)

	resp, err := t.RunCommandBytes(cmd)
	if err != nil {
		return false, err
	}

	var rHeader ResponseHeader
	if _, err := mu.UnmarshalFromBytes(resp, &rHeader); err != nil {
		return false, &InvalidResponseError{CommandGetCapability, fmt.Sprintf("cannot unmarshal response header: %v", err)}
	}

	if rHeader.Tag == TagNoSessions {
		return true, nil
	}
	return false, nil
}

// GetInputBuffer returns the value of the PropertyInputBuffer property, which indicates the maximum size of arguments of the
// MaxBuffer type in bytes. The size is TPM implementation specific, but required to be at least 1024 bytes.
func (t *TPMContext) GetInputBuffer(sessions ...SessionContext) int {
	props, err := t.GetCapabilityTPMProperties(PropertyInputBuffer, 1, sessions...)
	if err != nil {
		return 1024
	}
	if len(props) == 0 || props[0].Property != PropertyInputBuffer {
		return 1024
	}
	return int(props[0].Value)
}

// GetMaxDigest returns the value of the PropertyMaxDigest property, which indicates the size of the largest digest algorithm
// supported by the TPM in bytes.
func (t *TPMContext) GetMaxDigest(sessions ...SessionContext) (int, error) {
	props, err := t.GetCapabilityTPMProperties(PropertyMaxDigest, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(props) == 0 || props[0].Property != PropertyMaxDigest {
		return 0, &InvalidResponseError{Command: CommandGetCapability, msg: "expected TPM_PT_MAX_DIGEST property"}
	}
	return int(props[0].Value), nil
}

// GetMaxData returns the maximum size of arguments of the Data type supported by the TPM in bytes.
func (t *TPMContext) GetMaxData(sessions ...SessionContext) (int, error) {
	n, err := t.GetMaxDigest(sessions...)
	if err != nil {
		return 0, err
	}
	return n + binary.Size(AlgorithmId(0)), nil
}

// GetNVBufferMax returns the value of the PropertyNVBufferMax property, which indicates the maximum buffer size supported by
// the TPM in bytes for TPMContext.NVReadRaw and TPMContext.NVWriteRaw.
func (t *TPMContext) GetNVBufferMax(sessions ...SessionContext) (int, error) {
	props, err := t.GetCapabilityTPMProperties(PropertyNVBufferMax, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(props) == 0 || props[0].Property != PropertyNVBufferMax {
		return 0, &InvalidResponseError{Command: CommandGetCapability, msg: "expected TPM_PT_NV_BUFFER_MAX property"}
	}
	return int(props[0].Value), nil
}

// TestParms executes the TPM2_TestParms command to check if the specified combination of algorithm parameters is supported.
func (t *TPMContext) TestParms(parameters *PublicParams, sessions ...SessionContext) error {
	return t.RunCommand(CommandTestParms, sessions, Delimiter, parameters)
}
