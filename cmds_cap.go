// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
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
func (t *TPMContext) GetCapability(capability Capability, property, propertyCount uint32, sessions ...SessionContext) (*CapabilityData, error) {
	var capabilityData *CapabilityData

	nextProperty := property
	remaining := propertyCount

	for {
		var moreData bool
		var data CapabilityData

		if err := t.RunCommand(CommandGetCapability, sessions,
			Separator,
			capability, nextProperty, remaining, Separator,
			Separator,
			&moreData, &data); err != nil {
			return nil, err
		}

		if data.Capability != capability {
			return nil, &InvalidResponseError{CommandGetCapability, fmt.Sprintf("TPM responded with data for the wrong capability (got %s)",
				data.Capability)}
		}

		if capabilityData == nil {
			capabilityData = &data
		} else {
			var s int
			switch data.Capability {
			case CapabilityAlgs:
				capabilityData.Data.Data = append(capabilityData.Data.Algorithms(), data.Data.Algorithms()...)
				s = len(data.Data.Algorithms())
			case CapabilityHandles:
				capabilityData.Data.Data = append(capabilityData.Data.Handles(), data.Data.Handles()...)
				s = len(data.Data.Handles())
			case CapabilityCommands:
				capabilityData.Data.Data = append(capabilityData.Data.Command(), data.Data.Command()...)
				s = len(data.Data.Command())
			case CapabilityPPCommands:
				capabilityData.Data.Data = append(capabilityData.Data.PPCommands(), data.Data.PPCommands()...)
				s = len(data.Data.PPCommands())
			case CapabilityAuditCommands:
				capabilityData.Data.Data = append(capabilityData.Data.AuditCommands(), data.Data.AuditCommands()...)
				s = len(data.Data.AuditCommands())
			case CapabilityPCRs:
				capabilityData.Data.Data = append(capabilityData.Data.AssignedPCR(), data.Data.AssignedPCR()...)
				s = len(data.Data.AssignedPCR())
			case CapabilityTPMProperties:
				capabilityData.Data.Data = append(capabilityData.Data.TPMProperties(), data.Data.TPMProperties()...)
				s = len(data.Data.TPMProperties())
			case CapabilityPCRProperties:
				capabilityData.Data.Data = append(capabilityData.Data.PCRProperties(), data.Data.PCRProperties()...)
				s = len(data.Data.PCRProperties())
			case CapabilityECCCurves:
				capabilityData.Data.Data = append(capabilityData.Data.ECCCurves(), data.Data.ECCCurves()...)
				s = len(data.Data.ECCCurves())
			case CapabilityAuthPolicies:
				capabilityData.Data.Data = append(capabilityData.Data.AuthPolicies(), data.Data.AuthPolicies()...)
				s = len(data.Data.AuthPolicies())
			}
			nextProperty += uint32(s)
			remaining -= uint32(s)
		}

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
func (t *TPMContext) GetCapabilityAlgs(first AlgorithmId, propertyCount uint32, sessions ...SessionContext) (AlgorithmPropertyList, error) {
	data, err := t.GetCapability(CapabilityAlgs, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Algorithms(), nil
}

// GetCapabilityCommands is a helper function that wraps around TPMContext.GetCapability, and returns attributes of the commands
// supported by the TPM. The first parameter indicates the first command for which to return attributes. If this command isn't
// supported, then the attributes of the next supported command are returned instead. The propertyCount parameter indicates the
// number of commands for which to return attributes.
func (t *TPMContext) GetCapabilityCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (CommandAttributesList, error) {
	data, err := t.GetCapability(CapabilityCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Command(), nil
}

// GetCapabilityPPCommands is a helper function that wraps around TPMContext.GetCapability, and returns a list of commands that
// require physical presence for platform authorization. The first parameter indicates the command code at which the returned list
// should start. The propertyCount parameter indicates the maximum number of command codes to return.
func (t *TPMContext) GetCapabilityPPCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (CommandCodeList, error) {
	data, err := t.GetCapability(CapabilityPPCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PPCommands(), nil
}

// GetCapabilityPPCommands is a helper function that wraps around TPMContext.GetCapability, and returns a list of commands that are
// currently set for command audit. The first parameter indicates the command code at which the returned list should start. The
// propertyCount parameter indicates the maximum number of command codes to return.
func (t *TPMContext) GetCapabilityAuditCommands(first CommandCode, propertyCount uint32, sessions ...SessionContext) (CommandCodeList, error) {
	data, err := t.GetCapability(CapabilityAuditCommands, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuditCommands(), nil
}

// GetCapabilityHandles is a helper function that wraps around TPMContext.GetCapability, and returns a list of handles of resources
// on the TPM. The handleType parameter indicates the type of handles to be returned (represented by the most-significant byte),
// and also the handle at which the list should start. The propertyCount parameter indicates the maximum number of handles to return.
func (t *TPMContext) GetCapabilityHandles(handleType Handle, propertyCount uint32, sessions ...SessionContext) (HandleList, error) {
	data, err := t.GetCapability(CapabilityHandles, uint32(handleType), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.Handles(), nil
}

// GetCapabilityPCRs is a helper function that wraps around TPMContext.GetCapability, and returns the current allocation of PCRs on
// the TPM.
func (t *TPMContext) GetCapabilityPCRs(sessions ...SessionContext) (PCRSelectionList, error) {
	data, err := t.GetCapability(CapabilityPCRs, 0, CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AssignedPCR(), nil
}

// GetCapabilityTPMProperties is a helper function that wraps around TPMContext.GetCapability, and returns the values of properties of
// the TPM. The first parameter indicates the first property for which to return a value. If the property does not exist, then the
// value of the next available property is returned. The propertyCount parameter indicates the number of properties for which to
// return values.
func (t *TPMContext) GetCapabilityTPMProperties(first Property, propertyCount uint32, sessions ...SessionContext) (TaggedTPMPropertyList, error) {
	data, err := t.GetCapability(CapabilityTPMProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.TPMProperties(), nil
}

// GetCapabilityPCRProperties is a helper function that wraps around TPMContext.GetCapability, and returns the values of PCR
// properties. The first parameter indicates the first property for which to return a value. If the property does not exist, then
// the value of the next available property is returned. The propertyCount parameter indicates the number of properties for which to
// return values. Each returned property value is a list of PCR indexes associated with a property.
func (t *TPMContext) GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32, sessions ...SessionContext) (TaggedPCRPropertyList, error) {
	data, err := t.GetCapability(CapabilityPCRProperties, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.PCRProperties(), nil
}

// GetCapabilityECCCurves is a helper function that wraps around TPMContext.GetCapability, and returns a list of ECC curves supported
// by the TPM.
func (t *TPMContext) GetCapabilityECCCurves(sessions ...SessionContext) (ECCCurveList, error) {
	data, err := t.GetCapability(CapabilityECCCurves, uint32(ECCCurveFirst), CapabilityMaxProperties, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.ECCCurves(), nil
}

// GetCapabilityAuthPolicies is a helper function that wraps around TPMContext.GetCapability, and returns auth policy digests
// associated with permanent handles. The first parameter indicates the first handle for which to return an auth policy. If the
// handle doesn't exist, then the auth policy for the next available handle is returned. The propertyCount parameter indicates the
// number of permanent handles for which to return an auth policy.
func (t *TPMContext) GetCapabilityAuthPolicies(first Handle, propertyCount uint32, sessions ...SessionContext) (TaggedPolicyList, error) {
	data, err := t.GetCapability(CapabilityAuthPolicies, uint32(first), propertyCount, sessions...)
	if err != nil {
		return nil, err
	}
	return data.Data.AuthPolicies(), nil
}

// TPMManufacturer corresponds to the TPM manufacturer and is returned when querying the value PropertyManufacturer with
// TPMContext.GetCapabilityTPMProperties
type TPMManufacturer uint32

// GetManufacturer is a helper function that wraps around TPMContext.GetCapability in order to obtain the ID of the TPM manufacturer.
func (t *TPMContext) GetManufacturer(sessions ...SessionContext) (TPMManufacturer, error) {
	props, err := t.GetCapabilityTPMProperties(PropertyManufacturer, 1, sessions...)
	if err != nil {
		return 0, err
	}
	if len(props) == 0 {
		return 0, nil
	}
	return TPMManufacturer(props[0].Value), nil
}

// TestParms executes the TPM2_TestParms command to check if the specified combination of algorithm parameters is supported.
func (t *TPMContext) TestParms(parameters *PublicParams, sessions ...SessionContext) error {
	return t.RunCommand(CommandTestParms, sessions, Separator, parameters)
}
