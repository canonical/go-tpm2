package tpm2

import (
	"fmt"
)

func (t *tpmImpl) GetCapability(capability Capability, property, propertyCount uint32) (*CapabilityData,
	error) {
	var capabilityData *CapabilityData

	nextProperty := property
	remaining := propertyCount

	for {
		var moreData bool
		var data CapabilityData

		if err := t.RunCommand(CommandGetCapability, Separator, capability, nextProperty, remaining,
			Separator, Separator, &moreData, &data); err != nil {
			return nil, err
		}

		if data.Capability != capability {
			return nil, InvalidResponseError{fmt.Sprintf("unexpected capability %v", data.Capability)}
		}

		if capabilityData == nil {
			capabilityData = &data
		} else {
			var s int
			switch data.Capability {
			case CapabilityAlgs:
				capabilityData.Data.Algorithms =
					append(capabilityData.Data.Algorithms, data.Data.Algorithms...)
				s = len(data.Data.Algorithms)
			case CapabilityHandles:
				capabilityData.Data.Handles =
					append(capabilityData.Data.Handles, data.Data.Handles...)
				s = len(data.Data.Handles)
			case CapabilityCommands:
				capabilityData.Data.Command =
					append(capabilityData.Data.Command, data.Data.Command...)
				s = len(data.Data.Command)
			case CapabilityPPCommands:
				capabilityData.Data.PPCommands =
					append(capabilityData.Data.PPCommands, data.Data.PPCommands...)
				s = len(data.Data.PPCommands)
			case CapabilityAuditCommands:
				capabilityData.Data.AuditCommands =
					append(capabilityData.Data.AuditCommands, data.Data.AuditCommands...)
				s = len(data.Data.AuditCommands)
			case CapabilityPCRs:
				capabilityData.Data.AssignedPCR =
					append(capabilityData.Data.AssignedPCR, data.Data.AssignedPCR...)
				s = len(data.Data.AssignedPCR)
			case CapabilityTPMProperties:
				capabilityData.Data.TPMProperties =
					append(capabilityData.Data.TPMProperties, data.Data.TPMProperties...)
				s = len(data.Data.TPMProperties)
			case CapabilityPCRProperties:
				capabilityData.Data.PCRProperties =
					append(capabilityData.Data.PCRProperties, data.Data.PCRProperties...)
				s = len(data.Data.PCRProperties)
			case CapabilityECCCurves:
				capabilityData.Data.ECCCurves =
					append(capabilityData.Data.ECCCurves, data.Data.ECCCurves...)
				s = len(data.Data.ECCCurves)
			case CapabilityAuthPolicies:
				capabilityData.Data.AuthPolicies =
					append(capabilityData.Data.AuthPolicies, data.Data.AuthPolicies...)
				s = len(data.Data.AuthPolicies)
			default:
				return nil, InvalidResponseError{
					fmt.Sprintf("unexpected capability %v", data.Capability)}
			}
			nextProperty += uint32(s)
			remaining -= uint32(s)
		}

		if !moreData {
			break
		}

		if remaining < 1 {
			return nil, InvalidResponseError{"expected number of responses received but the TPM " +
				"indicates there are more to fetch"}
		}
	}

	return capabilityData, nil
}

func (t *tpmImpl) GetCapabilityAlgs(first AlgorithmId, propertyCount uint32) (AlgorithmPropertyList, error) {
	data, err := t.GetCapability(CapabilityAlgs, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Algorithms, nil
}

func (t *tpmImpl) GetCapabilityCommands(first CommandCode, propertyCount uint32) (CommandAttributesList, error) {
	data, err := t.GetCapability(CapabilityCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Command, nil
}

func (t *tpmImpl) GetCapabilityPPCommands(first CommandCode, propertyCount uint32) (CommandCodeList, error) {
	data, err := t.GetCapability(CapabilityPPCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.PPCommands, nil
}

func (t *tpmImpl) GetCapabilityAuditCommands(first CommandCode, propertyCount uint32) (CommandCodeList, error) {
	data, err := t.GetCapability(CapabilityAuditCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.AuditCommands, nil
}

func (t *tpmImpl) GetCapabilityHandles(handleType Handle, propertyCount uint32) (HandleList, error) {
	data, err := t.GetCapability(CapabilityHandles, uint32(handleType), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Handles, nil
}

func (t *tpmImpl) GetCapabilityPCRs() (PCRSelectionList, error) {
	data, err := t.GetCapability(CapabilityPCRs, 0, 100)
	if err != nil {
		return nil, err
	}
	return data.Data.AssignedPCR, nil
}

func (t *tpmImpl) GetCapabilityTPMProperties(first Property, propertyCount uint32) (TaggedTPMPropertyList,
	error) {
	data, err := t.GetCapability(CapabilityTPMProperties, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.TPMProperties, nil
}

func (t *tpmImpl) GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32) (TaggedPCRPropertyList,
	error) {
	data, err := t.GetCapability(CapabilityPCRProperties, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.PCRProperties, nil
}

func (t *tpmImpl) GetCapabilityECCCurves() (ECCCurveList, error) {
	data, err := t.GetCapability(CapabilityECCCurves, uint32(ECCCurveFirst), 100)
	if err != nil {
		return nil, err
	}
	return data.Data.ECCCurves, nil
}

func (t *tpmImpl) GetCapabilityAuthPolicies(first Handle, propertyCount uint32) (TaggedPolicyList, error) {
	data, err := t.GetCapability(CapabilityAuthPolicies, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.AuthPolicies, nil
}
