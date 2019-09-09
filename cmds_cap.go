// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"fmt"
)

func (t *tpmContext) GetCapability(capability Capability, property, propertyCount uint32) (*CapabilityData,
	error) {
	var capabilityData *CapabilityData

	nextProperty := property
	remaining := propertyCount

	for {
		var moreData bool
		var data CapabilityData

		if err := t.RunCommand(CommandGetCapability, nil, Separator, capability, nextProperty, remaining,
			Separator, Separator, &moreData, &data); err != nil {
			return nil, err
		}

		if data.Capability != capability {
			return nil, fmt.Errorf("TPM responded with data for the wrong capability for command "+
				"%s (got %s)", CommandGetCapability, data.Capability)
		}

		if capabilityData == nil {
			capabilityData = &data
		} else {
			var s int
			switch data.Capability {
			case CapabilityAlgs:
				capabilityData.Data.Data =
					append(capabilityData.Data.Algorithms(), data.Data.Algorithms()...)
				s = len(data.Data.Algorithms())
			case CapabilityHandles:
				capabilityData.Data.Data =
					append(capabilityData.Data.Handles(), data.Data.Handles()...)
				s = len(data.Data.Handles())
			case CapabilityCommands:
				capabilityData.Data.Data =
					append(capabilityData.Data.Command(), data.Data.Command()...)
				s = len(data.Data.Command())
			case CapabilityPPCommands:
				capabilityData.Data.Data =
					append(capabilityData.Data.PPCommands(), data.Data.PPCommands()...)
				s = len(data.Data.PPCommands())
			case CapabilityAuditCommands:
				capabilityData.Data.Data =
					append(capabilityData.Data.AuditCommands(), data.Data.AuditCommands()...)
				s = len(data.Data.AuditCommands())
			case CapabilityPCRs:
				capabilityData.Data.Data =
					append(capabilityData.Data.AssignedPCR(), data.Data.AssignedPCR()...)
				s = len(data.Data.AssignedPCR())
			case CapabilityTPMProperties:
				capabilityData.Data.Data =
					append(capabilityData.Data.TPMProperties(), data.Data.TPMProperties()...)
				s = len(data.Data.TPMProperties())
			case CapabilityPCRProperties:
				capabilityData.Data.Data =
					append(capabilityData.Data.PCRProperties(), data.Data.PCRProperties()...)
				s = len(data.Data.PCRProperties())
			case CapabilityECCCurves:
				capabilityData.Data.Data =
					append(capabilityData.Data.ECCCurves(), data.Data.ECCCurves()...)
				s = len(data.Data.ECCCurves())
			case CapabilityAuthPolicies:
				capabilityData.Data.Data =
					append(capabilityData.Data.AuthPolicies(), data.Data.AuthPolicies()...)
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

func (t *tpmContext) GetCapabilityAlgs(first AlgorithmId, propertyCount uint32) (AlgorithmPropertyList, error) {
	data, err := t.GetCapability(CapabilityAlgs, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Algorithms(), nil
}

func (t *tpmContext) GetCapabilityCommands(first CommandCode, propertyCount uint32) (CommandAttributesList,
	error) {
	data, err := t.GetCapability(CapabilityCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Command(), nil
}

func (t *tpmContext) GetCapabilityPPCommands(first CommandCode, propertyCount uint32) (CommandCodeList, error) {
	data, err := t.GetCapability(CapabilityPPCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.PPCommands(), nil
}

func (t *tpmContext) GetCapabilityAuditCommands(first CommandCode, propertyCount uint32) (CommandCodeList,
	error) {
	data, err := t.GetCapability(CapabilityAuditCommands, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.AuditCommands(), nil
}

func (t *tpmContext) GetCapabilityHandles(handleType Handle, propertyCount uint32) (HandleList, error) {
	data, err := t.GetCapability(CapabilityHandles, uint32(handleType), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.Handles(), nil
}

func (t *tpmContext) GetCapabilityPCRs() (PCRSelectionList, error) {
	data, err := t.GetCapability(CapabilityPCRs, 0, 100)
	if err != nil {
		return nil, err
	}
	return data.Data.AssignedPCR(), nil
}

func (t *tpmContext) GetCapabilityTPMProperties(first Property, propertyCount uint32) (TaggedTPMPropertyList,
	error) {
	data, err := t.GetCapability(CapabilityTPMProperties, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.TPMProperties(), nil
}

func (t *tpmContext) GetCapabilityPCRProperties(first PropertyPCR, propertyCount uint32) (TaggedPCRPropertyList,
	error) {
	data, err := t.GetCapability(CapabilityPCRProperties, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.PCRProperties(), nil
}

func (t *tpmContext) GetCapabilityECCCurves() (ECCCurveList, error) {
	data, err := t.GetCapability(CapabilityECCCurves, uint32(ECCCurveFirst), 100)
	if err != nil {
		return nil, err
	}
	return data.Data.ECCCurves(), nil
}

func (t *tpmContext) GetCapabilityAuthPolicies(first Handle, propertyCount uint32) (TaggedPolicyList, error) {
	data, err := t.GetCapability(CapabilityAuthPolicies, uint32(first), propertyCount)
	if err != nil {
		return nil, err
	}
	return data.Data.AuthPolicies(), nil
}
