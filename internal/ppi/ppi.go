// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package ppi

import (
	"sync"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/ppi"
)

type PPIBackend interface {
	SubmitOperation(op ppi.OperationId, arg *uint32) error
	StateTransitionAction() (ppi.StateTransitionAction, error)
	OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error)
	OperationResponse() (*ppi.OperationResponse, error)
}

type PPI struct {
	ppiType   ppi.Type
	version   ppi.Version
	functions PPIBackend

	staOnce  sync.Once
	sta      ppi.StateTransitionAction
	staError error

	ops map[ppi.OperationId]ppi.OperationStatus

	rspOnce  sync.Once
	rsp      *ppi.OperationResponse
	rspError error
}

func New(ppiType ppi.Type, version ppi.Version, functions PPIBackend) *PPI {
	return &PPI{
		ppiType:   ppiType,
		version:   version,
		functions: functions,
		ops:       make(map[ppi.OperationId]ppi.OperationStatus),
	}
}

func (p *PPI) submitOperation(op ppi.OperationId) error {
	return p.functions.SubmitOperation(op, nil)
}

func (p *PPI) Type() ppi.Type {
	return p.ppiType
}

func (p *PPI) Version() ppi.Version {
	return p.version
}

func (p *PPI) StateTransitionAction() (ppi.StateTransitionAction, error) {
	p.staOnce.Do(func() {
		p.sta, p.staError = p.functions.StateTransitionAction()
	})
	return p.sta, p.staError
}

func (p *PPI) OperationStatus(op ppi.OperationId) (ppi.OperationStatus, error) {
	status, exists := p.ops[op]
	if exists {
		return status, nil
	}
	status, err := p.functions.OperationStatus(op)
	if err != nil {
		return 0, err
	}
	p.ops[op] = status
	return status, nil
}

func (p *PPI) EnableTPM() error {
	return p.submitOperation(ppi.OperationEnableTPM)
}

func (p *PPI) DisableTPM() error {
	return p.submitOperation(ppi.OperationDisableTPM)
}

func (p *PPI) ClearTPM() error {
	return p.submitOperation(ppi.OperationClearTPM)
}

func (p *PPI) EnableAndClearTPM() error {
	return p.submitOperation(ppi.OperationEnableAndClearTPM)
}

func (p *PPI) SetPCRBanks(algs ...tpm2.HashAlgorithmId) error {
	bits := ppi.MakeHashAlgorithms(algs...)
	return p.functions.SubmitOperation(ppi.OperationSetPCRBanks, (*uint32)(&bits))
}

func (p *PPI) ChangeEPS() error {
	return p.submitOperation(ppi.OperationChangeEPS)
}

func (p *PPI) LogAllDigests() error {
	return p.submitOperation(ppi.OperationLogAllDigests)
}

func (p *PPI) DisableEndorsementAndEnableStorageHierarchy() error {
	return p.submitOperation(ppi.OperationDisableEndorsementEnableStorageHierarchy)
}

func (p *PPI) SetPPRequiredForOperation(op ppi.OperationId) error {
	op = op.SetPPRequiredOperationId()
	if op == ppi.NoOperation {
		return ppi.ErrOperationUnsupported
	}
	return p.submitOperation(op)
}

func (p *PPI) ClearPPRequiredForOperation(op ppi.OperationId) error {
	op = op.ClearPPRequiredOperationId()
	if op == ppi.NoOperation {
		return ppi.ErrOperationUnsupported
	}
	return p.submitOperation(op)
}

func (p *PPI) OperationResponse() (*ppi.OperationResponse, error) {
	p.rspOnce.Do(func() {
		p.rsp, p.rspError = p.functions.OperationResponse()
	})
	return p.rsp, p.rspError
}
