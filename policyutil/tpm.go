// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"

	"github.com/canonical/go-tpm2"
)

// TPMState provides a way for [Policy.Execute] to obtain TPM state in order
// to make decisions about which branch to execute.
type TPMState interface {
	// PCRValues returns the values of the PCRs associated with
	// the specified selection.
	PCRValues(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error)
}

type tpmState struct {
	tpm      *tpm2.TPMContext
	sessions []tpm2.SessionContext
}

// NewTPMState returns a new TPMState for the supplied context.
func NewTPMState(tpm *tpm2.TPMContext, sessions ...tpm2.SessionContext) TPMState {
	return &tpmState{
		tpm:      tpm,
		sessions: sessions,
	}
}

func (s *tpmState) PCRValues(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	_, values, err := s.tpm.PCRRead(pcrs, s.sessions...)
	return values, err
}

type nullTpmState struct{}

func (*nullTpmState) PCRValues(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	return nil, errors.New("no TPM state")
}
