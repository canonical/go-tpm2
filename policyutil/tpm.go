// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"

	"github.com/canonical/go-tpm2"
)

type tpmConnection interface {
	PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error)
	NVReadPublic(handle tpm2.Handle) (*tpm2.NVPublic, error)
	ReadClock() (*tpm2.TimeInfo, error)
	VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error)
}

type nullTpmConnection struct{}

func (*nullTpmConnection) PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	return nil, errors.New("no TPM connection")
}

func (*nullTpmConnection) NVReadPublic(handle tpm2.Handle) (*tpm2.NVPublic, error) {
	return nil, errors.New("no TPM connection")
}

func (*nullTpmConnection) ReadClock() (*tpm2.TimeInfo, error) {
	return nil, errors.New("no TPM connection")
}

func (*nullTpmConnection) VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error) {
	return nil, errors.New("no TPM connection")
}
