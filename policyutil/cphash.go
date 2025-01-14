// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// CpHash provides a way to obtain a command parameter digest.
type CpHash interface {
	// Digest returns the command parameter digest for the specified algorithm.
	Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error)
}

func computeCpHash(alg tpm2.HashAlgorithmId, command tpm2.CommandCode, handles []tpm2.Name, cpBytes []byte) (tpm2.Digest, error) {
	if !alg.Available() {
		return nil, errors.New("algorithm is not available")
	}

	h := alg.NewHash()

	binary.Write(h, binary.BigEndian, command)
	for _, handle := range handles {
		h.Write(handle.Name())
	}
	h.Write(cpBytes)

	return h.Sum(nil), nil
}

type commandParams struct {
	command tpm2.CommandCode
	handles []Named
	params  []interface{}
}

func (c *commandParams) Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	cpBytes, err := mu.MarshalToBytes(c.params...)
	if err != nil {
		return nil, err
	}
	var handles []tpm2.Name
	for i, handle := range c.handles {
		name := handle.Name()
		if !name.IsValid() {
			return nil, fmt.Errorf("invalid name for handle %d", i)
		}
		handles = append(handles, name)
	}
	return computeCpHash(alg, c.command, handles, cpBytes)
}

// CommandParameters returns a CpHash implementation for the specified command code, handles and
// parameters. The required parameters are defined in part 3 of the TPM 2.0 Library Specification
// for the specific command.
func CommandParameters(command tpm2.CommandCode, handles []Named, params ...interface{}) CpHash {
	return &commandParams{
		command: command,
		handles: handles,
		params:  params}
}

type cpDigest tpm2.TaggedHash

func (d *cpDigest) Digest(alg tpm2.HashAlgorithmId) (tpm2.Digest, error) {
	if alg != d.HashAlg {
		return nil, errors.New("no digest for algorithm")
	}
	return tpm2.Digest((*tpm2.TaggedHash)(d).Digest()), nil
}

// CommandParameterDigest returns a CpHash implementation for the specified algorithm and digest.
func CommandParameterDigest(alg tpm2.HashAlgorithmId, digest tpm2.Digest) CpHash {
	d := tpm2.MakeTaggedHash(alg, digest)
	return (*cpDigest)(&d)
}

// ComputeCpHash computes a command parameter digest from the specified command code, the supplied
// handles, and parameters using the specified digest algorithm.
//
// The required parameters is defined in part 3 of the TPM 2.0 Library Specification for the
// specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to
// a command and set of command parameters, such as [tpm2.TPMContext.PolicySigned],
// [tpm2.TPMContext.PolicySecret], [tpm2.TPMContext.PolicyTicket] and
// [tpm2.TPMContext.PolicyCpHash].
func ComputeCpHash(alg tpm2.HashAlgorithmId, command tpm2.CommandCode, handles []Named, params ...interface{}) (tpm2.Digest, error) {
	d := CommandParameters(command, handles, params...)
	return d.Digest(alg)
}
