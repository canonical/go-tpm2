// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// ComputeCpHash computes a command parameter digest from the specified command code and provided command parameters, using the
// digest algorithm specified by hashAlg. The params argument corresponds to the handle and parameters area of a command (in that
// order), separated by the Separator sentinel value. Handle arguments must be represented by either the Handle type or
// ResourceContext type.
//
// The number of command handles and number / type of command parameters can be determined by looking in part 3 of the TPM 2.0
// Library Specification for the specific command.
//
// The result of this is useful for extended authorization commands that bind an authorization to a command and set of command
// parameters, such as TPMContext.PolicySigned, TPMContext.PolicySecret, TPMContext.PolicyTicket and TPMContext.PolicyCpHash.
func ComputeCpHash(hashAlg AlgorithmId, command CommandCode, params ...interface{}) (Digest, error) {
	var handles []Name
	var i int

	for _, param := range params {
		if param == Separator {
			break
		}
		i++
		switch p := param.(type) {
		case Handle:
			handles = append(handles, permanentContext(p).Name())
		case ResourceContext:
			handles = append(handles, p.Name())
		default:
			return nil, makeInvalidParamError("params", "parameter in handle area is not a Handle or ResourceContext")
		}
	}

	var cpBytes []byte

	if i < len(params)-1 {
		var err error
		cpBytes, err = MarshalToBytes(params[i+1:]...)
		if err != nil {
			return nil, fmt.Errorf("cannot marshal command parameters: %v", err)
		}
	}

	return cryptComputeCpHash(hashAlg, command, handles, cpBytes), nil
}

type trialAuthPolicyExtendContext struct {
	t *TrialAuthPolicy
	h hash.Hash
}

func (c *trialAuthPolicyExtendContext) Write(p []byte) (int, error) {
	return c.h.Write(p)
}

func (c *trialAuthPolicyExtendContext) commit() {
	c.t.digest = c.h.Sum(nil)
}

// TrialAuthPolicy provides a mechanism for computing authorization policy digests without having to execute a trial authorization
// policy session on the TPM. An advantage of this is that it is possible to compute digests for PolicySecret and PolicyNV assertions
// without knowledge of the authorization value of the authorizing entities used for those commands.
type TrialAuthPolicy struct {
	alg    AlgorithmId
	digest Digest
}

// ComputeAuthPolicy creates a new context for computing an authorization policy digest.
func ComputeAuthPolicy(alg AlgorithmId) (*TrialAuthPolicy, error) {
	if !cryptIsKnownDigest(alg) {
		return nil, errors.New("invalid algorithm")
	}
	return &TrialAuthPolicy{alg: alg, digest: make(Digest, cryptGetDigestSize(alg))}, nil
}

func (p *TrialAuthPolicy) beginExtend(commandCode CommandCode) *trialAuthPolicyExtendContext {
	h := cryptConstructHash(p.alg)
	h.Write(p.digest)
	binary.Write(h, binary.BigEndian, commandCode)
	return &trialAuthPolicyExtendContext{t: p, h: h}
}

func (p *TrialAuthPolicy) policyUpdate(commandCode CommandCode, arg2 Name, arg3 Nonce) {
	h1 := p.beginExtend(commandCode)
	h1.Write(arg2)
	h1.commit()

	h2 := cryptConstructHash(p.alg)
	h2.Write(p.digest)
	h2.Write(arg3)

	p.digest = h2.Sum(nil)
}

func (p *TrialAuthPolicy) resetDigest() {
	p.digest = make(Digest, len(p.digest))
}

// GetDigest returns the current digest computed for the policy assertions executed so far.
func (p *TrialAuthPolicy) GetDigest() Digest {
	return p.digest
}

func (p *TrialAuthPolicy) PolicySigned(authObject ResourceContext, policyRef Nonce) {
	p.policyUpdate(CommandPolicySigned, authObject.Name(), policyRef)
}

func (p *TrialAuthPolicy) PolicySecret(authObject ResourceContext, policyRef Nonce) {
	p.policyUpdate(CommandPolicySecret, authObject.Name(), policyRef)
}

func (p *TrialAuthPolicy) PolicyOR(pHashList DigestList) {
	p.resetDigest()

	digests := new(bytes.Buffer)
	for _, digest := range pHashList {
		digests.Write(digest)
	}

	h := p.beginExtend(CommandPolicyOR)
	digests.WriteTo(h)
	h.commit()
}

func (p *TrialAuthPolicy) PolicyPCR(pcrDigest Digest, pcrs PCRSelectionList) {
	h := p.beginExtend(CommandPolicyPCR)
	if err := MarshalToWriter(h, pcrs); err != nil {
		panic(fmt.Sprintf("cannot marshal PCR selection: %v", err))
	}
	h.Write(pcrDigest)
	h.commit()
}

func (p *TrialAuthPolicy) PolicyNV(nvIndex ResourceContext, operandB Operand, offset uint16,
	operation ArithmeticOp) {
	h1 := cryptConstructHash(p.alg)
	h1.Write(operandB)
	binary.Write(h1, binary.BigEndian, offset)
	binary.Write(h1, binary.BigEndian, operation)

	args := h1.Sum(nil)

	h2 := p.beginExtend(CommandPolicyNV)
	h2.Write(args)
	h2.Write(nvIndex.Name())
	h2.commit()
}

func (p *TrialAuthPolicy) PolicyCommandCode(code CommandCode) {
	h := p.beginExtend(CommandPolicyCommandCode)
	binary.Write(h, binary.BigEndian, code)
	h.commit()
}

func (p *TrialAuthPolicy) PolicyAuthValue() {
	p.beginExtend(CommandPolicyAuthValue).commit()
}

func (p *TrialAuthPolicy) PolicyPassword() {
	// This extends the same value as PolicyAuthValue - see section 23.18 of part 3 of the "TPM 2.0 Library
	// Specification"
	p.beginExtend(CommandPolicyAuthValue).commit()
}
