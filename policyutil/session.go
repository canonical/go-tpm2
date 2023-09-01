// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// Session corresponds to a policy session
type Session interface {
	HashAlg() tpm2.HashAlgorithmId

	PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error
	PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error
	PolicyAuthValue() error
	PolicyCommandCode(code tpm2.CommandCode) error
	PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error
	PolicyCpHash(cpHashA tpm2.Digest) error
	PolicyNameHash(nameHash tpm2.Digest) error
	PolicyOR(pHashList tpm2.DigestList) error
	PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error
	PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error
	PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error
	PolicyPassword() error
	PolicyNvWritten(writtenSet bool) error

	PolicyGetDigest() (tpm2.Digest, error)
}

type tpmSession struct {
	tpm           *tpm2.TPMContext
	policySession tpm2.SessionContext
	sessions      []tpm2.SessionContext
}

// NewTPMSession creates a new Session for the supplied TPM context and TPM session.
func NewTPMSession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, sessions ...tpm2.SessionContext) Session {
	return &tpmSession{
		tpm:           tpm,
		policySession: policySession,
		sessions:      sessions,
	}
}

func (c *tpmSession) HashAlg() tpm2.HashAlgorithmId {
	return c.policySession.HashAlg()
}

func (c *tpmSession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return c.tpm.PolicyNV(auth, index, c.policySession, operandB, offset, operation, authAuthSession, c.sessions...)
}

func (c *tpmSession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return c.tpm.PolicySecret(authObject, c.policySession, cpHashA, policyRef, expiration, authObjectAuthSession, c.sessions...)
}

func (c *tpmSession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return c.tpm.PolicySigned(authKey, c.policySession, includeNonceTPM, cpHashA, policyRef, expiration, auth, c.sessions...)
}

func (c *tpmSession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return c.tpm.PolicyAuthorize(c.policySession, approvedPolicy, policyRef, keySign, verified, c.sessions...)
}

func (c *tpmSession) PolicyAuthValue() error {
	return c.tpm.PolicyAuthValue(c.policySession, c.sessions...)
}

func (c *tpmSession) PolicyCommandCode(code tpm2.CommandCode) error {
	return c.tpm.PolicyCommandCode(c.policySession, code, c.sessions...)
}

func (c *tpmSession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return c.tpm.PolicyCounterTimer(c.policySession, operandB, offset, operation, c.sessions...)
}

func (c *tpmSession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return c.tpm.PolicyCpHash(c.policySession, cpHashA, c.sessions...)
}

func (c *tpmSession) PolicyNameHash(nameHash tpm2.Digest) error {
	return c.tpm.PolicyNameHash(c.policySession, nameHash, c.sessions...)
}

func (c *tpmSession) PolicyOR(pHashList tpm2.DigestList) error {
	return c.tpm.PolicyOR(c.policySession, pHashList, c.sessions...)
}

func (c *tpmSession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return c.tpm.PolicyTicket(c.policySession, timeout, cpHashA, policyRef, authName, ticket, c.sessions...)
}

func (c *tpmSession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return c.tpm.PolicyPCR(c.policySession, pcrDigest, pcrs, c.sessions...)
}

func (c *tpmSession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return c.tpm.PolicyDuplicationSelect(c.policySession, objectName, newParentName, includeObject, c.sessions...)
}

func (c *tpmSession) PolicyPassword() error {
	return c.tpm.PolicyPassword(c.policySession, c.sessions...)
}

func (c *tpmSession) PolicyNvWritten(writtenSet bool) error {
	return c.tpm.PolicyNvWritten(c.policySession, writtenSet, c.sessions...)
}

func (c *tpmSession) PolicyGetDigest() (tpm2.Digest, error) {
	return c.tpm.PolicyGetDigest(c.policySession, c.sessions...)
}

// computePolicySession is an implementation of Session that computes a
// digest from a sequence of assertions.
type computePolicySession struct {
	digest *taggedHash
}

func newComputePolicySession(digest *taggedHash) *computePolicySession {
	return &computePolicySession{digest: digest}
}

func (s *computePolicySession) reset() {
	s.digest.Digest = make(tpm2.Digest, s.digest.HashAlg.Size())
}

func (s *computePolicySession) updateForCommand(command tpm2.CommandCode, params ...interface{}) error {
	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, command)
	if _, err := mu.MarshalToWriter(h, params...); err != nil {
		return err
	}
	s.digest.Digest = h.Sum(nil)
	return nil
}

func (s *computePolicySession) mustUpdateForCommand(command tpm2.CommandCode, params ...interface{}) {
	if err := s.updateForCommand(command, params...); err != nil {
		panic(err)
	}
}

func (s *computePolicySession) policyUpdate(command tpm2.CommandCode, name tpm2.Name, policyRef tpm2.Nonce) {
	s.mustUpdateForCommand(command, mu.Raw(name))

	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, mu.Raw(policyRef))
	s.digest.Digest = h.Sum(nil)
}

func (s *computePolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.digest.HashAlg
}

func (s *computePolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	if !index.Name().IsValid() {
		return errors.New("invalid index name")
	}
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.Raw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyNV, mu.Raw(h.Sum(nil)), mu.Raw(index.Name()))
	return nil
}

func (s *computePolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if !authObject.Name().IsValid() {
		return nil, nil, errors.New("invalid authObject name")
	}
	s.policyUpdate(tpm2.CommandPolicySecret, authObject.Name(), policyRef)
	return nil, nil, nil
}

func (s *computePolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if !authKey.Name().IsValid() {
		return nil, nil, errors.New("invalid authKey name")
	}

	s.policyUpdate(tpm2.CommandPolicySigned, authKey.Name(), policyRef)
	return nil, nil, nil
}

func (s *computePolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	s.policyUpdate(tpm2.CommandPolicyAuthorize, keySign, policyRef)
	return nil
}

func (s *computePolicySession) PolicyAuthValue() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *computePolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCommandCode, code)
	return nil
}

func (s *computePolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.Raw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyCounterTimer, mu.Raw(h.Sum(nil)))
	return nil
}

func (s *computePolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCpHash, mu.Raw(cpHashA))
	return nil
}

func (s *computePolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNameHash, mu.Raw(nameHash))
	return nil
}

func (s *computePolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	if len(pHashList) < 2 || len(pHashList) > 8 {
		return errors.New("invalid number of branches")
	}

	s.reset()

	digests := new(bytes.Buffer)
	for i, digest := range pHashList {
		if len(digest) != s.digest.HashAlg.Size() {
			return fmt.Errorf("invalid digest length at branch %d", i)
		}
		digests.Write(digest)
	}
	s.mustUpdateForCommand(tpm2.CommandPolicyOR, mu.Raw(digests.Bytes()))
	return nil
}

func (s *computePolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	panic("not reached")
}

func (s *computePolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.updateForCommand(tpm2.CommandPolicyPCR, pcrs, mu.Raw(pcrDigest))
}

func (s *computePolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	if !newParentName.IsValid() {
		return errors.New("invalid newParent name")
	}
	if includeObject {
		if !objectName.IsValid() {
			return errors.New("invalid object name")
		}
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.Raw(objectName), mu.Raw(newParentName), includeObject)
	} else {
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.Raw(newParentName), includeObject)
	}
	return nil
}

func (s *computePolicySession) PolicyPassword() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *computePolicySession) PolicyNvWritten(writtenSet bool) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNvWritten, writtenSet)
	return nil
}

func (s *computePolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.digest.Digest, nil
}

type nullPolicySession struct{}

func (*nullPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return tpm2.HashAlgorithmNull
}

func (*nullPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return nil
}

func (*nullPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return nil, nil, nil
}

func (*nullPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return nil, nil, nil
}

func (*nullPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return nil
}

func (*nullPolicySession) PolicyAuthValue() error {
	return nil
}

func (*nullPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	return nil
}

func (*nullPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return nil
}

func (*nullPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return nil
}

func (*nullPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	return nil
}

func (*nullPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (*nullPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return nil
}

func (*nullPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return nil
}

func (*nullPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return nil
}

func (*nullPolicySession) PolicyPassword() error {
	return nil
}

func (*nullPolicySession) PolicyNvWritten(writtenSet bool) error {
	return nil
}

func (*nullPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return nil, nil
}
