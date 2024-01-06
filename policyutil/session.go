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

// policySession corresponds to a policy session
type policySession interface {
	Name() tpm2.Name
	HashAlg() tpm2.HashAlgorithmId
	NonceTPM() tpm2.Nonce

	PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error
	PolicyOR(pHashList tpm2.DigestList) error
	PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error
	PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error
	PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error
	PolicyCommandCode(code tpm2.CommandCode) error
	PolicyCpHash(cpHashA tpm2.Digest) error
	PolicyNameHash(nameHash tpm2.Digest) error
	PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error
	PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error
	PolicyAuthValue() error
	PolicyPassword() error
	PolicyGetDigest() (tpm2.Digest, error)
	PolicyNvWritten(writtenSet bool) error

	Save() (restore func() error, err error)
}

// tpmPolicySession is an implementation of policySession that runs on a TPM
type tpmPolicySession struct {
	tpm     TPMConnection
	session tpm2.SessionContext
}

func newTpmPolicySession(tpm TPMConnection, session tpm2.SessionContext) policySession {
	return &tpmPolicySession{
		tpm:     tpm,
		session: session,
	}
}

func (s *tpmPolicySession) Name() tpm2.Name {
	return s.session.Name()
}

func (s *tpmPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.session.HashAlg()
}

func (s *tpmPolicySession) NonceTPM() tpm2.Nonce {
	return s.session.NonceTPM()
}

func (s *tpmPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return s.tpm.PolicySigned(authKey, s.session, includeNonceTPM, cpHashA, policyRef, expiration, auth)
}

func (s *tpmPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return s.tpm.PolicySecret(authObject, s.session, cpHashA, policyRef, expiration, authObjectAuthSession)
}

func (s *tpmPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return s.tpm.PolicyTicket(s.session, timeout, cpHashA, policyRef, authName, ticket)
}

func (s *tpmPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return s.tpm.PolicyOR(s.session, pHashList)
}

func (s *tpmPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.tpm.PolicyPCR(s.session, pcrDigest, pcrs)
}

func (s *tpmPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return s.tpm.PolicyNV(auth, index, s.session, operandB, offset, operation, authAuthSession)
}

func (s *tpmPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return s.tpm.PolicyCounterTimer(s.session, operandB, offset, operation)
}

func (s *tpmPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	return s.tpm.PolicyCommandCode(s.session, code)
}

func (s *tpmPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return s.tpm.PolicyCpHash(s.session, cpHashA)
}

func (s *tpmPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	return s.tpm.PolicyNameHash(s.session, nameHash)
}

func (s *tpmPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return s.tpm.PolicyDuplicationSelect(s.session, objectName, newParentName, includeObject)
}

func (s *tpmPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return s.tpm.PolicyAuthorize(s.session, approvedPolicy, policyRef, keySign, verified)
}

func (s *tpmPolicySession) PolicyAuthValue() error {
	return s.tpm.PolicyAuthValue(s.session)
}

func (s *tpmPolicySession) PolicyPassword() error {
	return s.tpm.PolicyPassword(s.session)
}

func (s *tpmPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.tpm.PolicyGetDigest(s.session)
}

func (s *tpmPolicySession) PolicyNvWritten(writtenSet bool) error {
	return s.tpm.PolicyNvWritten(s.session, writtenSet)
}

func (c *tpmPolicySession) Save() (restore func() error, err error) {
	context, err := c.tpm.ContextSave(c.session)
	if err != nil {
		return nil, err
	}
	return func() error {
		if context == nil {
			// already restored
			return nil
		}

		hc, err := c.tpm.ContextLoad(context)
		if err != nil {
			return err
		}

		context = nil

		sc, ok := hc.(tpm2.SessionContext)
		if !ok {
			return errors.New("internal error: invalid context type")
		}
		c.session = sc
		return nil
	}, nil
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
	s.mustUpdateForCommand(command, mu.MakeRaw(name))

	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, mu.MakeRaw(policyRef))
	s.digest.Digest = h.Sum(nil)
}

func (*computePolicySession) Name() tpm2.Name {
	return nil
}

func (s *computePolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.digest.HashAlg
}

func (*computePolicySession) NonceTPM() tpm2.Nonce {
	return nil
}

func (s *computePolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if !authKey.Name().IsValid() {
		return nil, nil, errors.New("invalid authKey name")
	}

	s.policyUpdate(tpm2.CommandPolicySigned, authKey.Name(), policyRef)
	return nil, nil, nil
}

func (s *computePolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if !authObject.Name().IsValid() {
		return nil, nil, errors.New("invalid authObject name")
	}
	s.policyUpdate(tpm2.CommandPolicySecret, authObject.Name(), policyRef)
	return nil, nil, nil
}

func (s *computePolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	panic("not reached")
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
	s.mustUpdateForCommand(tpm2.CommandPolicyOR, mu.MakeRaw(digests.Bytes()))
	return nil
}

func (s *computePolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.updateForCommand(tpm2.CommandPolicyPCR, pcrs, mu.MakeRaw(pcrDigest))
}

func (s *computePolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	if !index.Name().IsValid() {
		return errors.New("invalid index name")
	}
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.MakeRaw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyNV, mu.MakeRaw(h.Sum(nil)), mu.MakeRaw(index.Name()))
	return nil
}

func (s *computePolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.MakeRaw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyCounterTimer, mu.MakeRaw(h.Sum(nil)))
	return nil
}

func (s *computePolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCommandCode, code)
	return nil
}

func (s *computePolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCpHash, mu.MakeRaw(cpHashA))
	return nil
}

func (s *computePolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNameHash, mu.MakeRaw(nameHash))
	return nil
}

func (s *computePolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	if !newParentName.IsValid() {
		return errors.New("invalid newParent name")
	}
	if includeObject {
		if !objectName.IsValid() {
			return errors.New("invalid object name")
		}
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.MakeRaw(objectName), mu.MakeRaw(newParentName), includeObject)
	} else {
		s.mustUpdateForCommand(tpm2.CommandPolicyDuplicationSelect, mu.MakeRaw(newParentName), includeObject)
	}
	return nil
}

func (s *computePolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	s.policyUpdate(tpm2.CommandPolicyAuthorize, keySign, policyRef)
	return nil
}

func (s *computePolicySession) PolicyAuthValue() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *computePolicySession) PolicyPassword() error {
	s.mustUpdateForCommand(tpm2.CommandPolicyAuthValue)
	return nil
}

func (s *computePolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.digest.Digest, nil
}

func (s *computePolicySession) PolicyNvWritten(writtenSet bool) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyNvWritten, writtenSet)
	return nil
}

func (*computePolicySession) Save() (restore func() error, err error) {
	return func() error { return nil }, nil
}

type nullPolicySession struct {
	alg tpm2.HashAlgorithmId
}

func newNullPolicySession(alg tpm2.HashAlgorithmId) *nullPolicySession {
	return &nullPolicySession{alg: alg}
}

func (*nullPolicySession) Name() tpm2.Name {
	return nil
}

func (s *nullPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.alg
}

func (*nullPolicySession) NonceTPM() tpm2.Nonce {
	return nil
}

func (*nullPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return nil, nil, nil
}

func (*nullPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return nil, nil, nil
}

func (*nullPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return nil
}

func (*nullPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (*nullPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return nil
}

func (*nullPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return nil
}

func (*nullPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return nil
}

func (*nullPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	return nil
}

func (*nullPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return nil
}

func (*nullPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	return nil
}

func (*nullPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return nil
}

func (*nullPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return nil
}

func (*nullPolicySession) PolicyAuthValue() error {
	return nil
}

func (*nullPolicySession) PolicyPassword() error {
	return nil
}

func (s *nullPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return make(tpm2.Digest, s.alg.Size()), nil
}

func (*nullPolicySession) PolicyNvWritten(writtenSet bool) error {
	return nil
}

func (*nullPolicySession) Save() (restore func() error, err error) {
	return func() error { return nil }, nil
}

type teePolicySession struct {
	target  policySession
	monitor policySession
}

func newTeePolicySession(target policySession, monitor policySession) *teePolicySession {
	return &teePolicySession{
		target:  target,
		monitor: monitor,
	}
}

func (s *teePolicySession) Name() tpm2.Name {
	return s.target.Name()
}

func (s *teePolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.target.HashAlg()
}

func (s *teePolicySession) NonceTPM() tpm2.Nonce {
	return s.target.NonceTPM()
}

func (s *teePolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if _, _, err := s.monitor.PolicySigned(authKey, includeNonceTPM, cpHashA, policyRef, expiration, auth); err != nil {
		return nil, nil, err
	}
	return s.target.PolicySigned(authKey, includeNonceTPM, cpHashA, policyRef, expiration, auth)
}

func (s *teePolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	if _, _, err := s.monitor.PolicySecret(authObject, cpHashA, policyRef, expiration, authObjectAuthSession); err != nil {
		return nil, nil, err
	}
	return s.target.PolicySecret(authObject, cpHashA, policyRef, expiration, authObjectAuthSession)
}

func (s *teePolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	if err := s.monitor.PolicyTicket(timeout, cpHashA, policyRef, authName, ticket); err != nil {
		return err
	}
	return s.target.PolicyTicket(timeout, cpHashA, policyRef, authName, ticket)
}

func (s *teePolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	if err := s.monitor.PolicyOR(pHashList); err != nil {
		return err
	}
	return s.target.PolicyOR(pHashList)
}

func (s *teePolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	if err := s.monitor.PolicyPCR(pcrDigest, pcrs); err != nil {
		return err
	}
	return s.target.PolicyPCR(pcrDigest, pcrs)
}

func (s *teePolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	if err := s.monitor.PolicyNV(auth, index, operandB, offset, operation, authAuthSession); err != nil {
		return err
	}
	return s.target.PolicyNV(auth, index, operandB, offset, operation, authAuthSession)
}

func (s *teePolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	if err := s.monitor.PolicyCounterTimer(operandB, offset, operation); err != nil {
		return err
	}
	return s.target.PolicyCounterTimer(operandB, offset, operation)
}

func (s *teePolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	if err := s.monitor.PolicyCommandCode(code); err != nil {
		return err
	}
	return s.target.PolicyCommandCode(code)
}

func (s *teePolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	if err := s.monitor.PolicyCpHash(cpHashA); err != nil {
		return err
	}
	return s.target.PolicyCpHash(cpHashA)
}

func (s *teePolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	if err := s.monitor.PolicyNameHash(nameHash); err != nil {
		return err
	}
	return s.target.PolicyNameHash(nameHash)
}

func (s *teePolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	if err := s.monitor.PolicyDuplicationSelect(objectName, newParentName, includeObject); err != nil {
		return err
	}
	return s.target.PolicyDuplicationSelect(objectName, newParentName, includeObject)
}

func (s *teePolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	if err := s.monitor.PolicyAuthorize(approvedPolicy, policyRef, keySign, verified); err != nil {
		return err
	}
	return s.target.PolicyAuthorize(approvedPolicy, policyRef, keySign, verified)
}

func (s *teePolicySession) PolicyAuthValue() error {
	if err := s.monitor.PolicyAuthValue(); err != nil {
		return err
	}
	return s.target.PolicyAuthValue()
}

func (s *teePolicySession) PolicyPassword() error {
	if err := s.monitor.PolicyPassword(); err != nil {
		return err
	}
	return s.target.PolicyPassword()
}

func (s *teePolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.target.PolicyGetDigest()
}

func (s *teePolicySession) PolicyNvWritten(writtenSet bool) error {
	if err := s.monitor.PolicyNvWritten(writtenSet); err != nil {
		return err
	}
	return s.target.PolicyNvWritten(writtenSet)
}

func (s *teePolicySession) Save() (restore func() error, err error) {
	return s.target.Save()
}

type branchDetailsCollector struct {
	alg     tpm2.HashAlgorithmId
	details *PolicyBranchDetails
}

func newBranchDetailsCollector(alg tpm2.HashAlgorithmId, details *PolicyBranchDetails) *branchDetailsCollector {
	return &branchDetailsCollector{
		alg:     alg,
		details: details,
	}
}

func (*branchDetailsCollector) Name() tpm2.Name {
	return tpm2.Name{}
}

func (c *branchDetailsCollector) HashAlg() tpm2.HashAlgorithmId {
	return c.alg
}

func (*branchDetailsCollector) NonceTPM() tpm2.Nonce {
	return nil
}

func (c *branchDetailsCollector) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	c.details.Signed = append(c.details.Signed, PolicyAuthorizationDetails{
		AuthName:  authKey.Name(),
		PolicyRef: policyRef,
	})
	return nil, nil, nil
}

func (c *branchDetailsCollector) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	c.details.Secret = append(c.details.Secret, PolicyAuthorizationDetails{
		AuthName:  authObject.Name(),
		PolicyRef: policyRef,
	})
	return nil, nil, nil
}

func (c *branchDetailsCollector) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	switch ticket.Tag {
	case tpm2.TagAuthSecret:
		c.details.Secret = append(c.details.Secret, PolicyAuthorizationDetails{
			AuthName:  authName,
			PolicyRef: policyRef,
		})
	case tpm2.TagAuthSigned:
		c.details.Signed = append(c.details.Signed, PolicyAuthorizationDetails{
			AuthName:  authName,
			PolicyRef: policyRef,
		})
	}
	return nil
}

func (*branchDetailsCollector) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (c *branchDetailsCollector) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	c.details.PCR = append(c.details.PCR, PolicyPCRDetails{
		PCRDigest: pcrDigest,
		PCRs:      pcrs,
	})
	return nil
}

func (c *branchDetailsCollector) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	c.details.NV = append(c.details.NV, PolicyNVDetails{
		Auth:      auth.Handle(),
		Index:     index.Handle(),
		Name:      index.Name(),
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return nil
}

func (c *branchDetailsCollector) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	c.details.CounterTimer = append(c.details.CounterTimer, PolicyCounterTimerDetails{
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return nil
}

func (c *branchDetailsCollector) PolicyCommandCode(code tpm2.CommandCode) error {
	c.details.policyCommandCode = append(c.details.policyCommandCode, code)
	return nil
}

func (c *branchDetailsCollector) PolicyCpHash(cpHashA tpm2.Digest) error {
	c.details.policyCpHash = append(c.details.policyCpHash, cpHashA)
	return nil
}

func (c *branchDetailsCollector) PolicyNameHash(nameHash tpm2.Digest) error {
	c.details.policyNameHash = append(c.details.policyNameHash, nameHash)
	return nil
}

func (c *branchDetailsCollector) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	nameHash, err := ComputeNameHash(c.alg, objectName, newParentName)
	if err != nil {
		return err
	}
	if err := c.PolicyNameHash(nameHash); err != nil {
		return err
	}
	return c.PolicyCommandCode(tpm2.CommandPolicyDuplicationSelect)
}

func (c *branchDetailsCollector) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	c.details.Authorize = append(c.details.Authorize, PolicyAuthorizationDetails{
		AuthName:  keySign,
		PolicyRef: policyRef,
	})
	return nil
}

func (c *branchDetailsCollector) PolicyAuthValue() error {
	c.details.AuthValueNeeded = true
	return nil
}

func (c *branchDetailsCollector) PolicyPassword() error {
	c.details.AuthValueNeeded = true
	return nil
}

func (c *branchDetailsCollector) PolicyGetDigest() (tpm2.Digest, error) {
	return nil, errors.New("not supported")
}

func (c *branchDetailsCollector) PolicyNvWritten(writtenSet bool) error {
	c.details.policyNvWritten = append(c.details.policyNvWritten, writtenSet)
	return nil
}

func (*branchDetailsCollector) Save() (restore func() error, err error) {
	return func() error { return nil }, nil
}
