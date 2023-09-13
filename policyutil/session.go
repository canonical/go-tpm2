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
	s.mustUpdateForCommand(command, mu.Raw(name))

	h := s.digest.HashAlg.NewHash()
	h.Write(s.digest.Digest)
	mu.MustMarshalToWriter(h, mu.Raw(policyRef))
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
	s.mustUpdateForCommand(tpm2.CommandPolicyOR, mu.Raw(digests.Bytes()))
	return nil
}

func (s *computePolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.updateForCommand(tpm2.CommandPolicyPCR, pcrs, mu.Raw(pcrDigest))
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

func (s *computePolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	h := s.digest.HashAlg.NewHash()
	mu.MustMarshalToWriter(h, mu.Raw(operandB), offset, operation)

	s.mustUpdateForCommand(tpm2.CommandPolicyCounterTimer, mu.Raw(h.Sum(nil)))
	return nil
}

func (s *computePolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	s.mustUpdateForCommand(tpm2.CommandPolicyCommandCode, code)
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

type proxyPolicySession struct {
	session policySession
	details *PolicyBranchDetails
}

func newProxyPolicySession(session policySession, details *PolicyBranchDetails) *proxyPolicySession {
	return &proxyPolicySession{
		session: session,
		details: details,
	}
}

func (s *proxyPolicySession) Name() tpm2.Name {
	return s.session.Name()
}

func (s *proxyPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.session.HashAlg()
}

func (s *proxyPolicySession) NonceTPM() tpm2.Nonce {
	return s.session.NonceTPM()
}

func (s *proxyPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.details.Signed = append(s.details.Signed, PolicyAuthorizationDetails{
		AuthName:  authKey.Name(),
		PolicyRef: policyRef,
	})
	return s.session.PolicySigned(authKey, includeNonceTPM, cpHashA, policyRef, expiration, auth)
}

func (s *proxyPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.details.Secret = append(s.details.Secret, PolicyAuthorizationDetails{
		AuthName:  authObject.Name(),
		PolicyRef: policyRef,
	})
	return s.session.PolicySecret(authObject, cpHashA, policyRef, expiration, authObjectAuthSession)
}

func (s *proxyPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	switch ticket.Tag {
	case tpm2.TagAuthSecret:
		s.details.Secret = append(s.details.Secret, PolicyAuthorizationDetails{
			AuthName:  authName,
			PolicyRef: policyRef,
		})
	case tpm2.TagAuthSigned:
		s.details.Signed = append(s.details.Signed, PolicyAuthorizationDetails{
			AuthName:  authName,
			PolicyRef: policyRef,
		})
	}
	return s.session.PolicyTicket(timeout, cpHashA, policyRef, authName, ticket)
}

func (s *proxyPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return s.session.PolicyOR(pHashList)
}

func (s *proxyPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	s.details.PCR = append(s.details.PCR, PolicyPCRDetails{
		PCRDigest: pcrDigest,
		PCRs:      pcrs,
	})
	return s.session.PolicyPCR(pcrDigest, pcrs)
}

func (s *proxyPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	s.details.NV = append(s.details.NV, PolicyNVDetails{
		Auth:      auth.Handle(),
		Index:     index.Handle(),
		Name:      index.Name(),
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return s.session.PolicyNV(auth, index, operandB, offset, operation, authAuthSession)
}

func (s *proxyPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	s.details.CounterTimer = append(s.details.CounterTimer, PolicyCounterTimerDetails{
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return s.session.PolicyCounterTimer(operandB, offset, operation)
}

func (s *proxyPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	s.details.policyCommandCode = append(s.details.policyCommandCode, code)
	return s.session.PolicyCommandCode(code)
}

func (s *proxyPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.details.policyCpHash = append(s.details.policyCpHash, cpHashA)
	return s.session.PolicyCpHash(cpHashA)
}

func (s *proxyPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	s.details.policyNameHash = append(s.details.policyNameHash, nameHash)
	return s.session.PolicyNameHash(nameHash)
}

func (s *proxyPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	nameHash, _ := ComputeNameHash(s.session.HashAlg(), objectName, newParentName)
	s.details.policyNameHash = append(s.details.policyNameHash, nameHash)
	s.details.policyCommandCode = append(s.details.policyCommandCode, tpm2.CommandPolicyDuplicationSelect)
	return s.session.PolicyDuplicationSelect(objectName, newParentName, includeObject)
}

func (s *proxyPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	s.details.Authorize = append(s.details.Authorize, PolicyAuthorizationDetails{
		AuthName:  keySign,
		PolicyRef: policyRef,
	})
	return s.session.PolicyAuthorize(approvedPolicy, policyRef, keySign, verified)
}

func (s *proxyPolicySession) PolicyAuthValue() error {
	s.details.AuthValueNeeded = true
	return s.session.PolicyAuthValue()
}

func (s *proxyPolicySession) PolicyPassword() error {
	s.details.AuthValueNeeded = true
	return s.session.PolicyPassword()
}

func (s *proxyPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.session.PolicyGetDigest()
}

func (s *proxyPolicySession) PolicyNvWritten(writtenSet bool) error {
	s.details.policyNvWritten = append(s.details.policyNvWritten, writtenSet)
	return s.session.PolicyNvWritten(writtenSet)
}

func (s *proxyPolicySession) Save() (restore func() error, err error) {
	return s.session.Save()
}
