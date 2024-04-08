// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// policySession corresponds to a policy session. This is a limited version
// of PolicySession that's used in all code paths in Policy.
type policySession interface {
	Name() tpm2.Name
	HashAlg() tpm2.HashAlgorithmId

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
}

// SessionContext corresponds to a session on the TPM
type SessionContext interface {
	Session() tpm2.SessionContext
	Save() (restore func() error, err error)
	Flush()
}

// PolicySession corresponds to a policy session
type PolicySession interface {
	Context() SessionContext

	Name() tpm2.Name
	HashAlg() tpm2.HashAlgorithmId

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
}

type tpmSessionContext struct {
	tpm     *tpm2.TPMContext
	session tpm2.SessionContext
}

func newTpmSessionContext(tpm *tpm2.TPMContext, session tpm2.SessionContext) *tpmSessionContext {
	return &tpmSessionContext{
		tpm:     tpm,
		session: session,
	}
}

func (s *tpmSessionContext) Session() tpm2.SessionContext {
	return s.session
}

func (s *tpmSessionContext) Save() (restore func() error, err error) {
	context, err := s.tpm.ContextSave(s.session)
	if err != nil {
		return nil, err
	}
	return func() error {
		if context == nil {
			// already restored
			return nil
		}

		hc, err := s.tpm.ContextLoad(context)
		if err != nil {
			return err
		}

		context = nil

		sc, ok := hc.(tpm2.SessionContext)
		if !ok {
			return errors.New("internal error: invalid context type")
		}
		s.session = sc
		return nil
	}, nil
}

func (s *tpmSessionContext) Flush() {
	s.tpm.FlushContext(s.session)
}

type NewPolicySessionFn func(*tpm2.TPMContext, tpm2.SessionContext, ...tpm2.SessionContext) PolicySession

// tpmPolicySession is an implementation of policySession that runs on a TPM
type tpmPolicySession struct {
	tpm           *tpm2.TPMContext
	policySession SessionContext
	sessions      []tpm2.SessionContext
}

func NewTPMPolicySession(tpm *tpm2.TPMContext, policySession tpm2.SessionContext, sessions ...tpm2.SessionContext) PolicySession {
	return &tpmPolicySession{
		tpm:           tpm,
		policySession: newTpmSessionContext(tpm, policySession),
		sessions:      sessions,
	}
}

func (s *tpmPolicySession) Context() SessionContext {
	return s.policySession
}

func (s *tpmPolicySession) Name() tpm2.Name {
	return s.policySession.Session().Name()
}

func (s *tpmPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.policySession.Session().Params().HashAlg
}

func (s *tpmPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return s.tpm.PolicySigned(authKey, s.policySession.Session(), includeNonceTPM, cpHashA, policyRef, expiration, auth, s.sessions...)
}

func (s *tpmPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return s.tpm.PolicySecret(authObject, s.policySession.Session(), cpHashA, policyRef, expiration, authObjectAuthSession, s.sessions...)
}

func (s *tpmPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return s.tpm.PolicyTicket(s.policySession.Session(), timeout, cpHashA, policyRef, authName, ticket, s.sessions...)
}

func (s *tpmPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return s.tpm.PolicyOR(s.policySession.Session(), pHashList, s.sessions...)
}

func (s *tpmPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.tpm.PolicyPCR(s.policySession.Session(), pcrDigest, pcrs, s.sessions...)
}

func (s *tpmPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return s.tpm.PolicyNV(auth, index, s.policySession.Session(), operandB, offset, operation, authAuthSession, s.sessions...)
}

func (s *tpmPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return s.tpm.PolicyCounterTimer(s.policySession.Session(), operandB, offset, operation, s.sessions...)
}

func (s *tpmPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	return s.tpm.PolicyCommandCode(s.policySession.Session(), code, s.sessions...)
}

func (s *tpmPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return s.tpm.PolicyCpHash(s.policySession.Session(), cpHashA, s.sessions...)
}

func (s *tpmPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	return s.tpm.PolicyNameHash(s.policySession.Session(), nameHash, s.sessions...)
}

func (s *tpmPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return s.tpm.PolicyDuplicationSelect(s.policySession.Session(), objectName, newParentName, includeObject, s.sessions...)
}

func (s *tpmPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return s.tpm.PolicyAuthorize(s.policySession.Session(), approvedPolicy, policyRef, keySign, verified, s.sessions...)
}

func (s *tpmPolicySession) PolicyAuthValue() error {
	return s.tpm.PolicyAuthValue(s.policySession.Session(), s.sessions...)
}

func (s *tpmPolicySession) PolicyPassword() error {
	return s.tpm.PolicyPassword(s.policySession.Session(), s.sessions...)
}

func (s *tpmPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.tpm.PolicyGetDigest(s.policySession.Session(), s.sessions...)
}

func (s *tpmPolicySession) PolicyNvWritten(writtenSet bool) error {
	return s.tpm.PolicyNvWritten(s.policySession.Session(), writtenSet, s.sessions...)
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

type teePolicySession struct {
	outputs []policySession
}

func newTeePolicySession(outputs ...policySession) *teePolicySession {
	return &teePolicySession{outputs: outputs}
}

func (s *teePolicySession) head() policySession {
	return s.outputs[0]
}

func (s *teePolicySession) forEachExceptHead(fn func(policySession) error) error {
	for _, session := range s.outputs[1:] {
		if err := fn(session); err != nil {
			return err
		}
	}
	return nil
}

func (s *teePolicySession) forEach(fn func(policySession) error) error {
	for _, session := range s.outputs {
		if err := fn(session); err != nil {
			return err
		}
	}
	return nil
}

func (s *teePolicySession) Name() tpm2.Name {
	return s.head().Name()
}

func (s *teePolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.head().HashAlg()
}

func (s *teePolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	timeout, ticket, err := s.head().PolicySigned(authKey, includeNonceTPM, cpHashA, policyRef, expiration, auth)
	if err != nil {
		return nil, nil, err
	}
	if err := s.forEachExceptHead(func(session policySession) error {
		_, _, err := session.PolicySigned(authKey, includeNonceTPM, cpHashA, policyRef, expiration, auth)
		return err
	}); err != nil {
		return nil, nil, err
	}
	return timeout, ticket, nil
}

func (s *teePolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	timeout, ticket, err := s.head().PolicySecret(authObject, cpHashA, policyRef, expiration, authObjectAuthSession)
	if err != nil {
		return nil, nil, err
	}
	if err := s.forEachExceptHead(func(session policySession) error {
		_, _, err := session.PolicySecret(authObject, cpHashA, policyRef, expiration, authObjectAuthSession)
		return err
	}); err != nil {
		return nil, nil, err
	}
	return timeout, ticket, nil
}

func (s *teePolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyTicket(timeout, cpHashA, policyRef, authName, ticket)
	})
}

func (s *teePolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyOR(pHashList)
	})
}

func (s *teePolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyPCR(pcrDigest, pcrs)
	})
}

func (s *teePolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyNV(auth, index, operandB, offset, operation, authAuthSession)
	})
}

func (s *teePolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyCounterTimer(operandB, offset, operation)
	})
}

func (s *teePolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyCommandCode(code)
	})
}

func (s *teePolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyCpHash(cpHashA)
	})
}

func (s *teePolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyNameHash(nameHash)
	})
}

func (s *teePolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyDuplicationSelect(objectName, newParentName, includeObject)
	})
}

func (s *teePolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyAuthorize(approvedPolicy, policyRef, keySign, verified)
	})
}

func (s *teePolicySession) PolicyAuthValue() error {
	return s.forEach(func(session policySession) error {
		return session.PolicyAuthValue()
	})
}

func (s *teePolicySession) PolicyPassword() error {
	return s.forEach(func(session policySession) error {
		return session.PolicyPassword()
	})
}

func (s *teePolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return s.head().PolicyGetDigest()
}

func (s *teePolicySession) PolicyNvWritten(writtenSet bool) error {
	return s.forEach(func(session policySession) error {
		return session.PolicyNvWritten(writtenSet)
	})
}

type recorderPolicySession struct {
	alg     tpm2.HashAlgorithmId
	details *PolicyBranchDetails
}

func newRecorderPolicySession(alg tpm2.HashAlgorithmId, details *PolicyBranchDetails) *recorderPolicySession {
	return &recorderPolicySession{
		alg:     alg,
		details: details,
	}
}

func (*recorderPolicySession) Name() tpm2.Name {
	return nil
}

func (s *recorderPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.alg
}

func (s *recorderPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.details.Signed = append(s.details.Signed, PolicyAuthorizationDetails{
		AuthName:  authKey.Name(),
		PolicyRef: policyRef,
	})
	if len(cpHashA) > 0 {
		if err := s.PolicyCpHash(cpHashA); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, nil
}

func (s *recorderPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	s.details.Secret = append(s.details.Secret, PolicyAuthorizationDetails{
		AuthName:  authObject.Name(),
		PolicyRef: policyRef,
	})
	if len(cpHashA) > 0 {
		if err := s.PolicyCpHash(cpHashA); err != nil {
			return nil, nil, err
		}
	}
	return nil, nil, nil
}

func (s *recorderPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
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
	return nil
}

func (*recorderPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (s *recorderPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	s.details.PCR = append(s.details.PCR, PolicyPCRDetails{
		PCRDigest: pcrDigest,
		PCRs:      pcrs,
	})
	return nil
}

func (s *recorderPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	s.details.NV = append(s.details.NV, PolicyNVDetails{
		Auth:      auth.Handle(),
		Index:     index.Handle(),
		Name:      index.Name(),
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return nil
}

func (s *recorderPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	s.details.CounterTimer = append(s.details.CounterTimer, PolicyCounterTimerDetails{
		OperandB:  operandB,
		Offset:    offset,
		Operation: operation,
	})
	return nil
}

func (s *recorderPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	s.details.policyCommandCode = append(s.details.policyCommandCode, code)
	return nil
}

func (s *recorderPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	s.details.policyCpHash = append(s.details.policyCpHash, cpHashA)
	return nil
}

func (s *recorderPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	s.details.policyNameHash = append(s.details.policyNameHash, nameHash)
	return nil
}

func (s *recorderPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	nameHash, err := ComputeNameHash(s.alg, objectName, newParentName)
	if err != nil {
		return err
	}
	if err := s.PolicyNameHash(nameHash); err != nil {
		return err
	}
	return s.PolicyCommandCode(tpm2.CommandDuplicate)
}

func (s *recorderPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	s.details.Authorize = append(s.details.Authorize, PolicyAuthorizationDetails{
		AuthName:  keySign,
		PolicyRef: policyRef,
	})
	return nil
}

func (s *recorderPolicySession) PolicyAuthValue() error {
	s.details.AuthValueNeeded = true
	return nil
}

func (s *recorderPolicySession) PolicyPassword() error {
	s.details.AuthValueNeeded = true
	return nil
}

func (s *recorderPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return nil, errors.New("not supported")
}

func (s *recorderPolicySession) PolicyNvWritten(writtenSet bool) error {
	s.details.policyNvWritten = append(s.details.policyNvWritten, writtenSet)
	return nil
}

type stringifierPolicySession struct {
	alg   tpm2.HashAlgorithmId
	w     io.Writer
	depth int
}

func newStringifierPolicySession(alg tpm2.HashAlgorithmId, w io.Writer, depth int) *stringifierPolicySession {
	return &stringifierPolicySession{
		alg:   alg,
		w:     w,
		depth: depth,
	}
}

func (*stringifierPolicySession) Name() tpm2.Name {
	return nil
}

func (s *stringifierPolicySession) HashAlg() tpm2.HashAlgorithmId {
	return s.alg
}

func (s *stringifierPolicySession) PolicySigned(authKey tpm2.ResourceContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicySigned(authKey:%#x, policyRef:%#x)", s.depth*3, "", authKey.Name(), policyRef)
	return nil, nil, err
}

func (s *stringifierPolicySession) PolicySecret(authObject tpm2.ResourceContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicySecret(authObject:%#x, policyRef:%#x)", s.depth*3, "", authObject.Name(), policyRef)
	return nil, nil, err
}

func (s *stringifierPolicySession) PolicyTicket(timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyTicket(tag:%v, auth:%#x, policyRef:%#x)", s.depth*3, "", ticket.Tag, authName, policyRef)
	return err
}

func (s *stringifierPolicySession) PolicyOR(pHashList tpm2.DigestList) error {
	return nil
}

func (s *stringifierPolicySession) PolicyPCR(pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyPCR(pcrDigest:%#x, pcrs:%v)", s.depth*3, "", pcrDigest, pcrs)
	return err
}

func (s *stringifierPolicySession) PolicyNV(auth, index tpm2.ResourceContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyNV(index:%#x, operandB:%#x, offset:%d, operation:%v)", s.depth*3, "", index.Name(), operandB, offset, operation)
	return err
}

func (s *stringifierPolicySession) PolicyCounterTimer(operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyCounterTimer(operandB:%#x, offset:%d, operation:%v)", s.depth*3, "", operandB, offset, operation)
	return err
}

func (s *stringifierPolicySession) PolicyCommandCode(code tpm2.CommandCode) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyCommandCode(%v)", s.depth*3, "", code)
	return err
}

func (s *stringifierPolicySession) PolicyCpHash(cpHashA tpm2.Digest) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyCpHash(%#x)", s.depth*3, "", cpHashA)
	return err
}

func (s *stringifierPolicySession) PolicyNameHash(nameHash tpm2.Digest) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyNameHash(%#x)", s.depth*3, "", nameHash)
	return err
}

func (s *stringifierPolicySession) PolicyDuplicationSelect(objectName, newParentName tpm2.Name, includeObject bool) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyDuplicationSelect(objectName:%#x, newParentName:%#x, includeObject:%t)", s.depth*3, "", objectName, newParentName, includeObject)
	return err
}

func (s *stringifierPolicySession) PolicyAuthorize(approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyAuthorize(policyRef:%#x, keySign:%#x)", s.depth*3, "", policyRef, keySign)
	return err
}

func (s *stringifierPolicySession) PolicyAuthValue() error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyAuthValue()", s.depth*3, "")
	return err
}

func (s *stringifierPolicySession) PolicyPassword() error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyPassword()", s.depth*3, "")
	return err
}

func (s *stringifierPolicySession) PolicyGetDigest() (tpm2.Digest, error) {
	return nil, errors.New("not supported")
}

func (s *stringifierPolicySession) PolicyNvWritten(writtenSet bool) error {
	_, err := fmt.Fprintf(s.w, "\n%*s PolicyNvWritten(%t)", s.depth*3, "", writtenSet)
	return err
}

type mockSessionContext struct{}

func (*mockSessionContext) Session() tpm2.SessionContext {
	return nil
}

func (*mockSessionContext) Save() (func() error, error) {
	return func() error { return nil }, nil
}

func (*mockSessionContext) Flush() {}
