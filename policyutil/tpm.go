// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"github.com/canonical/go-tpm2"
)

// TPMConnection provides a way for [Policy.Execute] to communicate with a TPM.
type TPMConnection interface {
	StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (tpm2.SessionContext, error)

	LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (tpm2.ResourceContext, error)
	ReadPublic(handle tpm2.HandleContext) (*tpm2.Public, tpm2.Name, tpm2.Name, error)

	VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error)

	PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error)

	PolicySigned(authKey tpm2.ResourceContext, policySession tpm2.SessionContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicySecret(authObject tpm2.ResourceContext, policySession tpm2.SessionContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error)
	PolicyTicket(policySession tpm2.SessionContext, timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error
	PolicyOR(policySession tpm2.SessionContext, pHashList tpm2.DigestList) error
	PolicyPCR(policySession tpm2.SessionContext, pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error
	PolicyNV(auth, index tpm2.ResourceContext, policySession tpm2.SessionContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error
	PolicyCounterTimer(policySession tpm2.SessionContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error
	PolicyCommandCode(policySession tpm2.SessionContext, code tpm2.CommandCode) error
	PolicyCpHash(policySession tpm2.SessionContext, cpHashA tpm2.Digest) error
	PolicyNameHash(policySession tpm2.SessionContext, nameHash tpm2.Digest) error
	PolicyDuplicationSelect(policySession tpm2.SessionContext, objectName, newParentName tpm2.Name, includeObject bool) error
	PolicyAuthorize(policySession tpm2.SessionContext, approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error
	PolicyAuthValue(policySession tpm2.SessionContext) error
	PolicyPassword(policySession tpm2.SessionContext) error
	PolicyGetDigest(policySession tpm2.SessionContext) (tpm2.Digest, error)
	PolicyNvWritten(policySession tpm2.SessionContext, writtenSet bool) error

	ContextSave(handle tpm2.HandleContext) (*tpm2.Context, error)
	ContextLoad(context *tpm2.Context) (tpm2.HandleContext, error)
	FlushContext(handle tpm2.HandleContext) error

	ReadClock() (*tpm2.TimeInfo, error)

	NVRead(auth, index tpm2.ResourceContext, size, offset uint16, authAuthSession tpm2.SessionContext) (tpm2.MaxNVBuffer, error)
	NVReadPublic(handle tpm2.HandleContext) (*tpm2.NVPublic, tpm2.Name, error)
}

type onlineTpmConnection struct {
	tpm      *tpm2.TPMContext
	sessions []tpm2.SessionContext
}

func NewTPMConnection(tpm *tpm2.TPMContext, sessions ...tpm2.SessionContext) TPMConnection {
	return &onlineTpmConnection{
		tpm:      tpm,
		sessions: sessions,
	}
}

func (c *onlineTpmConnection) StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (tpm2.SessionContext, error) {
	return c.tpm.StartAuthSession(nil, nil, sessionType, nil, alg, c.sessions...)
}

func (c *onlineTpmConnection) LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (tpm2.ResourceContext, error) {
	return c.tpm.LoadExternal(inPrivate, inPublic, hierarchy, c.sessions...)
}

func (c *onlineTpmConnection) ReadPublic(handle tpm2.HandleContext) (*tpm2.Public, tpm2.Name, tpm2.Name, error) {
	return c.tpm.ReadPublic(handle, c.sessions...)
}

func (c *onlineTpmConnection) VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error) {
	return c.tpm.VerifySignature(key, digest, signature, c.sessions...)
}

func (c *onlineTpmConnection) PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	_, values, err := c.tpm.PCRRead(pcrs, c.sessions...)
	return values, err
}

func (c *onlineTpmConnection) PolicySigned(authKey tpm2.ResourceContext, policySession tpm2.SessionContext, includeNonceTPM bool, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, auth *tpm2.Signature) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return c.tpm.PolicySigned(authKey, policySession, includeNonceTPM, cpHashA, policyRef, expiration, auth, c.sessions...)
}

func (c *onlineTpmConnection) PolicySecret(authObject tpm2.ResourceContext, policySession tpm2.SessionContext, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, authObjectAuthSession tpm2.SessionContext) (tpm2.Timeout, *tpm2.TkAuth, error) {
	return c.tpm.PolicySecret(authObject, policySession, cpHashA, policyRef, expiration, authObjectAuthSession, c.sessions...)
}

func (c *onlineTpmConnection) PolicyTicket(policySession tpm2.SessionContext, timeout tpm2.Timeout, cpHashA tpm2.Digest, policyRef tpm2.Nonce, authName tpm2.Name, ticket *tpm2.TkAuth) error {
	return c.tpm.PolicyTicket(policySession, timeout, cpHashA, policyRef, authName, ticket)
}

func (c *onlineTpmConnection) PolicyOR(policySession tpm2.SessionContext, pHashList tpm2.DigestList) error {
	return c.tpm.PolicyOR(policySession, pHashList, c.sessions...)
}

func (c *onlineTpmConnection) PolicyPCR(policySession tpm2.SessionContext, pcrDigest tpm2.Digest, pcrs tpm2.PCRSelectionList) error {
	return c.tpm.PolicyPCR(policySession, pcrDigest, pcrs, c.sessions...)
}

func (c *onlineTpmConnection) PolicyNV(auth, index tpm2.ResourceContext, policySession tpm2.SessionContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp, authAuthSession tpm2.SessionContext) error {
	return c.tpm.PolicyNV(auth, index, policySession, operandB, offset, operation, authAuthSession, c.sessions...)
}

func (c *onlineTpmConnection) PolicyCounterTimer(policySession tpm2.SessionContext, operandB tpm2.Operand, offset uint16, operation tpm2.ArithmeticOp) error {
	return c.tpm.PolicyCounterTimer(policySession, operandB, offset, operation, c.sessions...)
}

func (c *onlineTpmConnection) PolicyCommandCode(policySession tpm2.SessionContext, code tpm2.CommandCode) error {
	return c.tpm.PolicyCommandCode(policySession, code, c.sessions...)
}

func (c *onlineTpmConnection) PolicyCpHash(policySession tpm2.SessionContext, cpHashA tpm2.Digest) error {
	return c.tpm.PolicyCpHash(policySession, cpHashA, c.sessions...)
}

func (c *onlineTpmConnection) PolicyNameHash(policySession tpm2.SessionContext, nameHash tpm2.Digest) error {
	return c.tpm.PolicyNameHash(policySession, nameHash, c.sessions...)
}

func (c *onlineTpmConnection) PolicyDuplicationSelect(policySession tpm2.SessionContext, objectName, newParentName tpm2.Name, includeObject bool) error {
	return c.tpm.PolicyDuplicationSelect(policySession, objectName, newParentName, includeObject, c.sessions...)
}

func (c *onlineTpmConnection) PolicyAuthorize(policySession tpm2.SessionContext, approvedPolicy tpm2.Digest, policyRef tpm2.Nonce, keySign tpm2.Name, verified *tpm2.TkVerified) error {
	return c.tpm.PolicyAuthorize(policySession, approvedPolicy, policyRef, keySign, verified, c.sessions...)
}

func (c *onlineTpmConnection) PolicyAuthValue(policySession tpm2.SessionContext) error {
	return c.tpm.PolicyAuthValue(policySession, c.sessions...)
}

func (c *onlineTpmConnection) PolicyPassword(policySession tpm2.SessionContext) error {
	return c.tpm.PolicyPassword(policySession, c.sessions...)
}

func (c *onlineTpmConnection) PolicyGetDigest(policySession tpm2.SessionContext) (tpm2.Digest, error) {
	return c.tpm.PolicyGetDigest(policySession, c.sessions...)
}

func (c *onlineTpmConnection) PolicyNvWritten(policySession tpm2.SessionContext, writtenSet bool) error {
	return c.tpm.PolicyNvWritten(policySession, writtenSet, c.sessions...)
}

func (c *onlineTpmConnection) ContextSave(handle tpm2.HandleContext) (*tpm2.Context, error) {
	return c.tpm.ContextSave(handle)
}

func (c *onlineTpmConnection) ContextLoad(context *tpm2.Context) (tpm2.HandleContext, error) {
	return c.tpm.ContextLoad(context)
}

func (c *onlineTpmConnection) FlushContext(handle tpm2.HandleContext) error {
	return c.tpm.FlushContext(handle)
}

func (c *onlineTpmConnection) ReadClock() (*tpm2.TimeInfo, error) {
	return c.tpm.ReadClock(c.sessions...)
}

func (c *onlineTpmConnection) NVRead(auth, index tpm2.ResourceContext, size, offset uint16, authAuthSession tpm2.SessionContext) (tpm2.MaxNVBuffer, error) {
	return c.tpm.NVReadRaw(auth, index, size, offset, authAuthSession, c.sessions...)
}

func (c *onlineTpmConnection) NVReadPublic(handle tpm2.HandleContext) (*tpm2.NVPublic, tpm2.Name, error) {
	return c.tpm.NVReadPublic(handle, c.sessions...)
}
