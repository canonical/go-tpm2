// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"

	"github.com/canonical/go-tpm2"
)

type SessionContext interface {
	Session() tpm2.SessionContext
	Flush() error
}

// TPMHelper provides a way for [Policy.Execute] to communicate with a TPM.
type TPMHelper interface {
	// StartAuthSession returns an authorization session with the specified type and
	// algorithm. It is required for any policy that includes TPM2_PolicySecret or
	// TPM2_PolicyNV assertions.
	StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (SessionContext, PolicySession, error)

	// LoadExternal loads the supplied external object into the TPM. It is required by
	// any policy that includes TPM2_PolicySigned or TPM2_PolicyAuthorize assertions.
	LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (ResourceContext, error)

	// ReadPublic returns the public area of the resource at the specified handle. It
	// is required by any policy that includes TPM2_PolicySecret assertions on persistent or
	// transient objects.
	ReadPublic(handle tpm2.HandleContext) (*tpm2.Public, error)

	// VerifySignature verifies the supplied signature with the supplied key object. It
	// is required by any policy that includes TPM2_PolicyAuthorize assertions.
	VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error)

	// PCRRead returns the PCR values for the specified selection. It is required to
	// automatically resolve branches where branches include TPM2_PolicyPCR assertions.
	PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error)

	// ReadClock returns the current time info. It is required to automatically resolve
	// branches where branches include TPM2_PolicyCounterTimer assertions.
	ReadClock() (*tpm2.TimeInfo, error)

	// NVRead returns the contents of the specified NV index. It is required to automatically
	// resolve branches where branches include TPM2_PolicyNV assertions. This will only
	// be called if the index has an authorization policy with a branch that includes
	// TPM2_PolicyCommandCode for TPM2_NV_Read and no other assertions.
	NVRead(auth, index tpm2.ResourceContext, size, offset uint16, authAuthSession tpm2.SessionContext) (tpm2.MaxNVBuffer, error)

	// NVReadPublic returns the public area of the NV index at the specified handle. It
	// is required by any policy that includes TPM2_PolicyNV assertions or TPM2_PolicySecret
	// assertions on NV indices.
	NVReadPublic(handle tpm2.HandleContext) (*tpm2.NVPublic, error)
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

func (s *tpmSessionContext) Flush() error {
	return s.tpm.FlushContext(s.session)
}

type onlineTpmHelper struct {
	tpm      *tpm2.TPMContext
	sessions []tpm2.SessionContext
}

func NewTPMHelper(tpm *tpm2.TPMContext, sessions ...tpm2.SessionContext) TPMHelper {
	return &onlineTpmHelper{
		tpm:      tpm,
		sessions: sessions,
	}
}

func (h *onlineTpmHelper) StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (SessionContext, PolicySession, error) {
	session, err := h.tpm.StartAuthSession(nil, nil, sessionType, nil, alg, h.sessions...)
	if err != nil {
		return nil, nil, err
	}
	return newTpmSessionContext(h.tpm, session), NewTPMPolicySession(h.tpm, session, h.sessions...), nil
}

func (h *onlineTpmHelper) LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (ResourceContext, error) {
	rc, err := h.tpm.LoadExternal(inPrivate, inPublic, hierarchy, h.sessions...)
	if err != nil {
		return nil, err
	}
	return newResourceContextFlushable(rc, h.tpm.FlushContext), nil
}

func (h *onlineTpmHelper) ReadPublic(handle tpm2.HandleContext) (*tpm2.Public, error) {
	pub, _, _, err := h.tpm.ReadPublic(handle, h.sessions...)
	return pub, err
}

func (h *onlineTpmHelper) VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error) {
	return h.tpm.VerifySignature(key, digest, signature, h.sessions...)
}

func (h *onlineTpmHelper) PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	_, values, err := h.tpm.PCRRead(pcrs, h.sessions...)
	return values, err
}

func (h *onlineTpmHelper) ReadClock() (*tpm2.TimeInfo, error) {
	return h.tpm.ReadClock(h.sessions...)
}

func (h *onlineTpmHelper) NVRead(auth, index tpm2.ResourceContext, size, offset uint16, authAuthSession tpm2.SessionContext) (tpm2.MaxNVBuffer, error) {
	return h.tpm.NVReadRaw(auth, index, size, offset, authAuthSession, h.sessions...)
}

func (h *onlineTpmHelper) NVReadPublic(handle tpm2.HandleContext) (*tpm2.NVPublic, error) {
	pub, _, err := h.tpm.NVReadPublic(handle, h.sessions...)
	return pub, err
}

type nullTpmHelper struct{}

func (*nullTpmHelper) StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (SessionContext, PolicySession, error) {
	return nil, nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (ResourceContext, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) ReadPublic(handle tpm2.HandleContext) (*tpm2.Public, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) ReadClock() (*tpm2.TimeInfo, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) NVRead(auth, index tpm2.ResourceContext, size, offset uint16, authAuthSession tpm2.SessionContext) (tpm2.MaxNVBuffer, error) {
	return nil, errors.New("no TPMHelper")
}

func (*nullTpmHelper) NVReadPublic(handle tpm2.HandleContext) (*tpm2.NVPublic, error) {
	return nil, errors.New("no TPMHelper")
}
