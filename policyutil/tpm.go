// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"

	"github.com/canonical/go-tpm2"
)

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

	// GetPermanentHandleAuthPolicy returns the auth policy digest for the specified
	// permanent handle, if there is one. If there isn't one, it returns a null hash.
	GetPermanentHandleAuthPolicy(handle tpm2.Handle) (tpm2.TaggedHash, error)
}

type onlineTpmHelper struct {
	newPolicySession NewPolicySessionFn
	tpm              *tpm2.TPMContext
	sessions         []tpm2.SessionContext
}

// TPMHelperParams provides parameters to [NewTPMHelper].
type TPMHelperParams struct {
	// NewPolicySessionFn allows the function used to create a new PolicySession
	// in StartAuthSession to be overridden. The default is NewTPMPolicySession.
	NewPolicySessionFn NewPolicySessionFn
}

// NewTPMHelper returns an implementation of TPMHelper that uses the supplied TPM context.
func NewTPMHelper(tpm *tpm2.TPMContext, params *TPMHelperParams, sessions ...tpm2.SessionContext) TPMHelper {
	if params == nil {
		params = new(TPMHelperParams)
	}
	newPolicySession := params.NewPolicySessionFn
	if newPolicySession == nil {
		newPolicySession = NewTPMPolicySession
	}

	return &onlineTpmHelper{
		newPolicySession: newPolicySession,
		tpm:              tpm,
		sessions:         sessions,
	}
}

func (h *onlineTpmHelper) StartAuthSession(sessionType tpm2.SessionType, alg tpm2.HashAlgorithmId) (SessionContext, PolicySession, error) {
	session, err := h.tpm.StartAuthSession(nil, nil, sessionType, nil, alg, h.sessions...)
	if err != nil {
		return nil, nil, err
	}

	switch sessionType {
	case tpm2.SessionTypeHMAC:
		return newTpmSessionContext(h.tpm, session), nil, nil
	case tpm2.SessionTypePolicy:
		policySession := h.newPolicySession(h.tpm, session, h.sessions...)
		return policySession.Context(), policySession, nil
	default:
		panic("not reached")
	}
}

func (h *onlineTpmHelper) LoadExternal(inPrivate *tpm2.Sensitive, inPublic *tpm2.Public, hierarchy tpm2.Handle) (ResourceContext, error) {
	rc, err := h.tpm.LoadExternal(inPrivate, inPublic, hierarchy, h.sessions...)
	if err != nil {
		return nil, err
	}
	return newTpmResourceContextFlushable(h.tpm, rc, nil), nil
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

func (h *onlineTpmHelper) GetPermanentHandleAuthPolicy(handle tpm2.Handle) (tpm2.TaggedHash, error) {
	return h.tpm.GetCapabilityAuthPolicy(handle, h.sessions...)
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

func (*nullTpmHelper) GetPermanentHandleAuthPolicy(handle tpm2.Handle) (tpm2.TaggedHash, error) {
	return tpm2.MakeTaggedHash(tpm2.HashAlgorithmNull, nil), errors.New("no TPMHelper")
}
