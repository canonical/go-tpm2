// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"
)

// PolicyExecuteHelper is an interface that is used to assist execution of a policy via
// [Policy.Execute].
type PolicyExecuteHelper interface {
	// LoadName loads the resource with the specified name if required, and returns
	// a context. If the name corresponds to a transient object, the Flush method of the
	// returned context will be called once the resource is no longer needed.
	LoadName(name tpm2.Name) (ResourceContext, *Policy, error)

	// LoadExternal loads the supplied public key and returns a new context. The
	// Flush method of the returned context will be called once the resource is no
	// longer needed.
	LoadExternal(public *tpm2.Public) (ResourceContext, error)

	// LoadNV returns a context for the supplied NV index
	LoadNV(public *tpm2.NVPublic) (tpm2.ResourceContext, *Policy, error)

	// LookupAuthorized policies returns a set of policies that are signed by the key with
	// the specified name, appropriate for a TPM2_PolicyAuthorize assertion with the
	// specified reference.
	LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)

	// NewSession should return a session of the specified type to use for authorization
	// of a resource with the specified name algorithm. If sessionType is [tpm2.SessionTypeHMAC]
	// then it is optional whether to return a session or not.
	//
	// The Close method of the returned session context will be called once the session has
	// been used.
	NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error)

	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error

	// PCRRead returns the values of the PCRs associated with
	// the specified selection.
	PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error)

	// NVReadPublic returns the public area of the NV index with the supplied
	// handle.
	NVReadPublic(handle tpm2.Handle) (*tpm2.NVPublic, error)

	// ReadClock obtains the current TimeInfo.
	ReadClock() (*tpm2.TimeInfo, error)

	VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error)
}

type tpmPolicyExecuteHelper struct {
	tpm        *tpm2.TPMContext
	resources  *Resources
	authorizer ResourceAuthorizer
	loaded     []tpm2.ResourceContext
	saved      []*SavedResource
	sessions   []tpm2.SessionContext
}

// NewTPMPolicyExecuteHelper returns a new PolicyExecuteHelper for the supplied
// TPM context. The other arguments are optional. The resources argument is required
// when a policy makes use of transient resources with the TPM2_PolicySecret assertion,
// although using it to explicitly specify persistent objects and NV indices can speed up
// execution. Some resources require authorization, which is performed via the authorizer
// argument. The authorizer argument is required when a policy contains TPM2_PolicyNV or
// TPM2_PolicySecret assertions.
func NewTPMPolicyExecuteHelper(tpm *tpm2.TPMContext, resources *Resources, authorizer ResourceAuthorizer, sessions ...tpm2.SessionContext) PolicyExecuteHelper {
	if resources == nil {
		resources = new(Resources)
	}
	if authorizer == nil {
		authorizer = new(nullResourceAuthorizer)
	}

	return &tpmPolicyExecuteHelper{
		tpm:        tpm,
		resources:  resources,
		authorizer: authorizer,
		sessions:   sessions,
	}
}

func (h *tpmPolicyExecuteHelper) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	if !name.IsValid() {
		return nil, nil, errors.New("invalid name")
	}
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContextNonFlushable(h.tpm.GetPermanentContext(name.Handle())), nil, nil
	}

	// Search already loaded resources
	for _, resource := range append(h.resources.Loaded, h.loaded...) {
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		return newResourceContextNonFlushable(resource), nil, nil
	}

	// Search saved contexts
	for _, context := range append(h.resources.Saved, h.saved...) {
		if !bytes.Equal(context.Name, name) {
			continue
		}

		hc, err := h.tpm.ContextLoad(context.Context)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(hc.Name(), name) {
			h.tpm.FlushContext(hc)
			return nil, nil, fmt.Errorf("loaded context has the wrong name (got %#x, expected %#x)", hc.Name(), name)
		}
		resource, ok := hc.(tpm2.ResourceContext)
		if !ok {
			h.tpm.FlushContext(hc)
			return nil, nil, fmt.Errorf("name %#x associated with a context of the wrong type", name)
		}

		return newResourceContextFlushable(h.tpm, resource), nil, nil
	}

	// Search loadable objects
	for _, object := range h.resources.Unloaded {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		parent, policy, err := h.LoadName(object.ParentName)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load parent for object with name %#x: %w", name, err)
		}
		defer parent.Flush()
		if policy != nil {
			return nil, nil, errors.New("unsupported auth method")
		}

		session, err := h.NewSession(parent.Resource().Name().Algorithm(), tpm2.SessionTypeHMAC)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot create session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer func() {
			if session == nil {
				return
			}
			session.Close()
		}()

		if err := h.Authorize(parent.Resource()); err != nil {
			return nil, nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}

		var tpmSession tpm2.SessionContext
		if session != nil {
			tpmSession = session.Session()
		}

		resource, err := h.tpm.Load(parent.Resource(), object.Private, object.Public, tpmSession, h.sessions...)
		if err != nil {
			return nil, nil, err
		}

		if context, err := h.tpm.ContextSave(resource); err == nil {
			h.saved = append(h.saved, &SavedResource{Name: name, Context: context})
		}

		return newResourceContextFlushable(h.tpm, resource), nil, nil
	}

	// Search persistent and NV index handles
	handles, err := h.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, h.sessions...)
	if err != nil {
		return nil, nil, err
	}
	nvHandles, err := h.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, h.sessions...)
	if err != nil {
		return nil, nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := h.tpm.NewResourceContext(handle, h.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		h.loaded = append(h.loaded, resource)
		return newResourceContextNonFlushable(resource), nil, nil
	}

	return nil, nil, errors.New("cannot find resource")
}

func (h *tpmPolicyExecuteHelper) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	rc, err := h.tpm.LoadExternal(nil, public, tpm2.HandleOwner, h.sessions...)
	if err != nil {
		return nil, err
	}
	return newResourceContextFlushable(h.tpm, rc), nil
}

func (h *tpmPolicyExecuteHelper) LoadNV(public *tpm2.NVPublic) (tpm2.ResourceContext, *Policy, error) {
	rc, err := tpm2.NewNVIndexResourceContextFromPub(public)
	return rc, nil, err
}

func (h *tpmPolicyExecuteHelper) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range h.resources.AuthorizedPolicies {
		for _, auth := range policy.policy.PolicyAuthorizations {
			if !bytes.Equal(auth.AuthKey.Name(), keySign) {
				continue
			}
			if !bytes.Equal(auth.PolicyRef, policyRef) {
				continue
			}
			out = append(out, policy)
			break
		}
	}

	return out, nil
}

func (h *tpmPolicyExecuteHelper) NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error) {
	if sessionType != tpm2.SessionTypeHMAC {
		return nil, errors.New("unsupported session type")
	}
	return h.authorizer.NewSession(nameAlg, sessionType)
}

func (h *tpmPolicyExecuteHelper) Authorize(resource tpm2.ResourceContext) error {
	return h.authorizer.Authorize(resource)
}

func (h *tpmPolicyExecuteHelper) PCRRead(pcrs tpm2.PCRSelectionList) (tpm2.PCRValues, error) {
	_, values, err := h.tpm.PCRRead(pcrs, h.sessions...)
	return values, err
}

func (h *tpmPolicyExecuteHelper) NVReadPublic(handle tpm2.Handle) (*tpm2.NVPublic, error) {
	index := tpm2.NewLimitedHandleContext(handle)
	pub, _, err := h.tpm.NVReadPublic(index, h.sessions...)
	return pub, err
}

func (h *tpmPolicyExecuteHelper) ReadClock() (*tpm2.TimeInfo, error) {
	return h.tpm.ReadClock(h.sessions...)
}

func (h *tpmPolicyExecuteHelper) VerifySignature(key tpm2.ResourceContext, digest tpm2.Digest, signature *tpm2.Signature) (*tpm2.TkVerified, error) {
	return h.tpm.VerifySignature(key, digest, signature, h.sessions...)
}

type nullPolicyExecuteHelper struct {
	nullTpmConnection
}

func (*nullPolicyExecuteHelper) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	return nil, nil, errors.New("no PolicyExecuteHelper")
}

func (*nullPolicyExecuteHelper) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	return nil, errors.New("no PolicyExecuteHelper")
}

func (*nullPolicyExecuteHelper) LoadNV(public *tpm2.NVPublic) (tpm2.ResourceContext, *Policy, error) {
	return nil, nil, errors.New("no PolicyExecuteHelper")
}

func (*nullPolicyExecuteHelper) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, errors.New("no PolicyExecuteHelper")
}

func (*nullPolicyExecuteHelper) NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error) {
	return nil, errors.New("no PolicyExecuteHelper")
}

func (*nullPolicyExecuteHelper) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no PolicyExecuteHelper")
}
