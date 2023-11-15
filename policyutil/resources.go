// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"math"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

// ResourceContext corresponds to a resource on the TPM.
type ResourceContext interface {
	Resource() tpm2.ResourceContext // The actual resource
	Flush() error                   // Flush the resource once it's no longer needed
}

// PolicyResources provides a way for [Policy.Execute] to access resources that
// are required by a policy.
type PolicyResources interface {
	// LoadName loads the resource with the specified name if required, and returns
	// a context. If the name corresponds to a transient object, the Flush method of the
	// returned context will be called once the resource is no longer needed.
	//
	// This should return an error if no resource can be returned.
	LoadName(name tpm2.Name) (ResourceContext, *Policy, error)

	// LoadPolicy returns a policy for the resource with the specified name if there
	// is one. As a policy is optional, returning a nil policy isn't an error.
	LoadPolicy(name tpm2.Name) (*Policy, error)

	// LoadAuthorizedPolicies returns a set of policies that are signed by the key with
	// the specified name, appropriate for a TPM2_PolicyAuthorize assertion with the
	// specified reference.
	LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)

	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error

	// SignAuthorization signs a TPM2_PolicySigned authorization for the specified key, policy ref
	// and session nonce.
	SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
}

// Authorizer provides a way for an implementation to provide authorizations
// using [NewTPMPolicyResources].
type Authorizer interface {
	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error

	// SignAuthorization signs a TPM2_PolicySigned authorization for the specified key, policy ref
	// and session nonce.
	SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
}

type nullAuthorizer struct{}

func (*nullAuthorizer) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no Authorizer")
}

func (*nullAuthorizer) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no Authorizer")
}

// PersistentResource contains details associated with a persistent object or
// NV index.
type PersistentResource struct {
	Name   tpm2.Name
	Handle tpm2.Handle

	Policy *Policy
}

// TransientResource contains details associated with a transient object.
type TransientResource struct {
	ParentName tpm2.Name
	Public     *tpm2.Public
	Private    tpm2.Private

	Policy *Policy
}

// PolicyResourcesData contains the resources that are required by [NewTPMPolicyResources].
type PolicyResourcesData struct {
	// Persistent contains the details associated with persistent objects and
	// NV indexes.
	Persistent []PersistentResource

	// Transient contains the details associated with loadable transient objects.
	Transient []TransientResource

	// AuthorizedPolicies contain authorized sub-policies
	AuthorizedPolicies []*Policy
}

type resourceContextFlushFn func(tpm2.HandleContext) error

type resourceContextFlushable struct {
	resource tpm2.ResourceContext
	flush    resourceContextFlushFn
}

func newResourceContextFlushable(context tpm2.ResourceContext, flush resourceContextFlushFn) *resourceContextFlushable {
	return &resourceContextFlushable{
		resource: context,
		flush:    flush,
	}
}

func (r *resourceContextFlushable) Resource() tpm2.ResourceContext {
	return r.resource
}

func (r *resourceContextFlushable) Flush() error {
	if r.flush == nil {
		return nil
	}
	return r.flush(r.resource)
}

type tpmPolicyResources struct {
	Authorizer
	tpm      *tpm2.TPMContext
	data     *PolicyResourcesData
	sessions []tpm2.SessionContext
}

func NewTPMPolicyResources(tpm *tpm2.TPMContext, data *PolicyResourcesData, authorizer Authorizer, sessions ...tpm2.SessionContext) PolicyResources {
	if data == nil {
		data = new(PolicyResourcesData)
	}
	if authorizer == nil {
		authorizer = new(nullAuthorizer)
	}

	return &tpmPolicyResources{
		Authorizer: authorizer,
		tpm:        tpm,
		data:       data,
		sessions:   sessions,
	}
}

func (r *tpmPolicyResources) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	if !name.IsValid() {
		return nil, nil, errors.New("invalid name")
	}
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContextFlushable(r.tpm.GetPermanentContext(name.Handle()), nil), nil, nil
	}

	// Search persistent resources
	for _, resource := range r.data.Persistent {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		rc, err := r.tpm.NewResourceContext(resource.Handle, r.sessions...)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(rc.Name(), name) {
			return nil, nil, fmt.Errorf("loaded context has the wrong name (got %#x, expected %#x)", rc.Name(), name)
		}

		return newResourceContextFlushable(rc, nil), resource.Policy, nil
	}

	// Search loadable objects
	for _, object := range r.data.Transient {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		parent, policy, err := r.LoadName(object.ParentName)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load parent for object with name %#x: %w", name, err)
		}
		defer parent.Flush()

		sessionType := tpm2.SessionTypeHMAC
		if policy != nil {
			sessionType = tpm2.SessionTypePolicy
		}

		session, err := r.tpm.StartAuthSession(nil, nil, sessionType, nil, parent.Resource().Name().Algorithm(), r.sessions...)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot start session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer r.tpm.FlushContext(session)

		requireAuthValue := true
		if policy != nil {
			params := &PolicyExecuteParams{
				Usage: NewPolicySessionUsage(tpm2.CommandLoad, []Named{parent.Resource()}, object.Private, object.Public),
			}
			result, err := policy.Execute(NewTPMConnection(r.tpm, r.sessions...), session, r, params)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot execute policy session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
			requireAuthValue = result.AuthValueNeeded
		}

		if requireAuthValue {
			if err := r.Authorize(parent.Resource()); err != nil {
				return nil, nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
		}

		resource, err := r.tpm.Load(parent.Resource(), object.Private, object.Public, session, r.sessions...)
		if err != nil {
			return nil, nil, err
		}

		return newResourceContextFlushable(resource, r.tpm.FlushContext), object.Policy, nil
	}

	// Search persistent and NV index handles
	handles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, err
	}
	nvHandles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := r.tpm.NewResourceContext(handle, r.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		return newResourceContextFlushable(resource, nil), nil, nil
	}

	return nil, nil, errors.New("unknown resource")
}

func (r *tpmPolicyResources) LoadPolicy(name tpm2.Name) (*Policy, error) {
	for _, resource := range r.data.Persistent {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		return resource.Policy, nil
	}
	for _, object := range r.data.Transient {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		return object.Policy, nil
	}

	return nil, nil
}

func (r *tpmPolicyResources) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range r.data.AuthorizedPolicies {
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

type mockPolicyResources struct{}

func (*mockPolicyResources) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	// the handle is not relevant here
	return newResourceContextFlushable(tpm2.NewLimitedResourceContext(0x80000000, name), nil), nil, nil
}

func (r *mockPolicyResources) LoadPolicy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (r *mockPolicyResources) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*mockPolicyResources) Authorize(resource tpm2.ResourceContext) error {
	return nil
}

func (*mockPolicyResources) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return &PolicySignedAuthorization{Authorization: new(PolicyAuthorization)}, nil
}

type nullPolicyResources struct{}

func (*nullPolicyResources) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	return nil, nil, errors.New("unknown resource")
}

func (*nullPolicyResources) LoadPolicy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no PolicyResources")
}

func (*nullPolicyResources) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no PolicyResources")
}

type cachedResourceType int

const (
	cachedResourceTypeResource cachedResourceType = iota
	cachedResourceTypeContext
	cachedResourceTypePolicy
)

type cachedResource struct {
	typ    cachedResourceType
	data   []byte
	policy *Policy
}

func nameKey(name tpm2.Name) paramKey {
	h := crypto.SHA256.New()
	mu.MustMarshalToWriter(h, name)

	var key paramKey
	copy(key[:], h.Sum(nil))
	return key
}

type cachedPolicyResources struct {
	PolicyResources

	tpm TPMConnection

	cached             map[paramKey]cachedResource
	authorizedPolicies map[paramKey][]*Policy
}

func newCachedPolicyResources(tpm TPMConnection, resources PolicyResources) *cachedPolicyResources {
	return &cachedPolicyResources{
		PolicyResources:    resources,
		tpm:                tpm,
		cached:             make(map[paramKey]cachedResource),
		authorizedPolicies: make(map[paramKey][]*Policy),
	}
}

func (r *cachedPolicyResources) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	if cached, exists := r.cached[nameKey(name)]; exists {
		switch cached.typ {
		case cachedResourceTypeResource:
			if hc, _, err := tpm2.NewHandleContextFromBytes(cached.data); err == nil {
				if resource, ok := hc.(tpm2.ResourceContext); ok {
					switch resource.Handle().Type() {
					case tpm2.HandleTypeTransient:
						return newResourceContextFlushable(resource, r.tpm.FlushContext), cached.policy, nil
					default:
						return newResourceContextFlushable(resource, nil), cached.policy, nil
					}
				}
			}
		case cachedResourceTypeContext:
			var context *tpm2.Context
			if _, err := mu.UnmarshalFromBytes(cached.data, &context); err == nil {
				if hc, err := r.tpm.ContextLoad(context); err == nil {
					if resource, ok := hc.(tpm2.ResourceContext); ok {
						return newResourceContextFlushable(resource, r.tpm.FlushContext), cached.policy, nil
					}
				}
			}
		}
	}

	resource, policy, err := r.PolicyResources.LoadName(name)
	if err != nil {
		return nil, nil, err
	}

	switch resource.Resource().Handle().Type() {
	case tpm2.HandleTypeTransient:
		if context, err := r.tpm.ContextSave(resource.Resource()); err == nil {
			r.cached[nameKey(name)] = cachedResource{
				typ:    cachedResourceTypeContext,
				data:   mu.MustMarshalToBytes(context),
				policy: policy,
			}
		}
	default:
		r.cached[nameKey(name)] = cachedResource{
			typ:    cachedResourceTypeResource,
			data:   resource.Resource().SerializeToBytes(),
			policy: policy,
		}
	}

	return resource, policy, nil
}

func (r *cachedPolicyResources) LoadPolicy(name tpm2.Name) (*Policy, error) {
	if cached, exists := r.cached[nameKey(name)]; exists {
		return cached.policy, nil
	}

	policy, err := r.PolicyResources.LoadPolicy(name)
	if err != nil {
		return nil, err
	}

	r.cached[nameKey(name)] = cachedResource{
		typ:    cachedResourceTypePolicy,
		policy: policy,
	}
	return policy, nil
}

func (r *cachedPolicyResources) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	if policies, exists := r.authorizedPolicies[policyParamKey(keySign, policyRef)]; exists {
		return policies, nil
	}

	policies, err := r.PolicyResources.LoadAuthorizedPolicies(keySign, policyRef)
	if err != nil {
		return nil, err
	}

	r.authorizedPolicies[policyParamKey(keySign, policyRef)] = policies
	return policies, nil
}
