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

// ResourceContext corresponds to a resource on the TPM.
type ResourceContext interface {
	Resource() tpm2.ResourceContext // The actual resource
	Flush() error                   // Flush the resource once it's no longer needed
}

// PolicyResourceLoader provides a way for [Policy.Execute] to access resources that
// are required by a policy.
type PolicyResourceLoader interface {
	// LoadName loads the resource with the specified name if required, and returns
	// a context. If the name corresponds to a transient object, the Flush method of the
	// returned context will be called once the resource is no longer needed.
	LoadName(name tpm2.Name) (ResourceContext, *Policy, error)

	// LoadNV returns a context for the supplied NV index
	LoadNVPolicy(name tpm2.Name) (*Policy, error)

	// LookupAuthorized policies returns a set of policies that are signed by the key with
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
// using [NewTPMPolicyResourceLoader].
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

// PolicyResources contains the resources that are required by [NewTPMPolicyResourceLoader].
type PolicyResources struct {
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

type savedResource struct {
	name    tpm2.Name
	context *tpm2.Context
	policy  *Policy
}

type tpmPolicyResourceLoader struct {
	Authorizer
	tpm        *tpm2.TPMContext
	resources  *PolicyResources
	persistent []PersistentResource
	saved      []savedResource
	sessions   []tpm2.SessionContext
}

func NewTPMPolicyResourceLoader(tpm *tpm2.TPMContext, resources *PolicyResources, authorizer Authorizer, sessions ...tpm2.SessionContext) PolicyResourceLoader {
	if resources == nil {
		resources = new(PolicyResources)
	}
	if authorizer == nil {
		authorizer = new(nullAuthorizer)
	}

	return &tpmPolicyResourceLoader{
		Authorizer: authorizer,
		tpm:        tpm,
		resources:  resources,
		sessions:   sessions,
	}
}

func (l *tpmPolicyResourceLoader) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	if !name.IsValid() {
		return nil, nil, errors.New("invalid name")
	}
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContextFlushable(l.tpm.GetPermanentContext(name.Handle()), nil), nil, nil
	}

	// Search persistent resources
	for _, resource := range append(l.persistent, l.resources.Persistent...) {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		rc, err := l.tpm.NewResourceContext(resource.Handle, l.sessions...)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(rc.Name(), name) {
			return nil, nil, fmt.Errorf("loaded context has the wrong name (gotr %#x, expected %#x)", rc.Name(), name)
		}

		return newResourceContextFlushable(rc, nil), resource.Policy, nil
	}

	// Search saved contexts
	for _, context := range l.saved {
		if !bytes.Equal(context.name, name) {
			continue
		}

		hc, err := l.tpm.ContextLoad(context.context)
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(hc.Name(), name) {
			l.tpm.FlushContext(hc)
			return nil, nil, fmt.Errorf("loaded context has the wrong name (got %#x, expected %#x)", hc.Name(), name)
		}
		resource, ok := hc.(tpm2.ResourceContext)
		if !ok {
			l.tpm.FlushContext(hc)
			return nil, nil, fmt.Errorf("name %#x associated with a context of the wrong type", name)
		}

		return newResourceContextFlushable(resource, l.tpm.FlushContext), context.policy, nil
	}

	// Search loadable objects
	for _, object := range l.resources.Transient {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		parent, policy, err := l.LoadName(object.ParentName)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot load parent for object with name %#x: %w", name, err)
		}
		defer parent.Flush()

		sessionType := tpm2.SessionTypeHMAC
		if policy != nil {
			sessionType = tpm2.SessionTypePolicy
		}

		session, err := l.tpm.StartAuthSession(nil, nil, sessionType, nil, parent.Resource().Name().Algorithm(), l.sessions...)
		if err != nil {
			return nil, nil, fmt.Errorf("cannot start session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer l.tpm.FlushContext(session)

		requireAuthValue := true
		if policy != nil {
			params := &PolicyExecuteParams{
				Usage: NewPolicySessionUsage(tpm2.CommandLoad, []Named{parent.Resource()}, object.Private, object.Public),
			}
			result, err := policy.Execute(NewTPMConnection(l.tpm, l.sessions...), session, l, params)
			if err != nil {
				return nil, nil, fmt.Errorf("cannot execute policy session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
			requireAuthValue = result.AuthValueNeeded
		}

		if requireAuthValue {
			if err := l.Authorize(parent.Resource()); err != nil {
				return nil, nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
		}

		resource, err := l.tpm.Load(parent.Resource(), object.Private, object.Public, session, l.sessions...)
		if err != nil {
			return nil, nil, err
		}

		if context, err := l.tpm.ContextSave(resource); err == nil {
			l.saved = append(l.saved, savedResource{name: name, context: context})
		}

		return newResourceContextFlushable(resource, l.tpm.FlushContext), object.Policy, nil
	}

	// Search persistent and NV index handles
	handles, err := l.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, l.sessions...)
	if err != nil {
		return nil, nil, err
	}
	nvHandles, err := l.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, l.sessions...)
	if err != nil {
		return nil, nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := l.tpm.NewResourceContext(handle, l.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		l.persistent = append(l.persistent, PersistentResource{Name: name, Handle: handle})
		return newResourceContextFlushable(resource, nil), nil, nil
	}

	return nil, nil, errors.New("cannot find resource")
}

func (l *tpmPolicyResourceLoader) LoadNVPolicy(name tpm2.Name) (*Policy, error) {
	for _, resource := range l.resources.Persistent {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		return resource.Policy, nil
	}

	return nil, nil
}

func (l *tpmPolicyResourceLoader) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range l.resources.AuthorizedPolicies {
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

type mockPolicyResourceLoader struct{}

func (*mockPolicyResourceLoader) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	// the handle is not relevant here
	return newResourceContextFlushable(tpm2.NewLimitedResourceContext(0x80000000, name), nil), nil, nil
}

func (r *mockPolicyResourceLoader) LoadNVPolicy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (r *mockPolicyResourceLoader) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*mockPolicyResourceLoader) Authorize(resource tpm2.ResourceContext) error {
	return nil
}

func (*mockPolicyResourceLoader) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return &PolicySignedAuthorization{Authorization: new(PolicyAuthorization)}, nil
}

type nullPolicyResourceLoader struct{}

func (*nullPolicyResourceLoader) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	return nil, nil, errors.New("no PolicyResourceLoader")
}

func (*nullPolicyResourceLoader) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	return nil, errors.New("no PolicyResourceLoader")
}

func (*nullPolicyResourceLoader) LoadNVPolicy(name tpm2.Name) (*Policy, error) {
	return nil, errors.New("no PolicyResourceLoader")
}

func (*nullPolicyResourceLoader) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, errors.New("no PolicyResourceLoader")
}

func (*nullPolicyResourceLoader) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no PolicyResourceLoader")
}

func (*nullPolicyResourceLoader) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no PolicyResourceLoader")
}
