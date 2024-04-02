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
	"github.com/canonical/go-tpm2/mu"
)

// ResourceContext corresponds to a resource on the TPM.
type ResourceContext interface {
	Resource() tpm2.ResourceContext // The actual resource
	Flush()                         // Flush the resource once it's no longer needed
}

// LoadPolicyParams contains parameters for policy sessions that are required to execute
// TPM2_Load commands via [PolicyResources.LoadedResource].
type LoadPolicyParams struct {
	Tickets              []*PolicyTicket         // See [PolicyExecuteParams.Tickets]
	IgnoreAuthorizations []PolicyAuthorizationID // See [PolicyExecuteParams.IgnoreAuthorizations]
	IgnoreNV             []Named                 // See [PolicyExecuteParams.IgnoreNV]
}

// PolicyResources provides a way for [Policy.Execute] to access resources that
// are required by a policy.
type PolicyResources interface {
	// LoadedResource loads the resource with the specified name if required, and returns
	// a context. The Flush method of the returned context will be called once the resource
	// is no longer needed.
	//
	// This should return an error if no resource can be returned.
	LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (resource ResourceContext, policy *Policy, newTickets []*PolicyTicket, invalidTickets []*PolicyTicket, err error)

	// Policy returns a policy for the resource with the specified name if there
	// is one. As a policy is optional, returning a nil policy isn't an error.
	Policy(name tpm2.Name) (*Policy, error)

	// AuthorizedPolicies returns a set of policies that are signed by the key with
	// the specified name, appropriate for a TPM2_PolicyAuthorize assertion with the
	// specified reference.
	AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)

	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error

	// SignedAuthorization signs a TPM2_PolicySigned authorization for the specified key, policy ref
	// and session nonce.
	SignedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)

	// ContextSave saves the context of the transient resource associated with the supplied
	// handle. This will return nil if it fails.
	ContextSave(resource tpm2.ResourceContext) *tpm2.Context

	// ContextLoad loads the supplied context and returns a transient handle. This will return
	// nil if the context can't be loaded or isn't a transient resource.
	ContextLoad(context *tpm2.Context) ResourceContext
}

// Authorizer provides a way for an implementation to provide authorizations
// using [NewTPMPolicyResources].
type Authorizer interface {
	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error
}

// SignedAuthorizer provides a way for an implementation to provide signed
// authorizations using [NewTPMPolicyResources].
type SignedAuthorizer interface {
	// SignedAuthorization signs a TPM2_PolicySigned authorization for the specified key, policy ref
	// and session nonce.
	SignedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
}

type nullAuthorizer struct{}

func (*nullAuthorizer) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no Authorizer")
}

type nullSignedAuthorizer struct{}

func (*nullSignedAuthorizer) SignedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no SignedAuthorizer")
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

type resourceContext struct {
	resource tpm2.ResourceContext
}

func newResourceContext(resource tpm2.ResourceContext) *resourceContext {
	return &resourceContext{resource: resource}
}

func (r *resourceContext) Resource() tpm2.ResourceContext {
	return r.resource
}

func (r *resourceContext) Flush() {}

type resourceContextFlushFn func(tpm2.HandleContext) error

type resourceContextFlushable struct {
	resourceContext
	flush resourceContextFlushFn
}

func newResourceContextFlushable(resource tpm2.ResourceContext, flush resourceContextFlushFn) *resourceContextFlushable {
	return &resourceContextFlushable{
		resourceContext: resourceContext{resource: resource},
		flush:           flush,
	}
}

func (r *resourceContextFlushable) Flush() {
	r.flush(r.resource)
}

type tpmPolicyResources struct {
	Authorizer
	SignedAuthorizer
	tpm      *tpm2.TPMContext
	data     *PolicyResourcesData
	sessions []tpm2.SessionContext
}

// NewTPMPolicyResources returns a PolicyResources implementation that uses
// the supplied data.
func NewTPMPolicyResources(tpm *tpm2.TPMContext, data *PolicyResourcesData, authorizer Authorizer, signedAuthorizer SignedAuthorizer, sessions ...tpm2.SessionContext) PolicyResources {
	if data == nil {
		data = new(PolicyResourcesData)
	}
	if authorizer == nil {
		authorizer = new(nullAuthorizer)
	}
	if signedAuthorizer == nil {
		signedAuthorizer = new(nullSignedAuthorizer)
	}

	return &tpmPolicyResources{
		Authorizer:       authorizer,
		SignedAuthorizer: signedAuthorizer,
		tpm:              tpm,
		data:             data,
		sessions:         sessions,
	}
}

func (r *tpmPolicyResources) LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (ResourceContext, *Policy, []*PolicyTicket, []*PolicyTicket, error) {
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContext(r.tpm.GetPermanentContext(name.Handle())), nil, nil, nil, nil
	}

	// Search persistent resources
	for _, resource := range r.data.Persistent {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		rc, err := r.tpm.NewResourceContext(resource.Handle, r.sessions...)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if !bytes.Equal(rc.Name(), name) {
			return nil, nil, nil, nil, fmt.Errorf("persistent TPM resource has the wrong name (%#x)", rc.Name())
		}

		return newResourceContext(rc), resource.Policy, nil, nil, nil
	}

	// Search loadable objects
	for _, object := range r.data.Transient {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		parent, policy, newTickets, invalidTickets, err := r.LoadedResource(object.ParentName, policyParams)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("cannot load parent with name %#x: %w", object.ParentName, err)
		}
		defer parent.Flush()

		ticketMap := make(map[ticketMapKey]*PolicyTicket)
		for _, ticket := range policyParams.Tickets {
			ticketMap[makeTicketMapKey(ticket)] = ticket
		}
		for _, ticket := range newTickets {
			ticketMap[makeTicketMapKey(ticket)] = ticket
		}
		for _, ticket := range invalidTickets {
			delete(ticketMap, makeTicketMapKey(ticket))
		}

		var tickets []*PolicyTicket
		for _, ticket := range ticketMap {
			tickets = append(tickets, ticket)
		}

		sessionType := tpm2.SessionTypeHMAC
		if policy != nil {
			sessionType = tpm2.SessionTypePolicy
		}

		session, err := r.tpm.StartAuthSession(nil, nil, sessionType, nil, parent.Resource().Name().Algorithm(), r.sessions...)
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("cannot start session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer r.tpm.FlushContext(session)

		requireAuthValue := true
		if policy != nil {
			params := &PolicyExecuteParams{
				Tickets:              tickets,
				Usage:                NewPolicySessionUsage(tpm2.CommandLoad, []Named{parent.Resource()}, object.Private, object.Public),
				IgnoreAuthorizations: policyParams.IgnoreAuthorizations,
				IgnoreNV:             policyParams.IgnoreNV,
			}
			result, err := policy.Execute(NewTPMPolicySession(r.tpm, session, r.sessions...), r, NewTPMHelper(r.tpm, r.sessions...), params)
			if err != nil {
				return nil, nil, nil, nil, fmt.Errorf("cannot execute policy session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
			requireAuthValue = result.AuthValueNeeded
			for _, ticket := range result.NewTickets {
				newTickets = append(newTickets, ticket)
			}
			for _, ticket := range result.InvalidTickets {
				invalidTickets = append(invalidTickets, ticket)
			}
		}

		if requireAuthValue {
			if err := r.Authorize(parent.Resource()); err != nil {
				return nil, nil, nil, nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
		}

		resource, err := r.tpm.Load(parent.Resource(), object.Private, object.Public, session, r.sessions...)
		if err != nil {
			return nil, nil, nil, nil, err
		}

		return newResourceContextFlushable(resource, r.tpm.FlushContext), object.Policy, newTickets, invalidTickets, nil
	}

	// Search persistent and NV index handles
	handles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	nvHandles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := r.tpm.NewResourceContext(handle, r.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		return newResourceContext(resource), nil, nil, nil, nil
	}

	return nil, nil, nil, nil, errors.New("resource not found")
}

func (r *tpmPolicyResources) Policy(name tpm2.Name) (*Policy, error) {
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

func (r *tpmPolicyResources) AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
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

func (r *tpmPolicyResources) ContextSave(resource tpm2.ResourceContext) *tpm2.Context {
	context, _ := r.tpm.ContextSave(resource)
	return context
}

func (r *tpmPolicyResources) ContextLoad(context *tpm2.Context) ResourceContext {
	hc, err := r.tpm.ContextLoad(context)
	if err != nil {
		return nil
	}
	rc, ok := hc.(tpm2.ResourceContext)
	if !ok {
		return nil
	}
	return newResourceContextFlushable(rc, r.tpm.FlushContext)
}

type nullPolicyResources struct{}

func (*nullPolicyResources) LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (ResourceContext, *Policy, []*PolicyTicket, []*PolicyTicket, error) {
	return nil, nil, nil, nil, errors.New("no PolicyResources")
}

func (*nullPolicyResources) Policy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no PolicyResources")
}

func (*nullPolicyResources) SignedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no PolicyResources")
}

func (*nullPolicyResources) ContextSave(resource tpm2.ResourceContext) *tpm2.Context {
	return nil
}

func (*nullPolicyResources) ContextLoad(context *tpm2.Context) ResourceContext {
	return nil
}

type policyResources interface {
	loadedResource(name tpm2.Name) (ResourceContext, *Policy, error)
	policy(name tpm2.Name) (*Policy, error)
	authorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)
	signedAuthorization(nonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
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

type nameMapKey uint32

func makeNameMapKey(name tpm2.Name) nameMapKey {
	return nameMapKey(mapKey(name))
}

type executePolicyResources struct {
	session SessionContext

	resources PolicyResources
	tickets   *executePolicyTickets

	ignoreAuthorizations []PolicyAuthorizationID
	ignoreNV             []Named

	cachedResources          map[nameMapKey]cachedResource
	cachedAuthorizedPolicies map[authMapKey][]*Policy
}

func newExecutePolicyResources(session SessionContext, resources PolicyResources, tickets *executePolicyTickets, ignoreAuthorizations []PolicyAuthorizationID, ignoreNV []Named) *executePolicyResources {
	return &executePolicyResources{
		session:                  session,
		resources:                resources,
		tickets:                  tickets,
		ignoreAuthorizations:     ignoreAuthorizations,
		ignoreNV:                 ignoreNV,
		cachedResources:          make(map[nameMapKey]cachedResource),
		cachedAuthorizedPolicies: make(map[authMapKey][]*Policy),
	}
}

func (r *executePolicyResources) forSession(session SessionContext) *executePolicyResources {
	out := *r
	out.session = session
	return &out
}

func (r *executePolicyResources) loadedResource(name tpm2.Name) (ResourceContext, *Policy, error) {
	if cached, exists := r.cachedResources[makeNameMapKey(name)]; exists {
		switch cached.typ {
		case cachedResourceTypeResource:
			if hc, _, err := tpm2.NewHandleContextFromBytes(cached.data); err == nil {
				if resource, ok := hc.(tpm2.ResourceContext); ok {
					return newResourceContext(resource), cached.policy, nil
				}
			}
		case cachedResourceTypeContext:
			var context *tpm2.Context
			if _, err := mu.UnmarshalFromBytes(cached.data, &context); err == nil {
				if resource := r.resources.ContextLoad(context); resource != nil {
					return resource, cached.policy, nil
				}
			}
		}
	}

	// Save the current policy session to make space for others that might be loaded
	restore, err := r.session.Save()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot save session: %w", err)
	}
	defer func() {
		if restoreErr := restore(); restoreErr != nil && err == nil {
			err = fmt.Errorf("cannot restore saved session: %w", restoreErr)
		}
	}()

	params := &LoadPolicyParams{
		Tickets:              r.tickets.currentTickets(),
		IgnoreAuthorizations: r.ignoreAuthorizations,
		IgnoreNV:             r.ignoreNV,
	}
	resource, policy, newTickets, invalidTickets, err := r.resources.LoadedResource(name, params)
	if err != nil {
		return nil, nil, err
	}

	switch resource.Resource().Handle().Type() {
	case tpm2.HandleTypeTransient:
		if context := r.resources.ContextSave(resource.Resource()); context != nil {
			r.cachedResources[makeNameMapKey(name)] = cachedResource{
				typ:    cachedResourceTypeContext,
				data:   mu.MustMarshalToBytes(context),
				policy: policy,
			}
		}
	default:
		r.cachedResources[makeNameMapKey(name)] = cachedResource{
			typ:    cachedResourceTypeResource,
			data:   resource.Resource().SerializeToBytes(),
			policy: policy,
		}
	}

	for _, ticket := range newTickets {
		r.tickets.addTicket(ticket)
	}
	for _, ticket := range invalidTickets {
		r.tickets.invalidTicket(ticket)
	}

	return resource, policy, nil
}

func (r *executePolicyResources) policy(name tpm2.Name) (*Policy, error) {
	if cached, exists := r.cachedResources[makeNameMapKey(name)]; exists {
		return cached.policy, nil
	}

	policy, err := r.resources.Policy(name)
	if err != nil {
		return nil, err
	}

	r.cachedResources[makeNameMapKey(name)] = cachedResource{
		typ:    cachedResourceTypePolicy,
		policy: policy,
	}
	return policy, nil
}

func (r *executePolicyResources) authorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	if policies, exists := r.cachedAuthorizedPolicies[makeAuthMapKey(keySign, policyRef)]; exists {
		return policies, nil
	}

	policies, err := r.resources.AuthorizedPolicies(keySign, policyRef)
	if err != nil {
		return nil, err
	}

	r.cachedAuthorizedPolicies[makeAuthMapKey(keySign, policyRef)] = policies
	return policies, nil
}

func (r *executePolicyResources) signedAuthorization(nonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return r.resources.SignedAuthorization(nonce, authKey, policyRef)
}

type mockPolicyResources struct{}

func (*mockPolicyResources) loadedResource(name tpm2.Name) (ResourceContext, *Policy, error) {
	// the handle is not relevant here
	return newResourceContext(tpm2.NewLimitedResourceContext(0x80000000, name)), nil, nil
}

func (r *mockPolicyResources) policy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (r *mockPolicyResources) authorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*mockPolicyResources) signedAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return &PolicySignedAuthorization{Authorization: new(PolicyAuthorization)}, nil
}
