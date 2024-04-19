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
	Policy() *Policy                // The policy associated with this resource, if there is one
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
	LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (resource ResourceContext, newTickets []*PolicyTicket, invalidTickets []*PolicyTicket, err error)

	// Policy returns a policy for the resource with the specified name if there
	// is one. As a policy is optional, returning a nil policy isn't an error.
	Policy(name tpm2.Name) (*Policy, error)

	// AuthorizedPolicies returns a set of policies that are signed by the key with
	// the specified name, appropriate for a TPM2_PolicyAuthorize assertion with the
	// specified reference.
	AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)

	AuthorizedNVPolicies(name tpm2.Name) ([]*Policy, error)

	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error

	// SignedAuthorization signs a TPM2_PolicySigned authorization for the specified key, policy ref
	// and session nonce. The supplied algorithm is the session algorithm, which should be
	// used to construct a cpHash if desired.
	SignedAuthorization(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)

	// ContextSave saves the context of the transient resource associated with the supplied
	// handle. This will return nil if it fails.
	ContextSave(resource tpm2.ResourceContext) *tpm2.Context

	// ContextLoad loads the supplied context and returns a transient handle. This will return
	// nil if the context can't be loaded or isn't a transient resource.
	ContextLoad(context *tpm2.Context, policy *Policy) ResourceContext

	// ExternalSensitive returns the sensitive area associated with the supplied name, to be
	// loaded with TPM2_LoadExternal.
	ExternalSensitive(name tpm2.Name) (*tpm2.Sensitive, error)
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
	SignedAuthorization(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
}

type ExternalSensitiveResources interface {
	ExternalSensitive(name tpm2.Name) (*tpm2.Sensitive, error)
}

type NVAuthorizedPolicy struct {
	Name   tpm2.Name
	Policy *Policy
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

	NVAuthorizedPolicies []NVAuthorizedPolicy // currently unused
}

type resourceContext struct {
	resource tpm2.ResourceContext
	policy   *Policy
}

func newResourceContext(resource tpm2.ResourceContext, policy *Policy) *resourceContext {
	return &resourceContext{
		resource: resource,
		policy:   policy,
	}
}

func (r *resourceContext) Resource() tpm2.ResourceContext {
	return r.resource
}

func (r *resourceContext) Policy() *Policy {
	return r.policy
}

func (r *resourceContext) Flush() {}

type tpmResourceContextFlushable struct {
	resourceContext
	tpm *tpm2.TPMContext
}

func newTpmResourceContextFlushable(tpm *tpm2.TPMContext, resource tpm2.ResourceContext, policy *Policy) *tpmResourceContextFlushable {
	return &tpmResourceContextFlushable{
		resourceContext: resourceContext{
			resource: resource,
			policy:   policy,
		},
		tpm: tpm,
	}
}

func (r *tpmResourceContextFlushable) Flush() {
	r.tpm.FlushContext(r.resource)
}

type tpmPolicyResources struct {
	authorizer                 Authorizer
	signedAuthorizer           SignedAuthorizer
	externalSensitiveResources ExternalSensitiveResources

	newTPMHelper     NewTPMHelperFn
	newPolicySession NewPolicySessionFn
	tpm              *tpm2.TPMContext
	data             *PolicyResourcesData
	sessions         []tpm2.SessionContext
}

type NewTPMHelperFn func(*tpm2.TPMContext, ...tpm2.SessionContext) TPMHelper

// TPMPolicyResourcesParams provides parameters to [NewTPMPolicyResources].
type TPMPolicyResourcesParams struct {
	Authorizer                 Authorizer                 // Provide a way to authorize resources
	SignedAuthorizer           SignedAuthorizer           // Provide a way to obtain signed authorizations
	ExternalSensitiveResources ExternalSensitiveResources // Provide a way to obtain sensitive areas to load with TPM2_LoadExternal

	// NewTPMHelperFn allows the function used to create a TPMHelper in order to
	// execute policies to be overridden. The default is NewTPMHelper.
	NewTPMHelperFn NewTPMHelperFn

	// NewPolicySessionFn allows the function used to create a new PolicySession
	// in order to execute policies to be overridden. The default is NewTPMPolicySession.
	NewPolicySessionFn NewPolicySessionFn
}

// NewTPMPolicyResources returns a PolicyResources implementation that uses
// the supplied data and communicates with the supplied TPM.
//
// The supplied data provides information about persistent resources, NV indexes,
// loadable objects and authorized policies that might be used when executing a
// policy. The supplied information can associate resources with policies so that
// these can be executed automatically when executing a policy that makes use of
// these resources.
//
// Information about persistent resources and NV indexes doesn't need to be supplied
// explicitly if there is no need to associate a policy with them. The returned
// TPMHelper implementation will query TPM handles whenever a policy requires a
// persistent resource or NV index for which there is no information.
//
// The returned TPMHelper implementation doesn't support associating policies
// with permanent resources - policies that use permanent resources will only use
// HMAC authorization.
//
// When loading transient objects to use for a policy, the returned TPMHelper
// implementation will automatically load any prerequisite parent objects first, as
// long as the details of these are supplied.
//
// Authorization values for resources, or signed authorizations or external sensitive
// areas for TPM2_PolicySigned assertions are requested using interfaces supplied via
// the optional parameters.
func NewTPMPolicyResources(tpm *tpm2.TPMContext, data *PolicyResourcesData, params *TPMPolicyResourcesParams, sessions ...tpm2.SessionContext) PolicyResources {
	if data == nil {
		data = new(PolicyResourcesData)
	}
	if params == nil {
		params = new(TPMPolicyResourcesParams)
	}

	newPolicySession := params.NewPolicySessionFn
	if newPolicySession == nil {
		newPolicySession = NewTPMPolicySession
	}
	newTPMHelper := params.NewTPMHelperFn
	if newTPMHelper == nil {
		newTPMHelper = func(tpm *tpm2.TPMContext, sessions ...tpm2.SessionContext) TPMHelper {
			return NewTPMHelper(tpm, &TPMHelperParams{NewPolicySessionFn: newPolicySession}, sessions...)
		}
	}

	return &tpmPolicyResources{
		authorizer:                 params.Authorizer,
		signedAuthorizer:           params.SignedAuthorizer,
		externalSensitiveResources: params.ExternalSensitiveResources,
		newTPMHelper:               newTPMHelper,
		newPolicySession:           newPolicySession,
		tpm:                        tpm,
		data:                       data,
		sessions:                   sessions,
	}
}

func (r *tpmPolicyResources) LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (ResourceContext, []*PolicyTicket, []*PolicyTicket, error) {
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContext(r.tpm.GetPermanentContext(name.Handle()), nil), nil, nil, nil
	}

	// Search persistent resources
	for _, resource := range r.data.Persistent {
		if !bytes.Equal(resource.Name, name) {
			continue
		}

		rc, err := r.tpm.NewResourceContext(resource.Handle, r.sessions...)
		if err != nil {
			return nil, nil, nil, err
		}
		if !bytes.Equal(rc.Name(), name) {
			return nil, nil, nil, fmt.Errorf("persistent TPM resource has the wrong name (%#x)", rc.Name())
		}

		return newResourceContext(rc, resource.Policy), nil, nil, nil
	}

	// Search loadable objects
	for _, object := range r.data.Transient {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		// After this point, the loop always exits and we return.

		parent, newTickets, invalidTickets, err := r.LoadedResource(object.ParentName, policyParams)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot load parent with name %#x: %w", object.ParentName, err)
		}
		defer parent.Flush()

		// Build a map of new and invalid tickets
		newTicketMap := make(map[*PolicyTicket]struct{})
		invalidTicketMap := make(map[*PolicyTicket]struct{})
		for _, ticket := range newTickets {
			newTicketMap[ticket] = struct{}{}
		}
		for _, ticket := range invalidTickets {
			invalidTicketMap[ticket] = struct{}{}
		}

		// Filter the originally supplied tickets to supply to the policy session below
		ticketMap := make(map[*PolicyTicket]struct{})
		for _, ticket := range policyParams.Tickets {
			ticketMap[ticket] = struct{}{}
		}
		for ticket := range newTicketMap {
			ticketMap[ticket] = struct{}{}
		}
		for ticket := range invalidTicketMap {
			delete(ticketMap, ticket)
		}

		var tickets []*PolicyTicket
		for ticket := range ticketMap {
			tickets = append(tickets, ticket)
		}

		sessionType := tpm2.SessionTypeHMAC
		if parent.Policy() != nil {
			sessionType = tpm2.SessionTypePolicy
		}

		session, err := r.tpm.StartAuthSession(nil, nil, sessionType, nil, parent.Resource().Name().Algorithm(), r.sessions...)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("cannot start session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer r.tpm.FlushContext(session)

		requireAuthValue := true
		if parent.Policy() != nil {
			params := &PolicyExecuteParams{
				Tickets:              tickets,
				Usage:                NewPolicySessionUsage(tpm2.CommandLoad, []NamedHandle{parent.Resource()}, object.Private, object.Public),
				IgnoreAuthorizations: policyParams.IgnoreAuthorizations,
				IgnoreNV:             policyParams.IgnoreNV,
			}
			result, err := parent.Policy().Execute(r.newPolicySession(r.tpm, session, r.sessions...), r, r.newTPMHelper(r.tpm, r.sessions...), params)
			if err != nil {
				return nil, nil, nil, fmt.Errorf("cannot execute policy session to authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
			requireAuthValue = result.AuthValueNeeded

			// Add new and invalid tickets to the ones collected earlier, noting
			// that this may have marked a previously new ticket as invalid
			for _, ticket := range result.NewTickets {
				newTicketMap[ticket] = struct{}{}
			}
			for _, ticket := range result.InvalidTickets {
				invalidTicketMap[ticket] = struct{}{}
				delete(newTicketMap, ticket)
			}

			newTickets = nil
			for ticket := range newTicketMap {
				newTickets = append(newTickets, ticket)
			}
			invalidTickets = nil
			for ticket := range invalidTicketMap {
				invalidTickets = append(invalidTickets, ticket)
			}
		}

		if requireAuthValue {
			if err := r.Authorize(parent.Resource()); err != nil {
				return nil, nil, nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
			}
		}

		resource, err := r.tpm.Load(parent.Resource(), object.Private, object.Public, session, r.sessions...)
		if err != nil {
			return nil, nil, nil, err
		}

		return newTpmResourceContextFlushable(r.tpm, resource, object.Policy), newTickets, invalidTickets, nil
	}

	// Search persistent and NV index handles
	handles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, nil, err
	}
	nvHandles, err := r.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, r.sessions...)
	if err != nil {
		return nil, nil, nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := r.tpm.NewResourceContext(handle, r.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, nil, nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		return newResourceContext(resource, nil), nil, nil, nil
	}

	return nil, nil, nil, errors.New("resource not found")
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

func (r *tpmPolicyResources) AuthorizedNVPolicies(name tpm2.Name) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range r.data.NVAuthorizedPolicies {
		if !bytes.Equal(policy.Name, name) {
			continue
		}
		out = append(out, policy.Policy)
	}
	return out, nil
}

func (r *tpmPolicyResources) Authorize(resource tpm2.ResourceContext) error {
	if r.authorizer == nil {
		return errors.New("no Authorizer")
	}
	return r.authorizer.Authorize(resource)
}

func (r *tpmPolicyResources) SignedAuthorization(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	if r.signedAuthorizer == nil {
		return nil, errors.New("no SignedAuthorizer")
	}
	return r.signedAuthorizer.SignedAuthorization(sessionAlg, sessionNonce, authKey, policyRef)
}

func (r *tpmPolicyResources) ContextSave(resource tpm2.ResourceContext) *tpm2.Context {
	context, _ := r.tpm.ContextSave(resource)
	return context
}

func (r *tpmPolicyResources) ContextLoad(context *tpm2.Context, policy *Policy) ResourceContext {
	hc, err := r.tpm.ContextLoad(context)
	if err != nil {
		return nil
	}
	rc, ok := hc.(tpm2.ResourceContext)
	if !ok {
		return nil
	}
	return newTpmResourceContextFlushable(r.tpm, rc, policy)
}

func (r *tpmPolicyResources) ExternalSensitive(name tpm2.Name) (*tpm2.Sensitive, error) {
	if r.externalSensitiveResources == nil {
		return nil, errors.New("no ExternalSensitiveResources")
	}
	return r.externalSensitiveResources.ExternalSensitive(name)
}

type nullPolicyResources struct{}

func (*nullPolicyResources) LoadedResource(name tpm2.Name, policyParams *LoadPolicyParams) (ResourceContext, []*PolicyTicket, []*PolicyTicket, error) {
	return nil, nil, nil, errors.New("no PolicyResources")
}

func (*nullPolicyResources) Policy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) AuthorizedNVPolicies(name tpm2.Name) ([]*Policy, error) {
	return nil, nil
}

func (*nullPolicyResources) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no PolicyResources")
}

func (*nullPolicyResources) SignedAuthorization(sessionAlg tpm2.HashAlgorithmId, sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return nil, errors.New("no PolicyResources")
}

func (*nullPolicyResources) ContextSave(resource tpm2.ResourceContext) *tpm2.Context {
	return nil
}

func (*nullPolicyResources) ContextLoad(context *tpm2.Context, policy *Policy) ResourceContext {
	return nil
}

func (*nullPolicyResources) ExternalSensitive(name tpm2.Name) (*tpm2.Sensitive, error) {
	return nil, errors.New("no PolicyResources")
}

type policyResources interface {
	loadedResource(name tpm2.Name) (ResourceContext, error)
	authorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)
	authorizedNVPolicies(name tpm2.Name) ([]*Policy, error)
	signedAuthorization(authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
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

	ignoreAuthorizations   []PolicyAuthorizationID
	ignoreNV               []Named
	ignoreNVAuthorizations tpm2.DigestList

	cachedResources            map[nameMapKey]cachedResource
	cachedAuthorizedPolicies   map[authMapKey][]*Policy
	cachedAuthorizedNVPolicies map[nameMapKey][]*Policy
}

func newExecutePolicyResources(session SessionContext, resources PolicyResources, tickets *executePolicyTickets, ignoreAuthorizations []PolicyAuthorizationID, ignoreNV []Named, ignoreNVAuthorizations tpm2.DigestList) *executePolicyResources {
	return &executePolicyResources{
		session:                  session,
		resources:                resources,
		tickets:                  tickets,
		ignoreAuthorizations:     ignoreAuthorizations,
		ignoreNV:                 ignoreNV,
		ignoreNVAuthorizations:   ignoreNVAuthorizations,
		cachedResources:          make(map[nameMapKey]cachedResource),
		cachedAuthorizedPolicies: make(map[authMapKey][]*Policy),
	}
}

func (r *executePolicyResources) forSession(session SessionContext) *executePolicyResources {
	out := *r
	out.session = session
	return &out
}

func (r *executePolicyResources) externalSensitive(name tpm2.Name) (*tpm2.Sensitive, error) {
	return r.resources.ExternalSensitive(name)
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

func (r *executePolicyResources) loadedResource(name tpm2.Name) (ResourceContext, error) {
	if cached, exists := r.cachedResources[makeNameMapKey(name)]; exists {
		switch cached.typ {
		case cachedResourceTypeResource:
			if hc, _, err := tpm2.NewHandleContextFromBytes(cached.data); err == nil {
				if resource, ok := hc.(tpm2.ResourceContext); ok {
					return newResourceContext(resource, cached.policy), nil
				}
			}
		case cachedResourceTypeContext:
			var context *tpm2.Context
			if _, err := mu.UnmarshalFromBytes(cached.data, &context); err == nil {
				if resource := r.resources.ContextLoad(context, cached.policy); resource != nil {
					return resource, nil
				}
			}
		}
	}

	// Save the current policy session to make space for others that might be loaded
	restore, err := r.session.Save()
	if err != nil {
		return nil, fmt.Errorf("cannot save session: %w", err)
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
	resource, newTickets, invalidTickets, err := r.resources.LoadedResource(name, params)
	if err != nil {
		return nil, err
	}

	switch resource.Resource().Handle().Type() {
	case tpm2.HandleTypeTransient:
		policy := resource.Policy()
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
			policy: resource.Policy(),
		}
	}

	for _, ticket := range newTickets {
		r.tickets.addTicket(ticket)
	}
	for _, ticket := range invalidTickets {
		r.tickets.invalidTicket(ticket)
	}

	return resource, nil
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

func (r *executePolicyResources) authorizedNVPolicies(name tpm2.Name) ([]*Policy, error) {
	if policies, exists := r.cachedAuthorizedNVPolicies[makeNameMapKey(name)]; exists {
		return policies, nil
	}

	policies, err := r.resources.AuthorizedNVPolicies(name)
	if err != nil {
		return nil, err
	}

	r.cachedAuthorizedNVPolicies[makeNameMapKey(name)] = policies
	return policies, nil
}

func (r *executePolicyResources) signedAuthorization(authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return r.resources.SignedAuthorization(r.session.Session().Params().HashAlg, r.session.Session().State().NonceTPM, authKey, policyRef)
}

type mockPolicyResources struct {
	authorized PolicyAuthorizedPolicies
}

func newMockPolicyResources(authorizedPolicies PolicyAuthorizedPolicies) *mockPolicyResources {
	return &mockPolicyResources{
		authorized: authorizedPolicies,
	}
}

func (*mockPolicyResources) loadedResource(name tpm2.Name) (ResourceContext, error) {
	// the handle is not relevant here
	return newResourceContext(tpm2.NewResourceContext(0x80000000, name), nil), nil
}

func (r *mockPolicyResources) policy(name tpm2.Name) (*Policy, error) {
	return nil, nil
}

func (r *mockPolicyResources) authorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	if r.authorized == nil {
		return nil, nil
	}
	return r.authorized.AuthorizedPolicies(keySign, policyRef)
}

func (r *mockPolicyResources) authorizedNVPolicies(name tpm2.Name) ([]*Policy, error) {
	if r.authorized == nil {
		return nil, nil
	}
	return r.authorized.AuthorizedNVPolicies(name)
}

func (*mockPolicyResources) signedAuthorization(authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return new(PolicySignedAuthorization), nil
}

// PolicyAuthorizedPolicies provides a way for [Policy.Branches], [Policy.Details] and
// [Policy.Stringer] to access authorized policies that are required by a policy.
type PolicyAuthorizedPolicies interface {
	// AuthorizedPolicies returns a set of policies that are signed by the key with
	// the specified name, appropriate for a TPM2_PolicyAuthorize assertion with the
	// specified reference.
	AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)

	AuthorizedNVPolicies(name tpm2.Name) ([]*Policy, error)
}

type policyAuthorizedPolicies struct {
	signedPolicies []*Policy
	nvPolicies     []NVAuthorizedPolicy
}

func (p *policyAuthorizedPolicies) AuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range p.signedPolicies {
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

func (p *policyAuthorizedPolicies) AuthorizedNVPolicies(name tpm2.Name) ([]*Policy, error) {
	var out []*Policy
	for _, policy := range p.nvPolicies {
		if !bytes.Equal(policy.Name, name) {
			continue
		}
		out = append(out, policy.Policy)
	}
	return out, nil
}

func NewPolicyAuthorizedPolicies(policies []*Policy, nvPolicies []NVAuthorizedPolicy) PolicyAuthorizedPolicies {
	return &policyAuthorizedPolicies{
		signedPolicies: policies,
		nvPolicies:     nvPolicies,
	}
}
