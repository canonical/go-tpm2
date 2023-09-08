// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"errors"

	"github.com/canonical/go-tpm2"
)

// ResourceContext corresponds to a resource on the TPM.
type ResourceContext interface {
	Resource() tpm2.ResourceContext // The actual resource
	Flush() error                   // Flush the resource once it's no longer needed
}

type SessionContext interface {
	Session() tpm2.SessionContext // The actual session
	Close() error                 // Save or flush the session for future use
}

// ResourceAuthorizer provides a way for an implementation to authorize a resource when
// using [NewTPMRPolicyExecuteHelper].
type ResourceAuthorizer interface {
	// NewSession should return a session of the specified type to use for authorization
	// of a resource with the specified name algorithm. If sessionType is [tpm2.SessionTypeHMAC]
	// then it is optional whether to return a session or not.
	//
	// The Close method of the returned session context will be called once the session has
	// been used.
	NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error)

	// Authorize sets the authorization value of the specified resource context.
	Authorize(resource tpm2.ResourceContext) error
}

// SavedResource contains the context of a saved transient object and its name, and
// can be used to supply transient resources to [Policy.Execute].
type SavedResource struct {
	Name    tpm2.Name
	Context *tpm2.Context
}

// SaveAndFlushResource saves the context of the supplied transient resource, flushes it and
// returns a *SavedResource instance that can be supplied to [Policy.Execute].
func SaveAndFlushResource(tpm *tpm2.TPMContext, resource tpm2.ResourceContext) (*SavedResource, error) {
	name := resource.Name()
	context, err := tpm.ContextSave(resource)
	if err != nil {
		return nil, err
	}
	if err := tpm.FlushContext(resource); err != nil {
		return nil, err
	}
	return &SavedResource{
		Name:    name,
		Context: context,
	}, nil
}

// LoadableResource contains the data associated with an unloaded transient object, and
// can be used to supply transient resources to [Policy.Execute].
type LoadableResource struct {
	ParentName tpm2.Name
	Public     *tpm2.Public
	Private    tpm2.Private
}

// Resources contains the resources that are required by [NewTPMPolicyExecuteHelper].
type Resources struct {
	// Loaded resources are resources that are already loaded in the TPM, such
	// as NV indices, persistent resources, or transient resources that have
	// already been loaded. Note that permanent or PCR resources do not need
	// to be explicitly supplied.
	Loaded []tpm2.ResourceContext

	// Saved resources are transient objects that have been previously loaded,
	// context saved and then flushed, and need to be context loaded with
	// TPM2_ContextLoad in order to use. These will be flushed after use.
	Saved []*SavedResource

	// Unloaded resources are transient objects that need to be loaded with
	// TPM2_Load in order to use. These will be flushed after use.
	Unloaded []*LoadableResource

	AuthorizedPolicies []*Policy
}

type resourceContextFlushable struct {
	resource tpm2.ResourceContext
	tpm      *tpm2.TPMContext
}

func newResourceContextFlushable(tpm *tpm2.TPMContext, context tpm2.ResourceContext) *resourceContextFlushable {
	return &resourceContextFlushable{resource: context, tpm: tpm}
}

func (r *resourceContextFlushable) Resource() tpm2.ResourceContext {
	return r.resource
}

func (r *resourceContextFlushable) Flush() error {
	return r.tpm.FlushContext(r.resource)
}

type resourceContextNonFlushable struct {
	resource tpm2.ResourceContext
}

func newResourceContextNonFlushable(context tpm2.ResourceContext) *resourceContextNonFlushable {
	return &resourceContextNonFlushable{resource: context}
}

func (r *resourceContextNonFlushable) Resource() tpm2.ResourceContext {
	return r.resource
}

func (r *resourceContextNonFlushable) Flush() error {
	return nil
}

type sessionContextFlushable struct {
	session tpm2.SessionContext
	tpm     *tpm2.TPMContext
}

func newSessionContextFlushable(tpm *tpm2.TPMContext, context tpm2.SessionContext) *sessionContextFlushable {
	return &sessionContextFlushable{session: context, tpm: tpm}
}

func (s *sessionContextFlushable) Session() tpm2.SessionContext {
	return s.session
}

func (s *sessionContextFlushable) Flush() error {
	return s.tpm.FlushContext(s.session)
}

type policyResources interface {
	LoadName(name tpm2.Name) (ResourceContext, *Policy, error)
	LoadExternal(public *tpm2.Public) (ResourceContext, error)
	LoadNV(public *tpm2.NVPublic) (tpm2.ResourceContext, *Policy, error)
	LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error)
	NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error)
	Authorize(resource tpm2.ResourceContext) error
}

// mockResources is an implementation of policyResources that doesn't require
// access to a TPM.
type mockResources struct{}

func (*mockResources) LoadName(name tpm2.Name) (ResourceContext, *Policy, error) {
	// the handle is not relevant here
	return newResourceContextNonFlushable(tpm2.NewLimitedResourceContext(0x80000000, name)), nil, nil
}

func (r *mockResources) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	// the handle is not relevant here
	resource := tpm2.NewLimitedResourceContext(0x80000000, public.Name())
	return newResourceContextNonFlushable(resource), nil
}

func (r *mockResources) LoadNV(public *tpm2.NVPublic) (tpm2.ResourceContext, *Policy, error) {
	rc, err := tpm2.NewNVIndexResourceContextFromPub(public)
	return rc, nil, err
}

func (r *mockResources) LoadAuthorizedPolicies(keySign tpm2.Name, policyRef tpm2.Nonce) ([]*Policy, error) {
	return nil, nil
}

func (*mockResources) NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error) {
	if sessionType != tpm2.SessionTypeHMAC {
		panic("unexpected session type")
	}
	return nil, nil
}

func (*mockResources) Authorize(resource tpm2.ResourceContext) error {
	return nil
}

type nullResourceAuthorizer struct{}

func (*nullResourceAuthorizer) NewSession(nameAlg tpm2.HashAlgorithmId, sessionType tpm2.SessionType) (SessionContext, error) {
	return nil, errors.New("no ResourceAuthorizer")
}

func (*nullResourceAuthorizer) Authorize(resource tpm2.ResourceContext) error {
	return errors.New("no ResourceAuthorizer")
}
