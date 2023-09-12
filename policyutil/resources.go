// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
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

// PersistentResource contains details associated with a persistent object or
// NV index.
type PersistentResource struct {
	Name   tpm2.Name
	Handle tpm2.Handle
}

// TransientResource contains details associated with a transient object.
type TransientResource struct {
	ParentName tpm2.Name
	Public     *tpm2.Public
	Private    tpm2.Private
}

// Resources contains the resources that are required by [NewTPMPolicyExecuteHelper].
type Resources struct {
	// Persistent contains the details associated with persistent objects and
	// NV indexes.
	Persistent []PersistentResource

	// Transient contains the details associated with loadable transient objects.
	Transient []TransientResource

	// AuthorizedPolicies contain authorized sub-policies
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
	SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error)
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

func (*mockResources) SignAuthorization(sessionNonce tpm2.Nonce, authKey tpm2.Name, policyRef tpm2.Nonce) (*PolicySignedAuthorization, error) {
	return &PolicySignedAuthorization{Authorization: new(PolicyAuthorization)}, nil
}
