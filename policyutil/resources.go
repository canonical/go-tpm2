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

// ResourceLoader provides a way for [Policy.Execute] to access resources.
type ResourceLoader interface {
	// LoadHandle requests that a resource context for the specified handle is created.
	// This is only called for permanent resources.
	LoadHandle(handle tpm2.Handle) (tpm2.ResourceContext, error)

	// LoadName requests that a resource with the specified name is loaded and a new
	// context is created. The Flush method of the returned context will be called
	// once the resource is no longer needed.
	LoadName(name tpm2.Name) (ResourceContext, error)

	// LoadExternal requests that the supplied public key is loaded and a new context
	// is created. The Flush method of the returned context will be called once
	// the resource is no longer needed.
	LoadExternal(public *tpm2.Public) (ResourceContext, error)

	// NeedAuthorize is called to indicate that the supplied resource needs to be
	// authorized. Implementations should set the authorization value if required,
	// and may return a policy and a session. The Close method of the returned
	// session context will be called once the session has been used.
	NeedAuthorize(resource tpm2.ResourceContext) (SessionContext, *Policy, error)
}

type SessionContext interface {
	Session() tpm2.SessionContext // The actual session
	Close() error                 // Save or flush the session for future use
}

// ResourceAuthorizer provides a way for an implementation to authorize a resource when
// using [NewTPMResourceLoader].
type ResourceAuthorizer interface {
	// NeedAuthorize is called to indicate that the supplied resource needs to be
	// authorized. Implementations should set the authorization value if required,
	// and may return a session. The Close method of the returned session context
	// will be called once the session has been used.
	NeedAuthorize(resource tpm2.ResourceContext, sessionType tpm2.SessionType) (SessionContext, error)
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

// Resources contains the resources that are required by [NewRealResourceState].
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

type tpmResourceLoader struct {
	tpm        *tpm2.TPMContext
	resources  *Resources
	authorizer ResourceAuthorizer
	loaded     []tpm2.ResourceContext
	saved      []*SavedResource
	sessions   []tpm2.SessionContext
}

// NewTPMResourceLoader returns a new ResourceLoader for the supplied TPM context.
// The other arguments are optional. The resources argument is required when a policy
// makes use of transient resources with the TPM2_PolicySecret assertion, although
// using it to explicitly specify persistent objects and NV indices can speed up
// execution. Some resources require authorization, which is performed via the
// authorizer argument. The authorizer argument is required when a policy contains
// TPM2_PolicyNV or TPM2_PolicySecret assertions.
func NewTPMResourceLoader(tpm *tpm2.TPMContext, resources *Resources, authorizer ResourceAuthorizer, sessions ...tpm2.SessionContext) ResourceLoader {
	if resources == nil {
		resources = new(Resources)
	}
	if authorizer == nil {
		authorizer = new(nullResourceAuthorizer)
	}

	return &tpmResourceLoader{
		tpm:        tpm,
		resources:  resources,
		authorizer: authorizer,
		sessions:   sessions,
	}
}

func (l *tpmResourceLoader) LoadHandle(handle tpm2.Handle) (tpm2.ResourceContext, error) {
	switch handle.Type() {
	case tpm2.HandleTypePCR, tpm2.HandleTypePermanent:
		return l.tpm.GetPermanentContext(handle), nil
	default:
		return nil, fmt.Errorf("invalid handle type %v", handle.Type())
	}
}

func (l *tpmResourceLoader) LoadName(name tpm2.Name) (ResourceContext, error) {
	if !name.IsValid() {
		return nil, errors.New("invalid name")
	}
	if name.Type() == tpm2.NameTypeHandle && (name.Handle().Type() == tpm2.HandleTypePCR || name.Handle().Type() == tpm2.HandleTypePermanent) {
		return newResourceContextNonFlushable(l.tpm.GetPermanentContext(name.Handle())), nil
	}

	// Search already loaded resources
	for _, resource := range append(l.resources.Loaded, l.loaded...) {
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		return newResourceContextNonFlushable(resource), nil
	}

	// Search saved contexts
	for _, context := range append(l.resources.Saved, l.saved...) {
		if !bytes.Equal(context.Name, name) {
			continue
		}

		hc, err := l.tpm.ContextLoad(context.Context)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(hc.Name(), name) {
			l.tpm.FlushContext(hc)
			return nil, fmt.Errorf("loaded context has the wrong name (got %#x, expected %#x)", hc.Name(), name)
		}
		resource, ok := hc.(tpm2.ResourceContext)
		if !ok {
			l.tpm.FlushContext(hc)
			return nil, fmt.Errorf("name %#x associated with a context of the wrong type", name)
		}

		return newResourceContextFlushable(l.tpm, resource), nil
	}

	// Search loadable objects
	for _, object := range l.resources.Unloaded {
		if !bytes.Equal(object.Public.Name(), name) {
			continue
		}

		parent, err := l.LoadName(object.ParentName)
		if err != nil {
			return nil, fmt.Errorf("cannot load parent for object with name %#x: %w", name, err)
		}
		defer parent.Flush()

		session, _, err := l.NeedAuthorize(parent.Resource())
		if err != nil {
			return nil, fmt.Errorf("cannot authorize parent with name %#x: %w", parent.Resource().Name(), err)
		}
		defer func() {
			if session == nil {
				return
			}
			session.Close()
		}()

		var tpmSession tpm2.SessionContext
		if session != nil {
			tpmSession = session.Session()
		}

		resource, err := l.tpm.Load(parent.Resource(), object.Private, object.Public, tpmSession, l.sessions...)
		if err != nil {
			return nil, err
		}

		if context, err := l.tpm.ContextSave(resource); err == nil {
			l.saved = append(l.saved, &SavedResource{Name: name, Context: context})
		}

		return newResourceContextFlushable(l.tpm, resource), nil
	}

	// Search persistent and NV index handles
	handles, err := l.tpm.GetCapabilityHandles(tpm2.HandleTypePersistent.BaseHandle(), math.MaxUint32, l.sessions...)
	if err != nil {
		return nil, err
	}
	nvHandles, err := l.tpm.GetCapabilityHandles(tpm2.HandleTypeNVIndex.BaseHandle(), math.MaxUint32, l.sessions...)
	if err != nil {
		return nil, err
	}
	handles = append(handles, nvHandles...)
	for _, handle := range handles {
		resource, err := l.tpm.NewResourceContext(handle, l.sessions...)
		if tpm2.IsResourceUnavailableError(err, handle) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(resource.Name(), name) {
			continue
		}

		l.loaded = append(l.loaded, resource)
		return newResourceContextNonFlushable(resource), nil
	}

	return nil, errors.New("cannot identify resource")
}

func (l *tpmResourceLoader) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	rc, err := l.tpm.LoadExternal(nil, public, tpm2.HandleOwner, l.sessions...)
	if err != nil {
		return nil, err
	}
	return newResourceContextFlushable(l.tpm, rc), nil
}

func (l *tpmResourceLoader) NeedAuthorize(resource tpm2.ResourceContext) (SessionContext, *Policy, error) {
	session, err := l.authorizer.NeedAuthorize(resource, tpm2.SessionTypeHMAC)
	return session, nil, err
}

// mockResourceLoader is an implementation of policyResources that doesn't require
// access to a TPM.
type mockResourceLoader struct {
	external map[*tpm2.Public]tpm2.Name // maps a dummy public key to a real name
}

func newMockResourceLoader(external map[*tpm2.Public]tpm2.Name) *mockResourceLoader {
	return &mockResourceLoader{
		external: external,
	}
}

func (l *mockResourceLoader) LoadHandle(handle tpm2.Handle) (tpm2.ResourceContext, error) {
	switch handle.Type() {
	case tpm2.HandleTypePCR, tpm2.HandleTypePermanent:
		// the handle is not relevant here
		return tpm2.NewLimitedResourceContext(0x80000000, tpm2.MakeHandleName(handle)), nil
	default:
		return nil, errors.New("invalid handle type")
	}
}

func (l *mockResourceLoader) LoadName(name tpm2.Name) (ResourceContext, error) {
	// the handle is not relevant here
	return newResourceContextNonFlushable(tpm2.NewLimitedResourceContext(0x80000000, name)), nil
}

func (l *mockResourceLoader) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	name, exists := l.external[public]
	if !exists {
		return nil, errors.New("unrecognized external object")
	}
	// the handle is not relevant here
	resource := tpm2.NewLimitedResourceContext(0x80000000, name)
	return newResourceContextNonFlushable(resource), nil
}

func (l *mockResourceLoader) NeedAuthorize(resource tpm2.ResourceContext) (SessionContext, *Policy, error) {
	return nil, nil, nil
}

type nullResourceLoader struct{}

func (*nullResourceLoader) LoadHandle(handle tpm2.Handle) (tpm2.ResourceContext, error) {
	return nil, errors.New("no resource loader")
}

func (*nullResourceLoader) LoadName(name tpm2.Name) (ResourceContext, error) {
	return nil, errors.New("no resource loader")
}

func (*nullResourceLoader) LoadExternal(public *tpm2.Public) (ResourceContext, error) {
	return nil, errors.New("no resource loader")
}

func (*nullResourceLoader) NeedAuthorize(resource tpm2.ResourceContext) (SessionContext, *Policy, error) {
	return nil, nil, errors.New("no resource loader")
}

type nullResourceAuthorizer struct{}

func (*nullResourceAuthorizer) NeedAuthorize(resource tpm2.ResourceContext, sessionType tpm2.SessionType) (SessionContext, error) {
	return nil, errors.New("no authorizer")
}
