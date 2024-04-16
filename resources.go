// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2/internal/union"
	"github.com/canonical/go-tpm2/mu"
)

// HandleContext corresponds to an entity that resides on the TPM. Implementations of HandleContext
// maintain some host-side state in order to be able to participate in sessions. They are
// invalidated when used in a command that results in the entity being flushed or evicted from the
// TPM. Once invalidated, they can no longer be used.
type HandleContext interface {
	// Handle returns the handle of the corresponding entity on the TPM. If Dispose has been called
	// then this will return HandleUnassigned.
	Handle() Handle
	Name() Name                        // The name of the entity. This will be empty if there isn't one or Dispose has been called.
	SerializeToBytes() []byte          // Return a byte slice containing the serialized form of this HandleContext
	SerializeToWriter(io.Writer) error // Write the serialized form of this HandleContext to the supplied io.Writer
	Dispose()                          // Called when the corresponding resource has been flushed or evicted from the TPM
}

// SessionContextParams corresponds to the parameters of a session.
type SessionContextParams struct {
	HashAlg     HashAlgorithmId // The session's digest algorithm
	IsBound     bool            // Whether the session is bound.
	BoundEntity Name            // The bound entity
	Symmetric   SymDef          // The session's symmetric algorithm
	SessionKey  []byte          // The session key
}

// SessionContextState corresponds to the state of a session.
type SessionContextState struct {
	NonceTPM       Nonce // The most recent TPM nonce value
	IsAudit        bool  // Whether the session is currently an audit session
	IsExclusive    bool  // Whether the session is currently an exclusive audit session
	NeedsPassword  bool  // Whether a policy session includes the TPM2_PolicyPassword assertion
	NeedsAuthValue bool  // Whether a policy session includes the TPM2_PolicyAuthValue assertion
}

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext

	// Params returns a copy of the session parameters. This will return a default
	// value (with HashAlg == HashAlgorithmNull) if the HandleContext.Dispose was called.
	Params() SessionContextParams

	// State provides access to read and modify the session state. This will return
	// nil if HandleContext.Dispose was called.
	State() *SessionContextState

	Attrs() SessionAttributes                         // The attributes associated with this session
	SetAttrs(attrs SessionAttributes)                 // Set the attributes that will be used for this SessionContext
	WithAttrs(attrs SessionAttributes) SessionContext // Return a duplicate of this SessionContext with the specified attributes

	// IncludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes included.
	IncludeAttrs(attrs SessionAttributes) SessionContext
	// ExcludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes excluded.
	ExcludeAttrs(attrs SessionAttributes) SessionContext
}

// ResourceContext is a HandleContext that corresponds to a non-session entity on the TPM.
type ResourceContext interface {
	HandleContext

	// AuthValue returns the authorization value previously set by SetAuthValue.
	AuthValue() []byte

	// SetAuthValue sets the authorization value that will be used in authorization roles where
	// knowledge of the authorization value is required. Functions that create resources on the TPM
	// and return a ResourceContext will set this automatically, else it will need to be set manually.
	SetAuthValue([]byte)
}

// ObjectContext is a ResourceContext that corresponds to an object on the TPM.
type ObjectContext interface {
	ResourceContext

	// Public is the public area associated with the object. This will return nil
	// if HandleContext.Dispose was called.
	Public() *Public
}

// NVIndexContext is a ResourceContext that corresponds to a NV index.
type NVIndexContext interface {
	ResourceContext

	// Type returns the type of the index
	Type() NVType

	// SetAttr is called when an attribute is set so that the context
	// can update its name.
	SetAttr(a NVAttributes)
}

type sessionContextData struct {
	Params SessionContextParams
	State  SessionContextState
}

type handleContextUnion struct {
	contents union.Contents
}

func newHandleContextUnion[T Public | NVPublic | sessionContextData | Empty](contents T) *handleContextUnion {
	return &handleContextUnion{contents: union.NewContents(contents)}
}

func (d handleContextUnion) Object() *Public {
	return union.ContentsPtr[Public](d.contents)
}

func (d handleContextUnion) NV() *NVPublic {
	return union.ContentsPtr[NVPublic](d.contents)
}

func (d handleContextUnion) Session() *sessionContextData {
	return union.ContentsPtr[sessionContextData](d.contents)
}

func (d handleContextUnion) SelectMarshal(selector any) any {
	switch selector.(handleContextType) {
	case handleContextTypePermanent, handleContextTypeLimitedResource, handleContextTypeLimited:
		return union.ContentsMarshal[Empty](d.contents)
	case handleContextTypeNVIndex:
		return union.ContentsMarshal[NVPublic](d.contents)
	case handleContextTypeSession:
		return union.ContentsMarshal[sessionContextData](d.contents)
	case handleContextTypeObject:
		return union.ContentsMarshal[Public](d.contents)
	default:
		return nil
	}
}

func (d *handleContextUnion) SelectUnmarshal(selector any) any {
	switch selector.(handleContextType) {
	case handleContextTypePermanent, handleContextTypeLimitedResource, handleContextTypeLimited:
		return union.ContentsUnmarshal[Empty](&d.contents)
	case handleContextTypeNVIndex:
		return union.ContentsUnmarshal[NVPublic](&d.contents)
	case handleContextTypeSession:
		return union.ContentsUnmarshal[sessionContextData](&d.contents)
	case handleContextTypeObject:
		return union.ContentsUnmarshal[Public](&d.contents)
	default:
		return nil
	}
}

type handleContextType uint8

const (
	handleContextTypePermanent handleContextType = 1 // corresponds to permanentContext
	handleContextTypeNVIndex   handleContextType = 2 // corresponds to nvIndexContext
	handleContextTypeSession   handleContextType = 3 // corresponds to sessionContext
	handleContextTypeObject    handleContextType = 4 // corresponds to objectContext

	// handleContextTypeLimitedResource corresponds to resourceContext. This can represent a
	// NV index or object for which we have a name but no public area.
	handleContextTypeLimitedResource handleContextType = 5

	// handleContextLimited corresponds to handleContext. This can represent any TPM resource
	// for which we only have a handle. The name will be set to the handle, which is ok for
	// permanent resources and sessions, but it means that NV indexes and objects are unsuitable
	// in any commands that use sessions.
	handleContextTypeLimited handleContextType = 6

	// handleContextTypeDisposed exists to prevent serializing handles where HandleContext.Dispose
	// has been called.
	handleContextTypeDisposed handleContextType = 7
)

func handleContextTypeFromHandle(handle Handle) handleContextType {
	switch handle.Type() {
	case HandleTypePCR, HandleTypePermanent:
		return handleContextTypePermanent
	case HandleTypeNVIndex:
		return handleContextTypeNVIndex
	case HandleTypeHMACSession, HandleTypePolicySession:
		return handleContextTypeSession
	case HandleTypeTransient, HandleTypePersistent:
		return handleContextTypeObject
	default:
		panic("invalid handle type")
	}
}

type handleContext struct {
	HandleType   handleContextType
	HandleHandle Handle
	HandleName   Name
	Data         *handleContextUnion
}

var _ HandleContext = (*handleContext)(nil)

func (h *handleContext) Handle() Handle {
	return h.HandleHandle
}

func (h *handleContext) Name() Name {
	return h.HandleName
}

func (h *handleContext) SerializeToBytes() []byte {
	data := mu.MustMarshalToBytes(h)

	hash := crypto.SHA256.New()
	hash.Write(data)
	return mu.MustMarshalToBytes(HashAlgorithmSHA256, hash.Sum(nil), data)
}

func (h *handleContext) SerializeToWriter(w io.Writer) error {
	data := mu.MustMarshalToBytes(h)

	hash := crypto.SHA256.New()
	hash.Write(data)
	_, err := mu.MarshalToWriter(w, HashAlgorithmSHA256, hash.Sum(nil), data)
	return err
}

func (h *handleContext) Dispose() {
	h.HandleType = handleContextTypeDisposed
	h.HandleHandle = HandleUnassigned
	h.HandleName = MakeHandleName(HandleUnassigned)
	h.Data = newHandleContextUnion(EmptyValue)
}

func (h *handleContext) checkValid() error {
	switch h.HandleType {
	case handleContextTypePermanent:
		switch h.HandleHandle.Type() {
		case HandleTypePCR, HandleTypePermanent:
			// ok
		default:
			return errors.New("unexpected handle type for permanent context")
		}
		expectedName := MakeHandleName(h.HandleHandle)
		if !bytes.Equal(h.HandleName, expectedName) {
			return errors.New("unexpected name for permanent context")
		}
	case handleContextTypeNVIndex:
		switch h.HandleHandle.Type() {
		case HandleTypeNVIndex:
			// ok
		default:
			return errors.New("unexpected handle type for NV index context")
		}
		if h.Data.NV().NameAlg.Available() {
			expectedName, err := h.Data.NV().ComputeName()
			if err != nil {
				return fmt.Errorf("cannot compute name of public area in NV index context: %w", err)
			}
			if !bytes.Equal(h.HandleName, expectedName) {
				return errors.New("unexpected name for NV index context")
			}
		}
	case handleContextTypeSession:
		switch h.HandleHandle.Type() {
		case HandleTypeHMACSession, HandleTypePolicySession:
			// ok
		default:
			return errors.New("unexpected handle type for session context")
		}
		expectedName := MakeHandleName(h.HandleHandle)
		if !bytes.Equal(h.HandleName, expectedName) {
			return errors.New("unexpected name for session context")
		}
		data := h.Data.Session()
		if !data.Params.HashAlg.Available() {
			return errors.New("session context digest algorithm is not available")
		}
		if len(data.Params.SessionKey) > 0 && len(data.Params.SessionKey) != data.Params.HashAlg.Size() {
			return errors.New("inconsistent digest algorithm and session key length for session context")
		}
		switch h.HandleHandle.Type() {
		case HandleTypeHMACSession:
			if data.Params.IsBound && len(data.Params.SessionKey) == 0 {
				return errors.New("inconsistent bind parameters and session key length for HMAC session context")
			}
			if data.Params.IsBound && len(data.Params.BoundEntity) == 0 || !data.Params.IsBound && len(data.Params.BoundEntity) > 0 {
				return errors.New("inconsistent bind parameters for HMAC session context")
			}
			if data.State.NeedsPassword || data.State.NeedsAuthValue {
				return errors.New("invalid policy session auth type for HMAC session context")
			}
		case HandleTypePolicySession:
			if data.Params.IsBound || len(data.Params.BoundEntity) > 0 {
				return errors.New("invalid bind parameters for policy session context")
			}
			if data.State.NeedsPassword && data.State.NeedsAuthValue {
				return errors.New("inconsistent auth types for policy session context")
			}
		default:
			panic("not reached")
		}
		return nil
	case handleContextTypeObject:
		switch h.HandleHandle.Type() {
		case HandleTypeTransient, HandleTypePersistent:
			// ok
		default:
			return errors.New("unexpected handle type for object context")
		}
		if h.Data.Object().NameAlg.Available() {
			expectedName, err := h.Data.Object().ComputeName()
			if err != nil {
				return fmt.Errorf("cannot compute name of public area in object context: %w", err)
			}
			if !bytes.Equal(h.HandleName, expectedName) {
				return errors.New("unexpected name for object context")
			}
		}
	case handleContextTypeLimitedResource:
		switch h.HandleHandle.Type() {
		case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
			// ok
		default:
			return errors.New("unexpected handle type for limited resource context")
		}
	case handleContextTypeLimited:
		switch h.HandleHandle.Type() {
		case HandleTypePCR, HandleTypeNVIndex, HandleTypeHMACSession, HandleTypePolicySession, HandleTypePermanent, HandleTypeTransient, HandleTypePersistent:
			// ok
		default:
			return errors.New("unexpected handle type for limited context")
		}
		expectedName := mu.MustMarshalToBytes(h.HandleHandle)
		if !bytes.Equal(h.HandleName, expectedName) {
			return errors.New("unexpected name for limited context")
		}
	default:
		panic("not reached")
	}

	return nil
}

func newHandleContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypePCR, HandleTypeNVIndex, HandleTypeHMACSession, HandleTypePolicySession, HandleTypePermanent, HandleTypeTransient, HandleTypePersistent:
		return &handleContext{
			HandleType:   handleContextTypeLimited,
			HandleHandle: handle,
			HandleName:   mu.MustMarshalToBytes(handle),
			Data:         newHandleContextUnion(EmptyValue),
		}
	default:
		panic("invalid handle type")
	}
}

type resourceContext struct {
	handleContext
	authValue []byte
}

func newResourceContext(handle Handle, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypePCR, HandleTypeNVIndex, HandleTypePermanent, HandleTypeTransient, HandleTypePersistent:
		return &resourceContext{
			handleContext: handleContext{
				HandleType:   handleContextTypeLimitedResource,
				HandleHandle: handle,
				HandleName:   name,
				Data:         newHandleContextUnion(EmptyValue),
			},
		}
	default:
		panic("invalid handle type")
	}
}

var _ ResourceContext = (*resourceContext)(nil)

func (r *resourceContext) SetAuthValue(authValue []byte) {
	r.authValue = authValue
}

func (r *resourceContext) Dispose() {
	r.authValue = nil
	r.handleContext.Dispose()
}

func (r *resourceContext) AuthValue() []byte {
	return bytes.TrimRight(r.authValue, "\x00")
}

type permanentContext struct {
	resourceContext
}

func newPermanentContext(handle Handle) *permanentContext {
	switch handle.Type() {
	case HandleTypePCR, HandleTypePermanent:
		return &permanentContext{
			resourceContext: resourceContext{
				handleContext: handleContext{
					HandleType:   handleContextTypePermanent,
					HandleHandle: handle,
					HandleName:   MakeHandleName(handle),
					Data:         newHandleContextUnion(EmptyValue),
				},
			},
		}
	default:
		panic("invalid handle type")
	}
}

var _ ResourceContext = (*permanentContext)(nil)

func (r *permanentContext) Dispose() {}

func nullResource() ResourceContext {
	return newPermanentContext(HandleNull)
}

type objectContext struct {
	resourceContext
}

func newObjectContext(handle Handle, name Name, public *Public) *objectContext {
	switch handle.Type() {
	case HandleTypeTransient, HandleTypePersistent:
		if public == nil {
			panic("nil public area")
		}
		return &objectContext{
			resourceContext: resourceContext{
				handleContext: handleContext{
					HandleType:   handleContextTypeObject,
					HandleHandle: handle,
					HandleName:   name,
					Data:         newHandleContextUnion(*public),
				},
			},
		}
	default:
		panic("invalid handle type")
	}
}

func (t *TPMContext) newObjectContextFromTPM(context HandleContext, sessions ...SessionContext) (ResourceContext, error) {
	pub, name, _, err := t.ReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if pub.NameAlg.Available() && !pub.compareName(name) {
		return nil, &InvalidResponseError{CommandReadPublic, errors.New("name and public area returned from TPM don't match")}
	}
	return newObjectContext(context.Handle(), name, pub), nil
}

var _ ObjectContext = (*objectContext)(nil)

func (r *objectContext) Dispose() {
	r.resourceContext.Dispose()
	r.Data = newHandleContextUnion(Public{Type: ObjectTypeId(AlgorithmNull), NameAlg: HashAlgorithmNull})
}

func (r *objectContext) Public() *Public {
	return r.Data.Object()
}

type nvIndexContext struct {
	resourceContext
}

func newNVIndexContext(handle Handle, name Name, public *NVPublic) *nvIndexContext {
	switch handle.Type() {
	case HandleTypeNVIndex:
		if public == nil {
			panic("nil public area")
		}
		return &nvIndexContext{
			resourceContext: resourceContext{
				handleContext: handleContext{
					HandleType:   handleContextTypeNVIndex,
					HandleHandle: handle,
					HandleName:   name,
					Data:         newHandleContextUnion(*public),
				},
			},
		}
	default:
		panic("invalid handle type")
	}
}

func (t *TPMContext) newNVIndexContextFromTPM(context HandleContext, sessions ...SessionContext) (ResourceContext, error) {
	pub, name, err := t.NVReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if pub.NameAlg.Available() && !pub.compareName(name) {
		return nil, &InvalidResponseError{CommandNVReadPublic, errors.New("name and public area returned from TPM don't match")}
	}
	if pub.Index != context.Handle() {
		return nil, &InvalidResponseError{CommandNVReadPublic, errors.New("unexpected index in public area")}
	}
	return newNVIndexContext(context.Handle(), name, pub), nil
}

var _ NVIndexContext = (*nvIndexContext)(nil)

func (r *nvIndexContext) Dispose() {
	r.resourceContext.Dispose()
	r.Data = newHandleContextUnion(NVPublic{NameAlg: HashAlgorithmNull})
}

func (r *nvIndexContext) Type() NVType {
	return r.Data.NV().Attrs.Type()
}

func (r *nvIndexContext) SetAttr(a NVAttributes) {
	r.Data.NV().Attrs |= a
	r.HandleName = r.Data.NV().Name()
}

type sessionContext struct {
	*handleContext
	attrs SessionAttributes
}

func newSessionContext(handle Handle, data *sessionContextData) *sessionContext {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		if data == nil {
			panic("nil session data")
		}
	default:
		if data == nil {
			panic("nil session data")
		}
		if handle != HandlePW {
			panic("invalid handle type")
		}
	}

	return &sessionContext{
		handleContext: &handleContext{
			HandleType:   handleContextTypeSession,
			HandleHandle: handle,
			HandleName:   MakeHandleName(handle),
			Data:         newHandleContextUnion(*data),
		},
	}
}

var _ SessionContext = (*sessionContext)(nil)

func (r *sessionContext) Dispose() {
	r.handleContext.Dispose()
	r.handleContext.Data = newHandleContextUnion(sessionContextData{
		Params: SessionContextParams{
			HashAlg:   HashAlgorithmNull,
			Symmetric: SymDef{Algorithm: SymAlgorithmNull},
		},
	})
}

func (r *sessionContext) Params() SessionContextParams {
	return r.Data().Params
}

func (r *sessionContext) State() *SessionContextState {
	return &r.Data().State
}

func (r *sessionContext) Attrs() SessionAttributes {
	attrs := r.attrs
	if attrs&AttrAuditExclusive > 0 {
		attrs |= AttrAudit
	}
	if attrs&AttrAuditReset > 0 {
		attrs |= AttrAudit
	}
	return attrs
}

func (r *sessionContext) SetAttrs(attrs SessionAttributes) {
	r.attrs = attrs
}

func (r *sessionContext) WithAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: attrs}
}

func (r *sessionContext) IncludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: r.attrs | attrs}
}

func (r *sessionContext) ExcludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{handleContext: r.handleContext, attrs: r.attrs &^ attrs}
}

func (r *sessionContext) Data() *sessionContextData {
	return r.handleContext.Data.Session()
}

func pwSession() SessionContext {
	return newSessionContext(HandlePW, &sessionContextData{
		Params: SessionContextParams{
			HashAlg:   HashAlgorithmNull,
			Symmetric: SymDef{Algorithm: SymAlgorithmNull},
		},
	}).WithAttrs(AttrContinueSession)
}

func (t *TPMContext) newResourceContextFromTPM(handle HandleContext, sessions ...SessionContext) (rc ResourceContext, err error) {
	switch handle.Handle().Type() {
	case HandleTypeNVIndex:
		rc, err = t.newNVIndexContextFromTPM(handle, sessions...)
	case HandleTypeTransient, HandleTypePersistent:
		rc, err = t.newObjectContextFromTPM(handle, sessions...)
	default:
		return nil, errors.New("invalid handle type")
	}

	switch {
	case IsTPMWarning(err, WarningReferenceH0, AnyCommandCode):
		return nil, ResourceUnavailableError{handle.Handle()}
	case IsTPMHandleError(err, ErrorHandle, AnyCommandCode, AnyHandleIndex):
		return nil, ResourceUnavailableError{handle.Handle()}
	case err != nil:
		return nil, err
	}

	return rc, nil
}

// NewResourceContext creates and returns a new ResourceContext for the specified handle. It will
// execute a command to read the public area from the TPM in order to initialize state that
// is maintained on the host side. A [ResourceUnavailableError] error will be returned if the
// specified handle references a resource that doesn't exist.
//
// The public area and name returned from the TPM are checked for consistency as long as the
// corresponding name algorithm is linked into the current binary.
//
// If any sessions are supplied, the public area is read from the TPM twice. The second time uses
// the supplied sessions.
//
// This function will return an error if handle doesn't correspond to a NV index, transient object
// or persistent object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// If the specified handle is an object, the returned context can be type asserted to [ObjectContext].
// If the specified handle is a NV index, the returned context can be type asserted to [NVIndexContext].
func (t *TPMContext) NewResourceContext(handle Handle, sessions ...SessionContext) (ResourceContext, error) {
	rc, err := t.newResourceContextFromTPM(newHandleContext(handle))
	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		return rc, nil
	}

	return t.newResourceContextFromTPM(rc, sessions...)
}

// NewHandleContext creates a new HandleContext for the specified handle. The returned
// HandleContext cannot be type asserted to [ResourceContext] or [SessionContext] and can
// only be used in commands that don't use sessions, such as [TPMContext.FlushContext],
// [TPMContext.ReadPublic] or [TPMContext.NVReadPublic].
//
// This function will panic if handle doesn't correspond to a session, transient or
// persistent object, or NV index.
func NewHandleContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeHMACSession, HandleTypePolicySession, HandleTypeTransient, HandleTypePersistent:
		return newHandleContext(handle)
	default:
		panic("invalid handle type")
	}
}

// GetPermanentContext returns a ResourceContext for the specified permanent handle or PCR handle.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func (t *TPMContext) GetPermanentContext(handle Handle) ResourceContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
		if rc, exists := t.permanentResources[handle]; exists {
			return rc
		}

		rc := newPermanentContext(handle)
		t.permanentResources[handle] = rc
		return rc
	default:
		panic("invalid handle type")
	}
}

// OwnerHandleContext returns the ResouceContext corresponding to the owner hiearchy.
func (t *TPMContext) OwnerHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleOwner)
}

// NulHandleContext returns the ResourceContext corresponding to the null hiearchy.
func (t *TPMContext) NullHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleNull)
}

// LockoutHandleContext returns the ResourceContext corresponding to the lockout hiearchy.
func (t *TPMContext) LockoutHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleLockout)
}

// EndorsementHandleContext returns the ResourceContext corresponding to the endorsement hiearchy.
func (t *TPMContext) EndorsementHandleContext() ResourceContext {
	return t.GetPermanentContext(HandleEndorsement)
}

// PlatformHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformHandleContext() ResourceContext {
	return t.GetPermanentContext(HandlePlatform)
}

// PlatformNVHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformNVHandleContext() ResourceContext {
	return t.GetPermanentContext(HandlePlatformNV)
}

// PCRHandleContext returns the ResourceContext corresponding to the PCR at the specified index.
// It will panic if pcr is not a valid PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) ResourceContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetPermanentContext(h)
}

// NewHandleContextFromReader returns a new HandleContext created from the serialized data read
// from the supplied io.Reader. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func NewHandleContextFromReader(r io.Reader) (HandleContext, error) {
	var integrityAlg HashAlgorithmId
	var integrity []byte
	var b []byte
	if _, err := mu.UnmarshalFromReader(r, &integrityAlg, &integrity, &b); err != nil {
		return nil, fmt.Errorf("cannot unpack context blob and checksum: %w", err)
	}

	if !integrityAlg.Available() {
		return nil, errors.New("invalid checksum algorithm")
	}
	h := integrityAlg.NewHash()
	h.Write(b)
	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("invalid checksum")
	}

	var data *handleContext
	n, err := mu.UnmarshalFromBytes(b, &data)
	if err != nil {
		return nil, fmt.Errorf("cannot unmarshal context data: %w", err)
	}
	if n < len(b) {
		return nil, errors.New("context blob contains trailing bytes")
	}

	if err := data.checkValid(); err != nil {
		return nil, err
	}

	switch data.HandleType {
	case handleContextTypePermanent:
		return newPermanentContext(data.Handle()), nil
	case handleContextTypeNVIndex:
		return newNVIndexContext(data.Handle(), data.Name(), data.Data.NV()), nil
	case handleContextTypeSession:
		data.Data.Session().State.IsExclusive = false
		return newSessionContext(data.Handle(), data.Data.Session()), nil
	case handleContextTypeObject:
		return newObjectContext(data.Handle(), data.Name(), data.Data.Object()), nil
	case handleContextTypeLimitedResource:
		return newResourceContext(data.Handle(), data.Name()), nil
	case handleContextTypeLimited:
		return newHandleContext(data.Handle()), nil
	default:
		// this should have been caught earlier
		panic("not reached")
	}
}

// NewHandleContextFromBytes returns a new HandleContext created from the serialized data read
// from the supplied byte slice. This should contain data that was previously created by
// [HandleContext].SerializeToBytes or [HandleContext].SerializeToWriter.
//
// If the supplied data corresponds to a session then a [SessionContext] will be returned, else a
// [ResourceContext] will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func NewHandleContextFromBytes(b []byte) (HandleContext, int, error) {
	buf := bytes.NewReader(b)
	rc, err := NewHandleContextFromReader(buf)
	if err != nil {
		return nil, 0, err
	}
	return rc, len(b) - buf.Len(), nil
}

// NewResourceContext creates a new ResourceContext with the specified handle and name. The
// returned ResourceContext has limited functionality - eg, it cannot bs used in functions that
// require knowledge of the public area associated with the resource (such as
// [TPMContext.StartAuthSession]), and some NV functions that modify the attributes of an index
// will not update its name. It cannot be type asserted to [ObjectContext] or [NVIndexContext].
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This function will panic if handle doesn't correspond to a transient or persistent object, or an
// NV index.
func NewResourceContext(handle Handle, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
		return newResourceContext(handle, name)
	default:
		panic("invalid handle type")
	}
}

// NewNVIndexResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue. The returned context can be type asserted to
// [NVIndexContext].
//
// This requires that the associated name algorithm is linked into the current binary.
func NewNVIndexResourceContextFromPub(pub *NVPublic) (ResourceContext, error) {
	if pub.Index.Type() != HandleTypeNVIndex {
		return nil, errors.New("invalid handle type")
	}
	name, err := pub.ComputeName()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name from public area: %v", err)
	}
	return newNVIndexContext(pub.Index, name, pub), nil
}

// NewNVIndexResourceContext returns a new ResourceContext created from the provided public area
// and associated name. This is useful for creating a ResourceContext for an object that uses a
// name algorithm that is not available. If subsequent use of the returned ResourceContext requires
// knowledge of the authorization value of the corresponding TPM resource, this should be provided
// by calling [ResourceContext].SetAuthValue. The returned context can be type asserted to
// [NVIndexContext].
//
// This does not check the consistency of the name and public area.
//
// It will panic if the Index field of the supplied public area has a handle type other than
// [HandleTypeNVIndex].
func NewNVIndexResourceContext(pub *NVPublic, name Name) ResourceContext {
	return newNVIndexContext(pub.Index, name, pub)
}

// NewObjectResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue. The returned context can be type asserted to
// [ObjectContext].
//
// This requires that the associated name algorithm is linked into the current binary.
func NewObjectResourceContextFromPub(handle Handle, pub *Public) (ResourceContext, error) {
	switch handle.Type() {
	case HandleTypeTransient, HandleTypePersistent:
		name, err := pub.ComputeName()
		if err != nil {
			return nil, fmt.Errorf("cannot compute name from public area: %v", err)
		}
		return newObjectContext(handle, name, pub), nil
	default:
		return nil, errors.New("invalid handle type")
	}
}

// NewObjectResourceContext returns a new ResourceContext created from the provided public area and
// associated name. This is useful for creating a ResourceContext for an object that uses a name
// algorithm that is not available. If subsequent use of the returned ResourceContext requires
// knowledge of the authorization value of the corresponding TPM resource, this should be provided
// by calling [ResourceContext].SetAuthValue. The returned context can be type asserted to
// [ObjectContext].
//
// This does not check the consistency of the name and public area.
//
// This will panic if the handle type is not [HandleTypeTransient] or [HandleTypePersistent].
func NewObjectResourceContext(handle Handle, pub *Public, name Name) ResourceContext {
	return newObjectContext(handle, name, pub)
}
