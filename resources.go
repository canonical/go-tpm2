// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"crypto"
	_ "crypto/sha256"
	"encoding/binary"
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

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext
	Available() bool          // Whether this context represents a session that is available. Will be false for flushed or saved sessions.
	HashAlg() HashAlgorithmId // The session's digest algorithm. Will be HashAlgorithmNull if Available is false.
	NonceTPM() Nonce          // The most recent TPM nonce value. Will be empty if Available is false.
	IsAudit() bool            // Whether the session has been used for audit
	IsExclusive() bool        // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes

	Attrs() SessionAttributes                         // The attributes associated with this session
	SetAttrs(attrs SessionAttributes)                 // Set the attributes that will be used for this SessionContext
	WithAttrs(attrs SessionAttributes) SessionContext // Return a duplicate of this SessionContext with the specified attributes

	// IncludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes included.
	IncludeAttrs(attrs SessionAttributes) SessionContext
	// ExcludeAttrs returns a duplicate of this SessionContext and its attributes with the specified attributes excluded.
	ExcludeAttrs(attrs SessionAttributes) SessionContext

	SessionKey() []byte // The session key. Will be empty if Available is false.

	IsBound() bool     // Whether the session is bound. Will be false if Available is false.
	BoundEntity() Name // The bound entity. Will be false it Available is false.

	Symmetric() *SymDef // The symmetric algorithm if one is set. Will be nil if Available is false.

	NeedsPassword() bool // Whether a policy session includes the TPM2_PolicyPassword assertion. Will be false if Available is false.
	SetNeedsPassword()   // This should be called when adding a TPM2_PolicyPassword assertion to a policy session.

	NeedsAuthValue() bool // Whether a policy session includes the TPM2_PolicyAuthValue assertion. Will be false if Available is false.
	SetNeedsAuthValue()   // This should be called when adding a TPM2_PolicyAuthValue assertion to a policy session.

	Update(nonce Nonce, isAudit, isExclusive bool) // Updates the session context based on a response.

	SetSaved() // Marks the session as being saved. Available should return false after this.
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

	// Public is the public area associated with the object.
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
	IsAudit        bool
	IsExclusive    bool
	HashAlg        HashAlgorithmId
	PolicyHMACType policyHMACType
	IsBound        bool
	BoundEntity    Name
	SessionKey     []byte
	NonceTPM       Nonce
	Symmetric      *SymDef
}

type publicSized struct {
	Data *Public `tpm2:"sized"`
}

type nvPublicSized struct {
	Data *NVPublic `tpm2:"sized"`
}

type sessionContextDataSized struct {
	Data *sessionContextData `tpm2:"sized"`
}

type handleContextUnion struct {
	contents union.Contents
}

func newHandleContextUnion[T publicSized | nvPublicSized | sessionContextDataSized | Empty](contents T) *handleContextUnion {
	return &handleContextUnion{contents: union.NewContents(contents)}
}

func (d *handleContextUnion) Object() *publicSized {
	return union.ContentsPtr[publicSized](d.contents)
}

func (d *handleContextUnion) NV() *nvPublicSized {
	return union.ContentsPtr[nvPublicSized](d.contents)
}

func (d *handleContextUnion) Session() *sessionContextDataSized {
	return union.ContentsPtr[sessionContextDataSized](d.contents)
}

func (d handleContextUnion) SelectMarshal(selector any) any {
	switch selector.(Handle).Type() {
	case HandleTypePCR, HandleTypePermanent:
		return union.ContentsMarshal[Empty](d.contents)
	case HandleTypeTransient, HandleTypePersistent:
		return union.ContentsMarshal[publicSized](d.contents)
	case HandleTypeNVIndex:
		return union.ContentsMarshal[nvPublicSized](d.contents)
	case HandleTypeHMACSession, HandleTypePolicySession:
		return union.ContentsMarshal[sessionContextDataSized](d.contents)
	default:
		return nil
	}
}

func (d *handleContextUnion) SelectUnmarshal(selector any) any {
	switch selector.(Handle).Type() {
	case HandleTypePCR, HandleTypePermanent:
		return union.ContentsUnmarshal[Empty](&d.contents)
	case HandleTypeTransient, HandleTypePersistent:
		return union.ContentsUnmarshal[publicSized](&d.contents)
	case HandleTypeNVIndex:
		return union.ContentsUnmarshal[nvPublicSized](&d.contents)
	case HandleTypeHMACSession, HandleTypePolicySession:
		return union.ContentsUnmarshal[sessionContextDataSized](&d.contents)
	default:
		return nil
	}
}

type handleContext struct {
	H    Handle
	N    Name
	Data *handleContextUnion
}

var _ HandleContext = (*handleContext)(nil)

func (h *handleContext) Handle() Handle {
	return h.H
}

func (h *handleContext) Name() Name {
	return h.N
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
	h.H = HandleUnassigned
	h.N = nil
	h.Data = newHandleContextUnion(EmptyValue)
}

func (h *handleContext) checkValid() error {
	switch h.H.Type() {
	case HandleTypePCR, HandleTypeNVIndex, HandleTypePermanent, HandleTypeTransient, HandleTypePersistent:
		return nil
	case HandleTypeHMACSession, HandleTypePolicySession:
		data := h.Data.Session().Data
		if data == nil {
			return nil
		}
		if !data.HashAlg.Available() {
			return errors.New("digest algorithm for session context is not available")
		}
		switch h.H.Type() {
		case HandleTypeHMACSession:
			if data.PolicyHMACType != policyHMACTypeNoAuth {
				return errors.New("invalid policy session HMAC type for HMAC session context")
			}
		case HandleTypePolicySession:
			if data.PolicyHMACType > policyHMACTypeMax {
				return errors.New("invalid policy session HMAC type for policy session context")
			}
		default:
			panic("not reached")
		}
		return nil
	default:
		// shouldn't happen because it should have failed to unmarshal
		panic("invalid context type")
	}
}

func newLimitedHandleContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypePCR, HandleTypePermanent:
		return newPermanentContext(handle)
	case HandleTypeNVIndex:
		name := make(Name, binary.Size(Handle(0)))
		binary.BigEndian.PutUint32(name, uint32(handle))

		return newNVIndexContext(handle, name, nil)
	case HandleTypeHMACSession, HandleTypePolicySession:
		return newSessionContext(handle, nil)
	case HandleTypeTransient, HandleTypePersistent:
		name := make(Name, binary.Size(Handle(0)))
		binary.BigEndian.PutUint32(name, uint32(handle))

		return newObjectContext(handle, name, nil)
	default:
		panic("invalid handle type")
	}

}

type resourceContext struct {
	handleContext
	authValue []byte
}

func newLimitedResourceContext(handle Handle, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeNVIndex:
		return newNVIndexContext(handle, name, nil)
	case HandleTypeTransient, HandleTypePersistent:
		return newObjectContext(handle, name, nil)
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
		// ok
	default:
		panic("invalid handle type")
	}

	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &permanentContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				H:    handle,
				N:    name,
				Data: newHandleContextUnion(EmptyValue)}}}
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
		// ok
	default:
		panic("invalid handle type")
	}

	return &objectContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				H:    handle,
				N:    name,
				Data: newHandleContextUnion(publicSized{public})}}}
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

func (r *objectContext) Public() *Public {
	if _, ok := r.Data.contents.(*publicSized); !ok {
		// This context was disposed.
		return nil
	}
	return r.Data.Object().Data
}

type nvIndexContext struct {
	resourceContext
}

func newNVIndexContext(handle Handle, name Name, public *NVPublic) *nvIndexContext {
	switch handle.Type() {
	case HandleTypeNVIndex:
		// ok
	default:
		panic("invalid handle type")
	}

	return &nvIndexContext{
		resourceContext: resourceContext{
			handleContext: handleContext{
				H:    handle,
				N:    name,
				Data: newHandleContextUnion(nvPublicSized{public})}}}
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

func (r *nvIndexContext) Type() NVType {
	if _, ok := r.Data.contents.(*nvPublicSized); !ok || r.Data.NV().Data == nil {
		// This context was disposed or is limited
		return 0
	}
	return r.Data.NV().Data.Attrs.Type()
}

func (r *nvIndexContext) SetAttr(a NVAttributes) {
	if _, ok := r.Data.contents.(*nvPublicSized); !ok || r.Data.NV().Data == nil {
		// This context was disposed or is limited
		return
	}
	r.Data.NV().Data.Attrs |= a
	r.N = r.Data.NV().Data.Name()
}

type sessionContext struct {
	*handleContext
	attrs SessionAttributes
}

func newSessionContext(handle Handle, data *sessionContextData) *sessionContext {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		// ok
	default:
		if handle != HandlePW {
			panic("invalid handle type")
		}
	}

	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &sessionContext{
		handleContext: &handleContext{
			H:    handle,
			N:    name,
			Data: newHandleContextUnion(sessionContextDataSized{data})}}
}

var _ SessionContext = (*sessionContext)(nil)

func (r *sessionContext) Available() bool {
	return r.Data() != nil
}

func (r *sessionContext) HashAlg() HashAlgorithmId {
	d := r.Data()
	if d == nil {
		return HashAlgorithmNull
	}
	return d.HashAlg
}

func (r *sessionContext) NonceTPM() Nonce {
	d := r.Data()
	if d == nil {
		return nil
	}
	return d.NonceTPM
}

func (r *sessionContext) IsAudit() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.IsAudit
}

func (r *sessionContext) IsExclusive() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.IsExclusive
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
	if _, ok := r.handleContext.Data.contents.(*sessionContextDataSized); !ok {
		// This handle context was disposed
		return nil
	}
	return r.handleContext.Data.Session().Data
}

func (r *sessionContext) SessionKey() []byte {
	d := r.Data()
	if d == nil {
		return nil
	}
	return d.SessionKey
}

func (r *sessionContext) IsBound() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.IsBound
}

func (r *sessionContext) BoundEntity() Name {
	d := r.Data()
	if d == nil {
		return nil
	}
	return d.BoundEntity
}

func (r *sessionContext) Symmetric() *SymDef {
	d := r.Data()
	if d == nil {
		return nil
	}
	return d.Symmetric
}

func (r *sessionContext) NeedsPassword() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.PolicyHMACType == policyHMACTypePassword
}

func (r *sessionContext) SetNeedsPassword() {
	if r.Handle().Type() != HandleTypePolicySession {
		return
	}
	d := r.Data()
	if d == nil {
		return
	}
	d.PolicyHMACType = policyHMACTypePassword
}

func (r *sessionContext) NeedsAuthValue() bool {
	d := r.Data()
	if d == nil {
		return false
	}
	return d.PolicyHMACType == policyHMACTypeAuth
}

func (r *sessionContext) SetNeedsAuthValue() {
	if r.Handle().Type() != HandleTypePolicySession {
		return
	}
	d := r.Data()
	if d == nil {
		return
	}
	d.PolicyHMACType = policyHMACTypeAuth
}

func (r *sessionContext) Update(nonce Nonce, isAudit, isExclusive bool) {
	d := r.Data()
	if d == nil {
		return
	}
	d.NonceTPM = nonce
	d.IsAudit = isAudit
	d.IsExclusive = isExclusive
	d.PolicyHMACType = policyHMACTypeNoAuth
}

func (r *sessionContext) SetSaved() {
	if _, ok := r.handleContext.Data.contents.(*sessionContextDataSized); !ok {
		// This handle context was disposed
		return
	}
	r.handleContext.Data.Session().Data = nil
}

func pwSession() SessionContext {
	return newSessionContext(HandlePW, &sessionContextData{
		HashAlg: HashAlgorithmNull,
	}).WithAttrs(AttrContinueSession)
}

func (t *TPMContext) newResourceContextFromTPM(handle HandleContext, sessions ...SessionContext) (rc ResourceContext, err error) {
	switch handle.Handle().Type() {
	case HandleTypeNVIndex:
		rc, err = t.newNVIndexContextFromTPM(handle, sessions...)
	case HandleTypeTransient, HandleTypePersistent:
		rc, err = t.newObjectContextFromTPM(handle, sessions...)
	default:
		panic("invalid handle type")
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
// This function will panic if handle doesn't correspond to a NV index, transient object or
// persistent object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value
// of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
func (t *TPMContext) NewResourceContext(handle Handle, sessions ...SessionContext) (ResourceContext, error) {
	rc, err := t.newResourceContextFromTPM(newLimitedHandleContext(handle))
	if err != nil {
		return nil, err
	}

	if len(sessions) == 0 {
		return rc, nil
	}

	return t.newResourceContextFromTPM(rc, sessions...)
}

// NewLimitedHandleContext creates a new HandleContext for the specified handle. The returned
// HandleContext can not be used in any commands other than [TPMContext.FlushContext],
// [TPMContext.ReadPublic] or [TPMContext.NVReadPublic], and it cannot be used with any sessions.
//
// This function will panic if handle doesn't correspond to a session, transient or persistent
// object, or NV index.
func NewLimitedHandleContext(handle Handle) HandleContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeHMACSession, HandleTypePolicySession, HandleTypeTransient, HandleTypePersistent:
		return newLimitedHandleContext(handle)
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

	switch data.Handle().Type() {
	case HandleTypePCR, HandleTypePermanent:
		return nil, errors.New("cannot create a permanent context from serialized data")
	}

	if err := data.checkValid(); err != nil {
		return nil, err
	}

	var hc HandleContext
	switch data.Handle().Type() {
	case HandleTypeNVIndex:
		hc = &nvIndexContext{resourceContext: resourceContext{handleContext: *data}}
	case HandleTypeHMACSession, HandleTypePolicySession:
		if data.Data.Session().Data != nil {
			data.Data.Session().Data.IsExclusive = false
		}
		hc = &sessionContext{handleContext: data}
	case HandleTypeTransient, HandleTypePersistent:
		hc = &objectContext{resourceContext: resourceContext{handleContext: *data}}
	default:
		panic("not reached")
	}

	return hc, nil
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

// NewLimitedResourceContext creates a new ResourceContext with the specified handle and name. The
// returned ResourceContext has limited functionality - eg, it cannot be used in functions that
// require knowledge of the public area associated with the resource (such as
// [TPMContext.StartAuthSession] and some NV functions).
//
// This function will panic if handle doesn't correspond to a transient or persistent object, or an
// NV index.
func NewLimitedResourceContext(handle Handle, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
		return newLimitedResourceContext(handle, name)
	default:
		panic("invalid handle type")
	}
}

// NewNVIndexResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
//
// This requires that the associated name algorithm is linked into the current binary.
func NewNVIndexResourceContextFromPub(pub *NVPublic) (ResourceContext, error) {
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
// by calling [ResourceContext].SetAuthValue.
func NewNVIndexResourceContext(pub *NVPublic, name Name) ResourceContext {
	return newNVIndexContext(pub.Index, name, pub)
}

// NewObjectResourceContextFromPub returns a new ResourceContext created from the provided
// public area. If subsequent use of the returned ResourceContext requires knowledge of the
// authorization value of the corresponding TPM resource, this should be provided by calling
// [ResourceContext].SetAuthValue.
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
// by calling [ResourceContext].SetAuthValue.
//
// This will panic if the handle type is not [HandleTypeTransient] or [HandleTypePersistent].
func NewObjectResourceContext(handle Handle, pub *Public, name Name) ResourceContext {
	switch handle.Type() {
	case HandleTypeTransient, HandleTypePersistent:
		return newObjectContext(handle, name, pub)
	default:
		panic("invalid handle type")
	}
}
