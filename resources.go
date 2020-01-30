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
	"reflect"

	"golang.org/x/xerrors"
)

// HandleContext corresponds to an entity that resides on the TPM. Implementations of HandleContext maintain some host-side
// state in order to be able to participate in HMAC sessions and session-based parameter encryption. HandleContext instances are
// tracked by the TPMContext that created them (when the corresponding TPM entity is created or loaded), and are invalidated when
// the entity is flushed or evicted from the TPM. They may also be invalidated if the TPM indicates it has allocated an entity with
// the same handle as an existing HandleContext - these stale HandleContext instances may occur when working with sessions or
// persistent resources via a resource manager. Once invalidated, they can no longer be used.
type HandleContext interface {
	// Handle returns the handle of the corresponding entity on the TPM. If the HandleContext has been invalidated because the
	// corresponding entity has been flushed from the TPM or the TPM indicated that this HandleContext is stale by allocating
	// another entity with the same handle, this will return HandleUnassigned
	Handle() Handle
	Name() Name                        // The name of the entity
	SerializeToBytes() []byte          // Return a byte slice containing the serialized form of this HandleContext
	SerializeToWriter(io.Writer) error // Write the serialized form of this HandleContext to the supplied io.Writer
}

type handleContextPrivate interface {
	invalidate()
	data() *handleContextData
}

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext
	NonceTPM() Nonce   // The most recent TPM nonce value
	IsAudit() bool     // Whether the session has been used for audit
	IsExclusive() bool // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes
}

// ResourceContext is a HandleContext that corresponds to a non-session entity on the TPM.
type ResourceContext interface {
	HandleContext

	// SetAuthValue sets the authorization value that will be used in authorization roles where knowledge of the authorization
	// value is required. Functions that create resources on the TPM and return a ResourceContext will set this automatically,
	// else it will need to be set manually.
	SetAuthValue([]byte)
}

type resourceContextPrivate interface {
	authValue() []byte
}

type handleContextType uint8

const (
	handleContextTypeUntracked handleContextType = iota
	handleContextTypePermanent
	handleContextTypeObject
	handleContextTypeNvIndex
	handleContextTypeSession
)

type sessionContextData struct {
	IsAudit        bool
	IsExclusive    bool
	HashAlg        HashAlgorithmId
	SessionType    SessionType
	PolicyHMACType policyHMACType
	IsBound        bool
	BoundEntity    Name
	SessionKey     []byte
	NonceCaller    Nonce
	NonceTPM       Nonce
	Symmetric      *SymDef
}

type handleContextDataU struct {
	Data interface{}
}

func (d handleContextDataU) Select(selector reflect.Value) (reflect.Type, error) {
	switch selector.Interface().(handleContextType) {
	case handleContextTypeUntracked, handleContextTypePermanent:
		return nil, nil
	case handleContextTypeObject:
		return reflect.TypeOf((*Public)(nil)), nil
	case handleContextTypeNvIndex:
		return reflect.TypeOf((*NVPublic)(nil)), nil
	case handleContextTypeSession:
		return reflect.TypeOf((*sessionContextData)(nil)), nil
	}
	return nil, invalidSelectorError{selector}
}

type handleContextData struct {
	Type   handleContextType
	Handle Handle
	Name   Name
	Data   handleContextDataU `tpm2:"selector:Type"`
}

func (d *handleContextData) serializeToBytes() []byte {
	data, err := MarshalToBytes(d)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal context data: %v", err))
	}
	h := crypto.SHA256.New()
	h.Write(data)
	data, err = MarshalToBytes(HashAlgorithmSHA256, h.Sum(nil), data)
	if err != nil {
		panic(fmt.Sprintf("cannot pack context blob and checksum: %v", err))
	}
	return data
}

func (d *handleContextData) serializeToWriter(w io.Writer) error {
	data, err := MarshalToBytes(d)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal context data: %v", err))
	}
	h := crypto.SHA256.New()
	h.Write(data)
	return MarshalToWriter(w, HashAlgorithmSHA256, h.Sum(nil), data)
}

func (d *handleContextData) checkConsistency() error {
	switch d.Type {
	case handleContextTypePermanent:
		switch d.Handle.Type() {
		case HandleTypePCR, HandleTypePermanent:
		default:
			return errors.New("inconsistent handle type for permanent context")
		}
		if !d.Name.IsHandle() || d.Name.Handle() != d.Handle {
			return errors.New("name inconsistent with handle for permanent context")
		}
	case handleContextTypeObject:
		switch d.Handle.Type() {
		case HandleTypeTransient, HandleTypePersistent:
		default:
			return errors.New("inconsistent handle type for object context")
		}
		public, ok := d.Data.Data.(*Public)
		if !ok {
			return errors.New("inconsistent data type for object context")
		}
		if public == nil {
			return errors.New("no public area for object context")
		}
		if !public.compareName(d.Name) {
			return errors.New("name inconsistent with public area for object context")
		}
	case handleContextTypeNvIndex:
		if d.Handle.Type() != HandleTypeNVIndex {
			return errors.New("inconsistent handle type for NV context")
		}
		public, ok := d.Data.Data.(*NVPublic)
		if !ok {
			return errors.New("inconsistent data type for NV context")
		}
		if public == nil {
			return errors.New("no public area for NV context")
		}
		if !public.compareName(d.Name) {
			return errors.New("name inconsistent with public area for NV context")
		}
	case handleContextTypeSession:
		switch d.Handle.Type() {
		case HandleTypeHMACSession, HandleTypePolicySession:
		default:
			return errors.New("inconsistent handle type for session context")
		}
		if !d.Name.IsHandle() || d.Name.Handle() != d.Handle {
			return errors.New("name inconsistent with handle for session context")
		}
		scData, ok := d.Data.Data.(*sessionContextData)
		if !ok {
			return errors.New("inconsistent data type for session context")
		}
		if scData != nil {
			if !scData.IsAudit && scData.IsExclusive {
				return errors.New("inconsistent audit attributes for session context")
			}
			if !scData.HashAlg.Supported() {
				return errors.New("invalid digest algorithm for session context")
			}
			switch scData.SessionType {
			case SessionTypeHMAC, SessionTypePolicy, SessionTypeTrial:
			default:
				return errors.New("invalid session type for session context")
			}
			if scData.PolicyHMACType > policyHMACTypeMax {
				return errors.New("invalid policy session HMAC type for session context")
			}
			if (scData.IsBound && len(scData.BoundEntity) == 0) || (!scData.IsBound && len(scData.BoundEntity) > 0) {
				return errors.New("invalid bind properties for session context")
			}
			digestSize := scData.HashAlg.Size()
			if len(scData.SessionKey) != digestSize && len(scData.SessionKey) != 0 {
				return errors.New("unexpected session key size for session context")
			}
			if len(scData.NonceCaller) != digestSize || len(scData.NonceTPM) != digestSize {
				return errors.New("unexpected nonce size for session context")
			}
			switch scData.Symmetric.Algorithm {
			case SymAlgorithmAES, SymAlgorithmXOR, SymAlgorithmNull, SymAlgorithmSM4, SymAlgorithmCamellia:
			default:
				return errors.New("invalid symmetric algorithm for session context")
			}
			switch scData.Symmetric.Algorithm {
			case SymAlgorithmAES, SymAlgorithmSM4, SymAlgorithmCamellia:
				if scData.Symmetric.Mode.Sym() != SymModeCFB {
					return errors.New("invalid symmetric mode for session context")
				}
			}
		}
	default:
		return errors.New("unrecognized context type")
	}
	return nil
}

type untrackedContext struct {
	d handleContextData
}

func (r *untrackedContext) Handle() Handle {
	return r.d.Handle
}

func (r *untrackedContext) Name() Name {
	return r.d.Name
}

func (r *untrackedContext) SerializeToBytes() []byte {
	return nil
}

func (r *untrackedContext) SerializeToWriter(io.Writer) error {
	return nil
}

func (r *untrackedContext) SetAuthValue([]byte) {
}

func (r *untrackedContext) invalidate() {
}

func (r *untrackedContext) data() *handleContextData {
	return &r.d
}

func makeUntrackedContext(handle Handle) *untrackedContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &untrackedContext{d: handleContextData{Type: handleContextTypeUntracked, Handle: handle, Name: name}}
}

type permanentContext struct {
	d    handleContextData
	auth []byte
}

func (r *permanentContext) Handle() Handle {
	return r.d.Handle
}

func (r *permanentContext) Name() Name {
	return r.d.Name
}

func (r *permanentContext) SerializeToBytes() []byte {
	return r.d.serializeToBytes()
}

func (r *permanentContext) SerializeToWriter(w io.Writer) error {
	return r.d.serializeToWriter(w)
}

func (r *permanentContext) SetAuthValue(value []byte) {
	r.auth = value
}

func (r *permanentContext) invalidate() {
	r.d.Handle = HandleUnassigned
	r.d.Name = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(r.d.Name, uint32(r.d.Handle))
}

func (r *permanentContext) data() *handleContextData {
	return &r.d
}

func (r *permanentContext) authValue() []byte {
	return r.auth
}

func makePermanentContext(handle Handle) *permanentContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &permanentContext{d: handleContextData{Type: handleContextTypePermanent, Handle: handle, Name: name}}
}

type objectContext struct {
	d    handleContextData
	auth []byte
}

func (r *objectContext) Handle() Handle {
	return r.d.Handle
}

func (r *objectContext) Name() Name {
	return r.d.Name
}

func (r *objectContext) SerializeToBytes() []byte {
	return r.d.serializeToBytes()
}

func (r *objectContext) SerializeToWriter(w io.Writer) error {
	return r.d.serializeToWriter(w)
}

func (r *objectContext) SetAuthValue(value []byte) {
	r.auth = value
}

func (r *objectContext) invalidate() {
	r.d.Handle = HandleUnassigned
	r.d.Name = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(r.d.Name, uint32(r.d.Handle))
	r.d.Data.Data = (*Public)(nil)
}

func (r *objectContext) data() *handleContextData {
	return &r.d
}

func (r *objectContext) authValue() []byte {
	return r.auth
}

func (r *objectContext) public() *Public {
	return r.d.Data.Data.(*Public)
}

func makeObjectContext(handle Handle, name Name, public *Public) *objectContext {
	return &objectContext{d: handleContextData{Type: handleContextTypeObject, Handle: handle, Name: name, Data: handleContextDataU{public}}}
}

func makeObjectContextFromTPM(t *TPMContext, context ResourceContext, sessions ...*Session) (ResourceContext, error) {
	pub, name, _, err := t.ReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if n, err := pub.Name(); err != nil {
		return nil, &InvalidResponseError{CommandReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, &InvalidResponseError{CommandReadPublic, "name and public area don't match"}
	}
	return makeObjectContext(context.Handle(), name, pub), nil
}

type nvIndexContext struct {
	d    handleContextData
	auth []byte
}

func (r *nvIndexContext) Handle() Handle {
	return r.d.Handle
}

func (r *nvIndexContext) Name() Name {
	return r.d.Name
}

func (r *nvIndexContext) SerializeToBytes() []byte {
	return r.d.serializeToBytes()
}

func (r *nvIndexContext) SerializeToWriter(w io.Writer) error {
	return r.d.serializeToWriter(w)
}

func (r *nvIndexContext) SetAuthValue(value []byte) {
	r.auth = value
}

func (r *nvIndexContext) invalidate() {
	r.d.Handle = HandleUnassigned
	r.d.Name = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(r.d.Name, uint32(r.d.Handle))
	r.d.Data.Data = (*NVPublic)(nil)
}

func (r *nvIndexContext) data() *handleContextData {
	return &r.d
}

func (r *nvIndexContext) authValue() []byte {
	return r.auth
}

func (r *nvIndexContext) setAttr(a NVAttributes) {
	r.d.Data.Data.(*NVPublic).Attrs |= a
	name, _ := r.d.Data.Data.(*NVPublic).Name()
	r.d.Name = name
}

func (r *nvIndexContext) clearAttr(a NVAttributes) {
	r.d.Data.Data.(*NVPublic).Attrs &= ^a
	name, _ := r.d.Data.Data.(*NVPublic).Name()
	r.d.Name = name
}

func (r *nvIndexContext) attrs() NVAttributes {
	return r.d.Data.Data.(*NVPublic).Attrs
}

func makeNVIndexContext(handle Handle, name Name, public *NVPublic) *nvIndexContext {
	return &nvIndexContext{d: handleContextData{Type: handleContextTypeNvIndex, Handle: handle, Name: name, Data: handleContextDataU{public}}}
}

func makeNVIndexContextFromTPM(t *TPMContext, context ResourceContext, sessions ...*Session) (ResourceContext, error) {
	pub, name, err := t.NVReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if n, err := pub.Name(); err != nil {
		return nil, &InvalidResponseError{CommandNVReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, &InvalidResponseError{CommandNVReadPublic, "name and public area don't match"}
	}
	return makeNVIndexContext(context.Handle(), name, pub), nil
}

type sessionContext struct {
	d handleContextData
}

func (r *sessionContext) Handle() Handle {
	return r.d.Handle
}

func (r *sessionContext) Name() Name {
	return r.d.Name
}

func (r *sessionContext) SerializeToBytes() []byte {
	return r.d.serializeToBytes()
}

func (r *sessionContext) SerializeToWriter(w io.Writer) error {
	return r.d.serializeToWriter(w)
}

func (r *sessionContext) NonceTPM() Nonce {
	d := r.d.Data.Data.(*sessionContextData)
	if d == nil {
		return nil
	}
	return d.NonceTPM
}

func (r *sessionContext) IsAudit() bool {
	d := r.d.Data.Data.(*sessionContextData)
	if d == nil {
		return false
	}
	return d.IsAudit
}

func (r *sessionContext) IsExclusive() bool {
	d := r.d.Data.Data.(*sessionContextData)
	if d == nil {
		return false
	}
	return d.IsExclusive
}

func (r *sessionContext) invalidate() {
	r.d.Handle = HandleUnassigned
	r.d.Name = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(r.d.Name, uint32(r.d.Handle))
}

func (r *sessionContext) data() *handleContextData {
	return &r.d
}

func (r *sessionContext) scData() *sessionContextData {
	return r.d.Data.Data.(*sessionContextData)
}

func makeSessionContext(handle Handle, data *sessionContextData) *sessionContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &sessionContext{d: handleContextData{Type: handleContextTypeSession, Handle: handle, Name: name, Data: handleContextDataU{data}}}
}

func makeIncompleteSessionContext(t *TPMContext, handle Handle) (SessionContext, error) {
	hr := handle & 0x00ffffff
	h, err := t.GetCapabilityHandles(hr|(Handle(HandleTypeLoadedSession)<<24), 1)
	if err != nil {
		return nil, err
	}
	if len(h) > 0 && h[0] == handle {
		return makeSessionContext(handle, nil), nil
	}
	h, err = t.GetCapabilityHandles(hr|(Handle(HandleTypeSavedSession)<<24), 1)
	if err != nil {
		return nil, err
	}
	if len(h) > 0 && h[0]&0x00ffffff == hr {
		return makeSessionContext(hr|(Handle(HandleTypeHMACSession)<<24), nil), nil
	}
	return nil, nil
}

func normalizeHandleForMap(handle Handle) Handle {
	if handle.Type() != HandleTypePolicySession {
		return handle
	}
	return (handle & 0x00ffffff) | (Handle(HandleTypeHMACSession) << 24)
}

func (t *TPMContext) evictHandleContext(rc HandleContext) {
	if err := t.checkHandleContextParam(rc); err != nil {
		panic(fmt.Sprintf("Attempting to evict an invalid resource context: %v", err))
	}
	delete(t.resources, normalizeHandleForMap(rc.Handle()))
	rc.(handleContextPrivate).invalidate()
}

func (t *TPMContext) addHandleContext(rc HandleContext) {
	if rc.Handle() == HandleUnassigned {
		panic("Attempting to add a closed resource context")
	}
	handle := normalizeHandleForMap(rc.Handle())
	if existing, exists := t.resources[handle]; exists && existing != rc {
		t.evictHandleContext(existing)
	}
	t.resources[handle] = rc
}

func (t *TPMContext) checkHandleContextParam(rc HandleContext) error {
	if rc == nil {
		return errors.New("nil value")
	}
	if _, isUntracked := rc.(*untrackedContext); isUntracked {
		return nil
	}
	if rc.Handle() == HandleUnassigned {
		return errors.New("resource has been closed")
	}
	erc, exists := t.resources[normalizeHandleForMap(rc.Handle())]
	if !exists || erc != rc {
		return errors.New("resource belongs to another TPM context")
	}
	return nil
}

// GetOrCreateResourceContext creates and returns a new ResourceContext for the specified handle, or returns the existing one if the
// TPMContext already has a reference to one. TPMContext will maintain a reference to the returned ResourceContext until it is flushed
// or evicted from the TPM or if the TPM indicates that it has created a new resource with the same handle - these stale
// ResourceContext instances may occur when working with persistent resources via a resource manager.
//
// If a new ResourceContext has to be created and the handle references a NV index or an object, it will execute a command to read the
// public area from the TPM in order to initialize state that is maintained on the host side. It will return a ResourceUnavailableError
// error if the specified handle references a NV index or object that is currently unavailable. If this function is called without any
// sessions, it does not benefit from any integrity protections other than a consistency cross-check that is performed on the returned
// data to make sure that the name and public area match. Applications should consider the implications of this during subsequent use
// of the ResourceContext. If any sessions are passed then the pubic area is read back from the TPM twice - the session is used only
// on the second read once the name is known. This second read provides an assurance that an entity with the name of the returned
// ResourceContext actually lives on the TPM.
//
// It always succeeds if the specified handle references a permanent resource.
//
// This function will panic if handle doesn't correspond to a PCR handle, permanent handle, NV index, transient object or persistent
// object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource,
// this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) GetOrCreateResourceContext(handle Handle, sessions ...*Session) (ResourceContext, error) {
	switch handle.Type() {
	case HandleTypePCR, HandleTypePermanent:
		return t.GetOrCreatePermanentContext(handle), nil
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(ResourceContext), nil
		}

		var rc ResourceContext = makeUntrackedContext(handle)
		var s []*Session
		for i := 0; i < 2; i++ {
			var err error
			if handle.Type() == HandleTypeNVIndex {
				rc, err = makeNVIndexContextFromTPM(t, rc, s...)
			} else {
				rc, err = makeObjectContextFromTPM(t, rc, s...)
			}

			if err != nil {
				switch e := err.(type) {
				case *TPMWarning:
					if e.Code == WarningReferenceH0 {
						return nil, ResourceUnavailableError{handle}
					}
				case *TPMHandleError:
					if e.Code() == ErrorHandle {
						return nil, ResourceUnavailableError{handle}
					}
				}
				return nil, err
			}
			t.addHandleContext(rc)

			if len(sessions) == 0 {
				break
			}
			s = sessions
		}

		return rc, nil
	default:
		panic("invalid handle type")
	}
}

// GetOrCreateSessionContext creates and returns a new SessionContext for the specified handle, or returns the existing one if the
// TPMContext already has a reference to one. TPMContext will maintain a reference to the returned SessionContext until it is flushed
// from the TPM or if the TPM indicates that it has created a new session with the same handle - these stale SessionContext instances
// may occur when working with sessions via a resource manager.
//
// If a new SessionContext has to be created, this command will execute some commands to determine if the session exists on the TPM,
// either as a saved or loaded session. If the session is saved then the returned SessionContext will return a Handle with a HandleType
// of HandleTypeHMACSession regardless of the HandleType of the supplied handle. Regardless of whether the session is saved or loaded,
// the returned SessionContext will not be complete and the session associated with it cannot be used in any command other than
// TPMContext.FlushContext. It will return a ResourceUnavailableError error if no session with the specified handle exists.
//
// This function will panic if handle doesn't correspond to a session.
func (t *TPMContext) GetOrCreateSessionContext(handle Handle) (SessionContext, error) {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(SessionContext), nil
		}
		rc, err := makeIncompleteSessionContext(t, handle)
		if err != nil {
			return nil, err
		}
		if rc == nil {
			return nil, ResourceUnavailableError{handle}
		}
		t.addHandleContext(rc)
		return rc, nil
	default:
		panic("invalid handle type")
	}
}

// GetOrCreatePermanentContext creates and returns a new ResourceContext for the specified permanent handle or PCR handle, or returns
// the existing one if the TPMContext already has a reference to one.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource,
// this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) GetOrCreatePermanentContext(handle Handle) ResourceContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
		if rc, exists := t.resources[normalizeHandleForMap(handle)]; exists {
			return rc.(ResourceContext)
		}

		rc := makePermanentContext(handle)
		t.addHandleContext(rc)
		return rc
	default:
		panic("invalid handle type")
	}
}

// OwnerHandleContext returns the ResouceContext corresponding to the owner hiearchy.
func (t *TPMContext) OwnerHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleOwner)
}

// NulHandleContext returns the ResourceContext corresponding to the null hiearchy.
func (t *TPMContext) NullHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleNull)
}

// LockoutHandleContext returns the ResourceContext corresponding to the lockout hiearchy.
func (t *TPMContext) LockoutHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleLockout)
}

// EndorsementHandleContext returns the ResourceContext corresponding to the endorsement hiearchy.
func (t *TPMContext) EndorsementHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandleEndorsement)
}

// PlatformHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandlePlatform)
}

// PlatformNVHandleContext returns the ResourceContext corresponding to the platform hiearchy.
func (t *TPMContext) PlatformNVHandleContext() ResourceContext {
	return t.GetOrCreatePermanentContext(HandlePlatformNV)
}

// PCRHandleContext returns the ResourceContext corresponding to the PCR at the specified index. It will panic if pcr is not a valid
// PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) ResourceContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetOrCreatePermanentContext(h)
}

// CreateHandleContextFromReader returns a new HandleContext created from the serialized data read from the supplied io.Reader. This
// will contain data that was previously created by HandleContext.SerializeToBytes or HandleContext.SerializeToWriter. TPMContext will
// maintain a reference to the returned HandleContext until it is flushed or evicted from the TPM or if the TPM indicates that it has
// created a new entity with the same handle - these stale HandleContext instances may occur when working with persistent resources or
// sessions via a resource manager. If the TPMContext contains a reference to another HandleContext with the same handle, then that
// HandleContext will become invalid.
//
// If the supplied data corresponds to a session then a SessionContext will be returned, else a ResourceContext will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the authorization value of the corresponding TPM
// resource, this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) CreateHandleContextFromReader(r io.Reader) (HandleContext, error) {
	var integrityAlg HashAlgorithmId
	var integrity []byte
	var b []byte
	if err := UnmarshalFromReader(r, &integrityAlg, &integrity, &b); err != nil {
		return nil, xerrors.Errorf("cannot unpack context blob and checksum: %w", err)
	}

	if !integrityAlg.Supported() {
		return nil, errors.New("invalid checksum algorithm")
	}
	h := integrityAlg.NewHash()
	h.Write(b)
	if !bytes.Equal(h.Sum(nil), integrity) {
		return nil, errors.New("invalid checksum")
	}

	var data *handleContextData
	n, err := UnmarshalFromBytes(b, &data)
	if err != nil {
		return nil, xerrors.Errorf("cannot unmarshal context data: %w", err)
	}
	if n < len(b) {
		return nil, errors.New("context blob contains trailing bytes")
	}

	if err := data.checkConsistency(); err != nil {
		return nil, err
	}

	var hc HandleContext
	switch data.Type {
	case handleContextTypePermanent:
		hc = &permanentContext{d: *data}
	case handleContextTypeObject:
		hc = &objectContext{d: *data}
	case handleContextTypeNvIndex:
		hc = &nvIndexContext{d: *data}
	case handleContextTypeSession:
		hc = &sessionContext{d: *data}
	default:
		panic("huh?")
	}

	t.addHandleContext(hc)
	return hc, nil
}

// CreateHandleContextFromBytes returns a new HandleContext created from the serialized data read from the supplied byte slice. This
// will contain data that was previously created by HandleContext.SerializeToBytes or HandleContext.SerializeToWriter. TPMContext will
// maintain a reference to the returned HandleContext until it is flushed or evicted from the TPM or if the TPM indicates that it has
// created a new entity with the same handle - these stale HandleContext instances may occur when working with persistent resources or
// sessions via a resource manager. If the TPMContext contains a reference to another HandleContext with the same handle, then that
// HandleContext will become invalid.
//
// If the supplied data corresponds to a session then a SessionContext will be returned, else a ResourceContext will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the authorization value of the corresponding TPM
// resource, this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) CreateHandleContextFromBytes(b []byte) (HandleContext, int, error) {
	buf := bytes.NewReader(b)
	rc, err := t.CreateHandleContextFromReader(buf)
	if err != nil {
		return nil, 0, err
	}
	return rc, len(b) - buf.Len(), nil
}

// ForgetHandleContext tells the TPMContext to drop its reference to the specified HandleContext without flushing the corresponding
// resources from the TPM.
//
// An error will be returned if the specified context has been invalidated, or if it is being tracked by another TPMContext instance.
//
// On succesful completion, the specified HandleContext will be invalidated and can no longer be used. APIs that return a
// HandleContext for the corresponding TPM resource in the future will return a newly created HandleContext.
func (t *TPMContext) ForgetHandleContext(context HandleContext) error {
	if err := t.checkHandleContextParam(context); err != nil {
		return makeInvalidParamError("context", fmt.Sprintf("%v", err))
	}

	t.evictHandleContext(context)
	return nil
}
