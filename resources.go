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

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

// HandleContext corresponds to an entity that resides on the TPM. Implementations of HandleContext maintain some host-side
// state in order to be able to participate in HMAC sessions. They are invalidated when used in a command that results in the
// entity being flushed or evicted from the TPM. Once invalidated, they can no longer be used.
type HandleContext interface {
	// Handle returns the handle of the corresponding entity on the TPM. If the HandleContext has been invalidated then this will
	// return HandleUnassigned.
	Handle() Handle
	Name() Name                        // The name of the entity
	SerializeToBytes() []byte          // Return a byte slice containing the serialized form of this HandleContext
	SerializeToWriter(io.Writer) error // Write the serialized form of this HandleContext to the supplied io.Writer
}

type handleContextPrivate interface {
	invalidate()
	data() *handleContextData
}

// SessionAttributes is a set of flags that specify the usage and behaviour of a session.
type SessionAttributes int

const (
	// AttrContinueSession specifies that the session should not be flushed from the TPM after it is used. If a session is used without
	// this flag, it will be flushed from the TPM after the command completes. In this case, the HandleContext associated with the
	// session will be invalidated.
	AttrContinueSession SessionAttributes = 1 << iota

	// AttrAuditExclusive indicates that the session should be used for auditing and that the command should only be executed if the
	// session is exclusive at the start of the command. A session becomes exclusive when it is used for auditing for the first time,
	// or if the AttrAuditReset attribute is provided. A session will remain exclusive until the TPM executes any command where the
	// exclusive session isn't used for auditing, if that command allows for audit sessions to be provided.
	AttrAuditExclusive

	// AttrAuditReset indicates that the session should be used for auditing and that the audit digest of the session should be reset.
	// The session will subsequently become exclusive. A session will remain exclusive until the TPM executes any command where the
	// exclusive session isn't used for auditing, if that command allows for audit sessions to be provided.
	AttrAuditReset

	// AttrCommandEncrypt specifies that the session should be used for encryption of the first command parameter before being sent
	// from the host to the TPM. This can only be used for parameters that have types corresponding to TPM2B prefixed TCG types,
	// and requires a session that was configured with a valid symmetric algorithm via the symmetric argument of
	// TPMContext.StartAuthSession.
	AttrCommandEncrypt

	// AttrResponseEncrypt specifies that the session should be used for encryption of the first response parameter before being sent
	// from the TPM to the host. This can only be used for parameters that have types corresponding to TPM2B prefixed TCG types, and
	// requires a session that was configured with a valid symmetric algorithm via the symmetric argument of TPMContext.StartAuthSession.
	// This package automatically decrypts the received encrypted response parameter.
	AttrResponseEncrypt

	// AttrAudit indicates that the session should be used for auditing. If this is the first time that the session is used for auditing,
	// then this attribute will result in the session becoming exclusive. A session will remain exclusive until the TPM executes any
	// command where the exclusive session isn't used for auditing, if that command allows for audit sessions to be provided.
	AttrAudit
)

// SessionContext is a HandleContext that corresponds to a session on the TPM.
type SessionContext interface {
	HandleContext
	NonceTPM() Nonce   // The most recent TPM nonce value
	IsAudit() bool     // Whether the session has been used for audit
	IsExclusive() bool // Whether the most recent response from the TPM indicated that the session is exclusive for audit purposes

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
	handleContextTypeDummy handleContextType = iota
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

func (d handleContextDataU) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(handleContextType) {
	case handleContextTypeDummy, handleContextTypePermanent:
		return reflect.TypeOf(mu.NilUnionValue)
	case handleContextTypeObject:
		return reflect.TypeOf((*Public)(nil))
	case handleContextTypeNvIndex:
		return reflect.TypeOf((*NVPublic)(nil))
	case handleContextTypeSession:
		return reflect.TypeOf((*sessionContextData)(nil))
	default:
		return nil
	}
}

type handleContextData struct {
	Type   handleContextType
	Handle Handle
	Name   Name
	Data   handleContextDataU `tpm2:"selector:Type"`
}

func (d *handleContextData) serializeToBytes() []byte {
	data, err := mu.MarshalToBytes(d)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal context data: %v", err))
	}
	h := crypto.SHA256.New()
	h.Write(data)
	data, err = mu.MarshalToBytes(HashAlgorithmSHA256, h.Sum(nil), data)
	if err != nil {
		panic(fmt.Sprintf("cannot pack context blob and checksum: %v", err))
	}
	return data
}

func (d *handleContextData) serializeToWriter(w io.Writer) error {
	data, err := mu.MarshalToBytes(d)
	if err != nil {
		panic(fmt.Sprintf("cannot marshal context data: %v", err))
	}
	h := crypto.SHA256.New()
	h.Write(data)
	_, err = mu.MarshalToWriter(w, HashAlgorithmSHA256, h.Sum(nil), data)
	return err
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

type dummyContext struct {
	d handleContextData
}

func (r *dummyContext) Handle() Handle {
	return r.d.Handle
}

func (r *dummyContext) Name() Name {
	return r.d.Name
}

func (r *dummyContext) SerializeToBytes() []byte {
	return nil
}

func (r *dummyContext) SerializeToWriter(io.Writer) error {
	return nil
}

func (r *dummyContext) SetAuthValue([]byte) {
}

func (r *dummyContext) invalidate() {}

func (r *dummyContext) data() *handleContextData {
	return &r.d
}

func makeDummyContext(handle Handle) *dummyContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &dummyContext{d: handleContextData{Type: handleContextTypeDummy, Handle: handle, Name: name}}
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

func (r *permanentContext) invalidate() {}

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

func (t *TPMContext) makeObjectContextFromTPM(context ResourceContext, sessions ...SessionContext) (ResourceContext, error) {
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

func makeNVIndexContext(name Name, public *NVPublic) *nvIndexContext {
	return &nvIndexContext{d: handleContextData{Type: handleContextTypeNvIndex, Handle: public.Index, Name: name, Data: handleContextDataU{public}}}
}

func (t *TPMContext) makeNVIndexContextFromTPM(context ResourceContext, sessions ...SessionContext) (ResourceContext, error) {
	pub, name, err := t.NVReadPublic(context, sessions...)
	if err != nil {
		return nil, err
	}
	if n, err := pub.Name(); err != nil {
		return nil, &InvalidResponseError{CommandNVReadPublic, fmt.Sprintf("cannot compute name of returned public area: %v", err)}
	} else if !bytes.Equal(n, name) {
		return nil, &InvalidResponseError{CommandNVReadPublic, "name and public area don't match"}
	}
	if pub.Index != context.Handle() {
		return nil, &InvalidResponseError{CommandNVReadPublic, "unexpected index in public area"}
	}
	return makeNVIndexContext(name, pub), nil
}

type sessionContext struct {
	d     *handleContextData
	attrs SessionAttributes
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

func (r *sessionContext) SetAttrs(attrs SessionAttributes) {
	r.attrs = attrs
}

func (r *sessionContext) WithAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{d: r.d, attrs: attrs}
}

func (r *sessionContext) IncludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{d: r.d, attrs: r.attrs | attrs}
}

func (r *sessionContext) ExcludeAttrs(attrs SessionAttributes) SessionContext {
	return &sessionContext{d: r.d, attrs: r.attrs &^ attrs}
}

func (r *sessionContext) invalidate() {
	r.d.Handle = HandleUnassigned
	r.d.Name = make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(r.d.Name, uint32(r.d.Handle))
}

func (r *sessionContext) data() *handleContextData {
	return r.d
}

func (r *sessionContext) scData() *sessionContextData {
	return r.d.Data.Data.(*sessionContextData)
}

func (r *sessionContext) tpmAttrs() sessionAttrs {
	var attrs sessionAttrs
	if r.attrs&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	if r.attrs&AttrAuditExclusive > 0 {
		attrs |= (attrAuditExclusive | attrAudit)
	}
	if r.attrs&AttrAuditReset > 0 {
		attrs |= (attrAuditReset | attrAudit)
	}
	if r.attrs&AttrCommandEncrypt > 0 {
		attrs |= attrDecrypt
	}
	if r.attrs&AttrResponseEncrypt > 0 {
		attrs |= attrEncrypt
	}
	if r.attrs&AttrAudit > 0 {
		attrs |= attrAudit
	}
	return attrs
}

func makeSessionContext(handle Handle, data *sessionContextData) *sessionContext {
	name := make(Name, binary.Size(Handle(0)))
	binary.BigEndian.PutUint32(name, uint32(handle))
	return &sessionContext{d: &handleContextData{Type: handleContextTypeSession, Handle: handle, Name: name, Data: handleContextDataU{data}}}
}

// CreateResourceContextFromTPM creates and returns a new ResourceContext for the specified handle. It will execute a command to read
// the public area from the TPM in order to initialize state that is maintained on the host side. A ResourceUnavailableError error
// will be returned if the specified handle references a resource that is currently unavailable. If this function is called without any
// sessions, it does not benefit from any integrity protections other than a consistency cross-check that is performed on the returned
// data to make sure that the name and public area match. Applications should consider the implications of this during subsequent use
// of the ResourceContext. If any sessions are passed then the pubic area is read back from the TPM twice - the session is used only
// on the second read once the name is known. This second read provides an assurance that an entity with the name of the returned
// ResourceContext actually lives on the TPM.
//
// This function will panic if handle doesn't correspond to a NV index, transient object or persistent object.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource,
// this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) CreateResourceContextFromTPM(handle Handle, sessions ...SessionContext) (ResourceContext, error) {
	switch handle.Type() {
	case HandleTypeNVIndex, HandleTypeTransient, HandleTypePersistent:
	default:
		panic("invalid handle type")
	}

	var rc ResourceContext = makeDummyContext(handle)
	var s []SessionContext
	for i := 0; i < 2; i++ {
		var err error
		if handle.Type() == HandleTypeNVIndex {
			rc, err = t.makeNVIndexContextFromTPM(rc, s...)
		} else {
			rc, err = t.makeObjectContextFromTPM(rc, s...)
		}

		switch {
		case IsTPMWarning(err, WarningReferenceH0, AnyCommandCode):
			return nil, ResourceUnavailableError{handle}
		case IsTPMHandleError(err, ErrorHandle, AnyCommandCode, AnyHandleIndex):
			return nil, ResourceUnavailableError{handle}
		case err != nil:
			return nil, err
		}

		if len(sessions) == 0 {
			break
		}
		s = sessions
	}

	return rc, nil
}

// CreateIncompleteSessionContext creates and returns a new SessionContext for the specified handle. The returned SessionContext will
// not be complete and the session associated with it cannot be used in any command other than TPMContext.FlushContext.
//
// This function will panic if handle doesn't correspond to a session.
func CreateIncompleteSessionContext(handle Handle) SessionContext {
	switch handle.Type() {
	case HandleTypeHMACSession, HandleTypePolicySession:
		return makeSessionContext(handle, nil)
	default:
		panic("invalid handle type")
	}
}

// GetPermanentContext returns a ResourceContext for the specified permanent handle or PCR handle.
//
// This function will panic if handle does not correspond to a permanent or PCR handle.
//
// If subsequent use of the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource,
// this should be provided by calling ResourceContext.SetAuthValue.
func (t *TPMContext) GetPermanentContext(handle Handle) ResourceContext {
	switch handle.Type() {
	case HandleTypePermanent, HandleTypePCR:
		if rc, exists := t.permanentResources[handle]; exists {
			return rc
		}

		rc := makePermanentContext(handle)
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

// PCRHandleContext returns the ResourceContext corresponding to the PCR at the specified index. It will panic if pcr is not a valid
// PCR index.
func (t *TPMContext) PCRHandleContext(pcr int) ResourceContext {
	h := Handle(pcr)
	if h.Type() != HandleTypePCR {
		panic("invalid PCR index")
	}
	return t.GetPermanentContext(h)
}

// CreateHandleContextFromReader returns a new HandleContext created from the serialized data read from the supplied io.Reader. This
// should contain data that was previously created by HandleContext.SerializeToBytes or HandleContext.SerializeToWriter.
//
// If the supplied data corresponds to a session then a SessionContext will be returned, else a ResourceContext will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the authorization value of the corresponding TPM
// resource, this should be provided by calling ResourceContext.SetAuthValue.
func CreateHandleContextFromReader(r io.Reader) (HandleContext, error) {
	var integrityAlg HashAlgorithmId
	var integrity []byte
	var b []byte
	if _, err := mu.UnmarshalFromReader(r, &integrityAlg, &integrity, &b); err != nil {
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
	n, err := mu.UnmarshalFromBytes(b, &data)
	if err != nil {
		return nil, xerrors.Errorf("cannot unmarshal context data: %w", err)
	}
	if n < len(b) {
		return nil, errors.New("context blob contains trailing bytes")
	}

	if data.Type == handleContextTypePermanent {
		return nil, errors.New("cannot create a permanent context from serialized data")
	}

	if err := data.checkConsistency(); err != nil {
		return nil, err
	}

	var hc HandleContext
	switch data.Type {
	case handleContextTypeObject:
		hc = &objectContext{d: *data}
	case handleContextTypeNvIndex:
		hc = &nvIndexContext{d: *data}
	case handleContextTypeSession:
		hc = &sessionContext{d: data}
	default:
		panic("not reached")
	}

	return hc, nil
}

// CreateHandleContextFromBytes returns a new HandleContext created from the serialized data read from the supplied byte slice. This
// should contain data that was previously created by HandleContext.SerializeToBytes or HandleContext.SerializeToWriter.
//
// If the supplied data corresponds to a session then a SessionContext will be returned, else a ResourceContext will be returned.
//
// If a ResourceContext is returned and subsequent use of it requires knowledge of the authorization value of the corresponding TPM
// resource, this should be provided by calling ResourceContext.SetAuthValue.
func CreateHandleContextFromBytes(b []byte) (HandleContext, int, error) {
	buf := bytes.NewReader(b)
	rc, err := CreateHandleContextFromReader(buf)
	if err != nil {
		return nil, 0, err
	}
	return rc, len(b) - buf.Len(), nil
}

// CreateNVIndexResourceContextFromPublic returns a new ResourceContext created from the provided public area. If subsequent use of
// the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource, this should be
// provided by calling ResourceContext.SetAuthValue.
func CreateNVIndexResourceContextFromPublic(pub *NVPublic) (ResourceContext, error) {
	name, err := pub.Name()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name from public area: %v", err)
	}
	rc := makeNVIndexContext(name, pub)
	if err := rc.d.checkConsistency(); err != nil {
		return nil, err
	}
	return rc, nil
}

// CreateObjectResourceContextFromPublic returns a new ResourceContext created from the provided public area. If subsequent use of
// the returned ResourceContext requires knowledge of the authorization value of the corresponding TPM resource, this should be
// provided by calling ResourceContext.SetAuthValue.
func CreateObjectResourceContextFromPublic(handle Handle, pub *Public) (ResourceContext, error) {
	name, err := pub.Name()
	if err != nil {
		return nil, fmt.Errorf("cannot compute name from public area: %v", err)
	}
	rc := makeObjectContext(handle, name, pub)
	if err := rc.d.checkConsistency(); err != nil {
		return nil, err
	}
	return rc, nil
}
