/*
Package tpm2 implements an API for communicating with TPM 2.0 devices.

This documentation refers to TPM commands and types that are described in more detail in the TPM 2.0 Library Specification, which can
be found at https://trustedcomputinggroup.org/resource/tpm-library-specification/. Knowledge of this specification is assumed in this
documentation.

Communication with Linux TPM character devices and TPM simulators implementing the Microsoft TPM2 simulator interface is supported.
The core type by which consumers of this package communicate with a TPM is TPMContext.

Quick start

In order to create a new TPMContext that can be used to communicate with a Linux TPM character device:
 tcti, err := tpm2.OpenTPMDevice("/dev/tpm0")
 if err != nil {
	 return err
 }
 tpm, _ := tpm2.NewTPMContext(tcti)

In order to create and persist a new storage primary key:
 tcti, err := tpm2.OpenTPMDevice("/dev/tpm0")
 if err != nil {
	return err
 }
 tpm, _ := tpm2.NewTPMContext(tcti)

 template = tpm2.Public{
	Type:    tpm2.ObjectTypeRSA,
	NameAlg: tpm2.HashAlgorithmSHA256,
	Attrs: tpm2.AttrFixedTPM | tpm2.AttrFixedParent | tpm2.AttrSensitiveDataOrigin | tpm2.AttrUserWithAuth | tpm2.AttrNoDA | tpm2.AttrRestricted | tpm2.AttrDecrypt,
	Params: tpm2.PublicParamsU{
		Data: &tpm2.RSAParams{
			Symmetric: tpm2.SymDefObject{
				Algorithm: tpm2.SymObjectAlgorithmAES,
				KeyBits:   tpm2.SymKeyBitsU{Data: uint16(128)},
				Mode:      tpm2.SymModeU{Data: tpm2.SymModeCFB}},
			Scheme:   tpm2.RSAScheme{Scheme: tpm2.RSASchemeNull},
			KeyBits:  2048,
			Exponent: 0}},
	Unique: tpm2.PublicIDU{Data: make(tpm2.PublicKeyRSA, 256)}}
 context, _, _, _, _, err := tpm.CreatePrimary(tpm.OwnerHandleContext(), nil, &template, nil, nil, nil)
 if err != nil {
	return err
 }

 persistentContext, err := tpm.EvictControl(tpm.OwnerHandleContext(), context, tpm2.Handle(0x81000001), nil)
 if err != nil {
	return err
 }
 // persistentContext is a ResourceContext corresponding to the new persistent storage primary key.

In order to evict a persistent object:
 tcti, err := tpm2.OpenTPMDevice("/dev/tpm0")
 if err != nil {
	return err
 }
 tpm, _ := tpm2.NewTPMContext(tcti)

 context, err := tpm.GetOrCreateResourceContext(tpm2.Handle(0x81000001))
 if err != nil {
	 return err
 }

 if _, err := tpm.EvictControl(tpm.OwnerHandleContext(), context, context.Handle(), nil); err != nil {
	 return err
 }
 // The resource associated with context is now unavailable.

Parameter marshalling and unmarshalling

This package marshals go types to and from the TPM wire format, according to the following rules:
 * UINT8 <-> uint8
 * BYTE <-> byte
 * INT8 <-> int8
 * BOOL <-> bool
 * UINT16 <-> uint16
 * INT16 <-> int16
 * UINT32 <-> uint32
 * INT32 <-> int32
 * UINT64 <-> uint64
 * INT64 <-> int64
 * TPM2B prefixed types (sized buffers with a 2-byte size field) fall in to 2 categories:
    * Byte buffer <-> []byte, or any type with an identical underlying type.
    * Sized structure <-> struct referenced via a pointer field in an enclosing struct, where the field has the `tpm2:"sized"` tag. A
    zero sized struct is represented as a nil pointer.
 * TPMA prefixed types (attributes) <-> whichever go type corresponds to the underlying TPM type (UINT8, UINT16, or UINT32).
 * TPM_ALG_ID (algorithm enum) <-> AlgorithmId
 * TPML prefixed types (lists with a 4-byte length field) <-> slice of whichever go type corresponds to the underlying TPM type.
 * TPMS prefixed types (structures) <-> struct
 * TPMT prefixed types (structures with a tag field used as a union selector) <-> struct
 * TPMU prefixed types (unions) <-> struct with a single field and which implements the Union interface. These must be referenced
 from a field in an enclosing struct, where the field has the `tpm2:"selector:<field_name>"` tag referencing a valid selector
 field name in the enclosing struct.

TPMI prefixed types (interface types) are generally not explicitly supported. These are used by the TPM for type checking during
unmarshalling. Some TPMI prefixed types that use TPM_ALG_ID as the underlying concrete type are implemented.

Pointer types are automatically dereferenced.

The marshalling code parses the "tpm2" tag on struct fields, the value of which is a comma separated list of options. These options are:
 * selector:<field_name> - used when the field is a struct that implements the Union interface. <field_name> references the name of
 another field in the struct, the value of which is used as the selector for the union type.
 * sized - used when the field is a struct, to indicate that it should be marshalled and unmarshalled as a sized struct. The field
 must be a pointer to a struct, and a nil pointer indicates a zero-sized struct.
 * raw - used when the field is a slice, to indicate that it should be marshalled and unmarshalled without a length (if it
 represents a list) or size (if it represents a sized buffer) field. The slice must be pre-allocated to the correct length by the
 caller during unmarshalling.

Authorization types

Some TPM resources require authorization in order to use them in some commands. There are 3 main types of authorization supported by
this package:
 * Cleartext password: A cleartext authorization value is sent to the TPM by calling ResourceContext.SetAuthValue and supplying the
 ResourceContext to a function requiring authorization. Authorization succeeds if the correct value is sent.

 * HMAC session: Knowledge of an authorization value is demonstrated by calling ResourceContext.SetAuthValue and supplying the ResourceContext
 to a function requiring authorization, along with a session with the type SessionTypeHMAC. Authorization succeeds if the computed HMAC
 matches that expected by the TPM.

 * Policy session: A ResourceContext is supplied to a function requiring authorization along with a session with the type
 SessionTypePolicy, containing a record of and the result of a sequence of assertions. Authorization succeeds if the conditions
 required by the resource's authorization policy are satisfied.

The type of authorizations permitted for a resource is dependent on the authorization role (user, admin or duplication), the type of
resource and the resource's attributes.
*/
package tpm2
