/*
Package tpm2 implements an API for communicating with TPM 2.0 devices.

This documentation refers to TPM commands and types that are described in more detail in the TPM 2.0 Library
Specification, which can be found at https://trustedcomputinggroup.org/resource/tpm-library-specification/.
Knowledge of this specification is assumed in this documentation.

Communication with Linux TPM character devices and TPM simulators implementing the Microsoft TPM2 simulator
interface is supported. The core type by which consumers of this package communicate with a TPM is TPMContext.

Quick start

In order to create a new TPMContext that can be used to communicate with a Linux TPM character device:
 tcti, err := tpm2.OpenTPMDevice("/dev/tpm0")
 if err != nil {
	 return err
 }
 tpm, _ := tpm2.NewTPMContext(tcti)

Parameter marshalling and unmarshalling

This package marshals go types to and from the TPM wire format, according to the following rules:
    * UINT8 <-> uint8
    * BYTE <-> byte
    * INT8 <-> int8
    * BOOL <-> bool
    * UINT16 <-> uint16
    * INT16 <-> int16
    * UINT32 <-> int32
    * INT32 <-> int32
    * UINT64 <-> uint64
    * INT64 <-> int64
    * TPM2B prefixed types (sized buffers with a 2-byte size field) fall in to 2 categories:
	* Byte buffer <-> []byte, or any type with an identical underlying type.
	* Sized structure <-> struct referenced via a pointer field in an enclosing struct, where the field has the
	`tpm2:"sized"` tag. A zero sized struct is represented as a nil pointer.
    * TPMA prefixed types (attributes) <-> whichever go type corresponds to the underlying TPM type (UINT8, UINT16,
    or UINT32).
    * TPM_ALG_ID (algorithm enum) <-> AlgorithmId
    * TPML prefixed types (lists with a 4-byte length field) <-> slice of whichever go type corresponds to the
    underlying TPM type.
    * TPMS prefixed types (structures) <-> struct
    * TPMT prefixed types (structures with a tag field used as a union selector) <-> struct
    * TPMU prefixed types (unions) <-> struct with a single field and which implements the Union interface. These
    must be referenced from a field in an encosing struct, where the field has the `tpm2:"selector:<field_name>"`
    tag referencing a valid selector field name in the enclosing struct.

TPMI prefixed types (interface types) are not explicitly supported. These are just used for type checking during
unmarshalling.

Pointer types are automatically dereferenced.

The marshalling code parses the "tpm2" tag on struct fields, the value of which is a comma separated list of
options. These options are:
    * selector:<field_name> - used when the field is a struct that implements the Union interface. <field_name>
    references the name of another field in the struct, the value of which is used as the selector for the union
    type.
    * sized - used when the field is a struct, to indicate that it should be marshalled and unmarshalled as a
    sized struct. The field must be a pointer to a struct, and a nil pointer indicates a zero-sized struct.
    * raw - used when the field is a slice, to indicate that it should be marshalled and unmarshalled without
    a length (if it represents a list) or size (if it represents a sized buffer) field. The slice must be
    pre-allocated to the correct length by the caller during unmarshalling.
*/
package tpm2