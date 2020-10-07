/*
Package mu provides helpers to marshalling to and unmarshalling from the TPM wire format.

Go types are marshalled to and from the TPM wire format according to the following rules:
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
 * TPM_ALG_ID (algorithm enum) <-> tpm2.AlgorithmId
 * TPML prefixed types (lists with a 4-byte length field) <-> slice of whichever go type corresponds to the underlying TPM type.
 * TPMS prefixed types (structures) <-> struct
 * TPMT prefixed types (structures with a tag field used as a union selector) <-> struct
 * TPMU prefixed types (unions) <-> struct which implements the Union interface. These must be referenced from a field in an
  enclosing struct, where the field has the `tpm2:"selector:<field_name>"` tag referencing a valid selector field name in the
  enclosing struct.

TPMI prefixed types (interface types) are generally not explicitly supported. These are used by the TPM for type checking during
unmarshalling. Some TPMI prefixed types that use TPM_ALG_ID as the underlying concrete type are implemented.

Pointer types are automatically dereferenced. Nil pointers are dereference to their zero value during marshalling.

The marshalling code parses the "tpm2" tag on struct fields, the value of which is a comma separated list of options. These options are:
 * selector:<field_name> - used when the field is a struct that implements the Union interface. <field_name> references the name of
 another field in the struct, the value of which is used as the selector for the union type.
 * sized - used when the field is a struct, to indicate that it should be marshalled and unmarshalled as a sized struct. The field
 must be a pointer to a struct, and a nil pointer indicates a zero-sized struct.
 * raw - used when the field is a slice, to indicate that it should be marshalled and unmarshalled without a length (if it
 represents a list) or size (if it represents a sized buffer) field. The slice must be pre-allocated to the correct length by the
 caller during unmarshalling.
*/
package mu
