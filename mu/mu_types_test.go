// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu_test

import (
	"encoding/binary"
	"io"
	"math"
	"reflect"

	. "github.com/canonical/go-tpm2/mu"
)

type testSizedBuffer []byte

type testStruct struct {
	A uint16
	B *uint32
	C bool
	D []uint32
}

type testStructWithRawTagFields struct {
	A []uint16 `tpm2:"raw"`
	B []byte   `tpm2:"raw"`
}

type testStructWithSizedField struct {
	A uint32
	B *testStruct `tpm2:"sized"`
}

type testStructWithSizedField2 struct {
	A *testStructWithImplicitSizedField `tpm2:"sized"`
}

type testUnion struct {
	A *testStruct
	B []uint32
	C uint16
}

func (t *testUnion) Select(selector reflect.Value) interface{} {
	switch selector.Interface().(uint32) {
	case 1:
		return &t.A
	case 2:
		return &t.B
	case 3:
		return &t.C
	case 4:
		return NilUnionValue
	case math.MaxUint32:
		var a uint32
		return &a
	default:
		return nil
	}
}

type testTaggedUnion struct {
	Select uint32
	Union  *testUnion
}

type testTaggedUnion2 struct {
	Select uint32
	Union  *testUnion `tpm2:"selector:Select"`
}

type testTaggedUnion3 struct {
	Select uint32
	Union  testUnion
}

type testStructContainingCustom struct {
	A uint32
	X *testCustom
}

type testStructContainingCustom2 struct {
	A uint32
	X testCustom2
}

type testStructWithSized1Field struct {
	A uint16
	B []byte `tpm2:"sized1"`
}

type testStructContainingInvalidCustomField struct {
	A uint32
	X *testCustom `tpm2:"raw"`
}

type testStructContainingInvalidCustomField2 struct {
	A uint32
	X *testCustom `tpm2:"selector:A"`
}

type testStructContainingInvalidCustomField3 struct {
	A uint32
	X *testCustom `tpm2:"sized1"`
}

type testStructWithInvalidPrimitiveField struct {
	A uint32
	B uint16 `tpm2:"raw"`
}

type testStructWithInvalidPrimitiveField2 struct {
	A uint32
	B uint16 `tpm2:"sized"`
}

type testStructWithInvalidPrimitiveField3 struct {
	A uint32
	B uint16 `tpm2:"selector:A"`
}

type testStructWithInvalidPrimitiveField4 struct {
	A uint32
	B uint16 `tpm2:"sized1"`
}

type testStructWithInvalidSliceField struct {
	A uint16
	B []uint32 `tpm2:"sized"`
}

type testStructWithInvalidSliceField2 struct {
	A uint16
	B []uint32 `tpm2:"selector:A"`
}

type testStructWithInvalidSliceField3 struct {
	A uint16
	B Sized1Bytes `tpm2:"raw"`
}

type testStructWithInvalidSliceField4 struct {
	A uint16
	B []byte `tpm2:"raw,sized1"`
}

type testStructWithInvalidRawField struct {
	A testStruct `tpm2:"raw"`
}

type testStructWithInvalidSized1Field struct {
	A testStruct `tpm2:"sized1"`
}

type testStructWithRawTagSizedFields struct {
	A [][]byte `tpm2:"raw"`
}

type testInvalidTaggedUnion struct {
	Select uint32
	A      *testUnion `tpm2:"selector:foo"`
}

type testStructWithInvalidSizedField struct {
	A testStruct `tpm2:"sized"`
}

type testStructWithInvalidUnionField struct {
	A uint8
	B testStruct `tpm2:"selector:A"`
}

type testStructWithImplicitSizedField struct {
	A uint32
	B []byte
}

type testInvalidTaggedUnion2 struct {
	Selector uint32
	A        *testUnion
}

func (u *testInvalidTaggedUnion2) Select(selector reflect.Value) interface{} {
	return nil
}

type testStructContainingPanicCustom struct {
	A testPanicCustom
}

type testRecursiveStruct struct {
	A *testRecursiveStruct
}

type testRecursiveStruct2 struct {
	A []*testRecursiveStruct3
}

type testRecursiveStruct3 struct {
	A *testRecursiveStruct2
}

type testRecursiveStruct4 struct {
	A testRecursiveCustom
}

type testRecursiveCustom struct {
	A []*testRecursiveStruct4
}

type testStructWithIgnoredField struct {
	A uint16 `tpm2:"ignore"`
	B []uint16
}

type testCustom struct {
	A uint16
	B []uint32
}

func (t testCustom) Marshal(w io.Writer) error {
	var a [2]byte
	binary.LittleEndian.PutUint16(a[:], t.A)
//line foo.go:150
	_, err := MarshalToWriter(w, binary.BigEndian.Uint16(a[:]), t.B)
	return err
}

func (t *testCustom) Unmarshal(r io.Reader) error {
//line foo.go:200
	_, err := UnmarshalFromReader(r, &t.A, &t.B)
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], t.A)
	t.A = binary.LittleEndian.Uint16(a[:])
	return err
}

type testCustom2 struct {
	A uint16
	B []uint32
}

func (t *testCustom2) Marshal(w io.Writer) error {
	var a [2]byte
	binary.LittleEndian.PutUint16(a[:], t.A)
//line foo.go:350
	_, err := MarshalToWriter(w, binary.BigEndian.Uint16(a[:]), t.B)
	return err
}

func (t *testCustom2) Unmarshal(r io.Reader) error {
//line foo.go:400
	_, err := UnmarshalFromReader(r, &t.A, &t.B)
	var a [2]byte
	binary.BigEndian.PutUint16(a[:], t.A)
	t.A = binary.LittleEndian.Uint16(a[:])
	return err
}

type testPanicCustom struct{}

func (t testPanicCustom) Marshal(w io.Writer) error {
	panic("some error")
}

func (t *testPanicCustom) Unmarshal(r io.Reader) error {
	panic("some error")
}

type testPanicCustom2 struct {
	A testStructContainingPanicCustom
}

func (t testPanicCustom2) Marshal(w io.Writer) error {
//line foo.go:550
	_, err := MarshalToWriter(w, t.A)
	return err
}

func (t *testPanicCustom2) Unmarshal(r io.Reader) error {
//line foo.go:600
	_, err := UnmarshalFromReader(r, &t.A)
	return err
}

func (c testRecursiveCustom) Marshal(w io.Writer) error {
//line foo.go:750
	_, err := MarshalToWriter(w, c.A)
	return err
}

func (c *testRecursiveCustom) Unmarshal(r io.Reader) error {
//line foo.go:800
	_, err := UnmarshalFromReader(r, &c.A)
	return err
}
