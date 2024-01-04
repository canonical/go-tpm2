// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu_test

import (
	"encoding/binary"
	"io"

	"github.com/canonical/go-tpm2/internal/union"
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

type empty struct{}

var emptyValue empty

type testUnion struct {
	contents union.Contents
}

func newTestUnion[T *testStruct | []uint32 | uint16 | empty](contents T) *testUnion {
	return &testUnion{contents: union.NewContents(contents)}
}

func (t *testUnion) A() *testStruct {
	return union.ContentsElem[*testStruct](t.contents)
}

func (t *testUnion) B() []uint32 {
	return union.ContentsElem[[]uint32](t.contents)
}

func (t *testUnion) C() uint16 {
	return union.ContentsElem[uint16](t.contents)
}

func (t testUnion) SelectMarshal(selector any) (value any) {
	switch selector.(uint32) {
	case 1:
		return union.ContentsMarshal[*testStruct](t.contents)
	case 2:
		return union.ContentsMarshal[[]uint32](t.contents)
	case 3:
		return union.ContentsMarshal[uint16](t.contents)
	case 4:
		return union.ContentsMarshal[empty](t.contents)
	default:
		return nil
	}
}

func (t *testUnion) SelectUnmarshal(selector any) any {
	switch selector.(uint32) {
	case 1:
		return union.ContentsUnmarshal[*testStruct](&t.contents)
	case 2:
		return union.ContentsUnmarshal[[]uint32](&t.contents)
	case 3:
		return union.ContentsUnmarshal[uint16](&t.contents)
	case 4:
		return union.ContentsUnmarshal[empty](&t.contents)
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

type testStructWithInvalidArrayField struct {
	A [10]byte `tpm2:"sized"`
}

type testStructWithInvalidArrayField2 struct {
	A [10]byte `tpm2:"raw"`
}

type testStructWithInvalidArrayField3 struct {
	A [10]byte `tpm2:"sized1"`
}

type testStructWithInvalidArrayField4 struct {
	A uint16
	B [10]byte `tpm2:"selector:A"`
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

func (u testInvalidTaggedUnion2) SelectMarshal(selector any) any {
	return nil
}

func (u *testInvalidTaggedUnion2) SelectUnmarshal(selector any) any {
	return nil
}

type testStructContainingPanicCustom struct {
	A testPanicCustom
}

type testRecursiveStruct struct {
	A *testRecursiveStruct
}

type testRecursiveStruct2 struct {
	A *testRecursiveStruct3
}

type testRecursiveStruct3 struct {
	A *testRecursiveStruct2
}

type testRecursiveStruct4 struct {
	A *testRecursiveCustom
}

type testRecursiveCustom struct {
	A *testRecursiveStruct4
}

type testNonRecursiveStruct struct {
	A *testNonRecursiveStruct `tpm2:"sized"`
}

type testNonRecursiveStruct2 struct {
	A *testNonRecursiveStruct3
}

type testNonRecursiveStruct3 struct {
	A []*testNonRecursiveStruct2
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
