// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"testing"
)

func TestMarshalBasic(t *testing.T) {
	var a uint16 = 1156
	var b bool = true
	var c uint32 = 45623564
	var d bool = false
	e := &a

	out, err := MarshalToBytes(a, b, c, d, e)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x04, 0x84, 0x01, 0x02, 0xb8, 0x29, 0x0c, 0x00, 0x04, 0x84}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao uint16
	var bo bool
	var co uint32
	var do bool
	var eo uint16

	n, err := UnmarshalFromBytes(out, &ao, &bo, &co, &do, &eo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if a != ao || b != bo || c != co || d != do || *e != eo {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestUnmarshalValue(t *testing.T) {
	var a uint32
	_, err := UnmarshalFromBytes([]byte{0xff, 0xff, 0xff, 0xff}, a)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes shouldn't be able to unmarshal to a non-pointer type")
	}
	if err.Error() != "cannot unmarshal to non-pointer type uint32" {
		t.Errorf("UnmarshalFromBytes returned unexpected error: %v", err)
	}
}

func TestMarshalRawSlice(t *testing.T) {
	a := []uint16{56, 453, 3233}
	out, err := MarshalToBytes(RawSlice(a))
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x00, 0x38, 0x01, 0xc5, 0x0c, 0xa1}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	ao := make([]uint16, 3)

	n, err := UnmarshalFromBytes(out, RawSlice(ao))
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestSizedBuffer []byte

func TestMarshalSizedBuffer(t *testing.T) {
	a := TestSizedBuffer{0x2f, 0x74, 0x68, 0x3f, 0x15, 0x43, 0x1d, 0x01, 0xea, 0x28, 0xad, 0xe2, 0x6c,
		0x4d, 0x00, 0x9b}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x10, 0x2f, 0x74, 0x68, 0x3f, 0x15, 0x43, 0x1d, 0x01, 0xea, 0x28,
		0xad, 0xe2, 0x6c, 0x4d, 0x00, 0x9b}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestSizedBuffer

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestListUint32 []uint32

func TestMarshalList(t *testing.T) {
	a := TestListUint32{46, 4563421, 678, 12390}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x45, 0xa1, 0xdd, 0x00,
		0x00, 0x02, 0xa6, 0x00, 0x00, 0x30, 0x66}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestListUint32

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestStructSimple struct {
	A uint16
	B uint32
	C bool
	D TestListUint32
}

func TestMarshalStruct(t *testing.T) {
	a := TestStructSimple{56324, 657763432, true, TestListUint32{4232, 567785}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0xdc, 0x04, 0x27, 0x34, 0xac, 0x68, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
		0x10, 0x88, 0x00, 0x08, 0xa9, 0xe9}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructSimple

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestStructWithEmbeddedStructs struct {
	A bool
	B uint16
	C TestStructSimple
	D *TestStructSimple
}

func TestMarshalStructWithEmbeddedStructs(t *testing.T) {
	a := TestStructWithEmbeddedStructs{
		A: false,
		B: 7644,
		C: TestStructSimple{
			A: 543,
			B: 44322323,
			C: false,
			D: TestListUint32{43221, 565675}},
		D: &TestStructSimple{
			A: 8903,
			B: 3321211,
			C: true,
			D: TestListUint32{22143432}}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x1d, 0xdc, 0x02, 0x1f, 0x02, 0xa4, 0x4e, 0x13, 0x00, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x00, 0xa8, 0xd5, 0x00, 0x08, 0xa1, 0xab, 0x22, 0xc7, 0x00, 0x32, 0xad, 0x7b, 0x01,
		0x00, 0x00, 0x00, 0x01, 0x01, 0x51, 0xe1, 0xc8}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructWithEmbeddedStructs

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestSizedStruct struct {
	A uint32
	B TestListUint32
}

type testSizedStructSized struct {
	Ptr *TestSizedStruct `tpm2:"sized"`
}

func TestMarshalSizedStructParam(t *testing.T) {
	a := TestSizedStruct{A: 754122, B: TestListUint32{22189, 854543, 445888654}}
	out, err := MarshalToBytes(testSizedStructSized{&a})
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x14, 0x00, 0x0b, 0x81, 0xca, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x56,
		0xad, 0x00, 0x0d, 0x0a, 0x0f, 0x1a, 0x93, 0xb8, 0x8e}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao testSizedStructSized

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, *(ao.Ptr)) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestMarshalNilSizedStructParam(t *testing.T) {
	out, err := MarshalToBytes(testSizedStructSized{})
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var o testSizedStructSized
	n, err := UnmarshalFromBytes(out, &o)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if o.Ptr != nil {
		t.Errorf("UnmarsalFromBytes should have returned a nil pointer")
	}
}

type TestStructWithNonPointerSizedStruct struct {
	S TestSizedStruct `tpm2:"sized"`
}

func TestMarshalSizedStructAsValue(t *testing.T) {
	a := TestStructWithNonPointerSizedStruct{}
	_, err := MarshalToBytes(a)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal a non-pointer sized struct")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestStructWithNonPointerSizedStruct: cannot marshal "+
		"field S: cannot marshal struct type tpm2.TestSizedStruct: sized struct inside container type "+
		"tpm2.TestStructWithNonPointerSizedStruct is not referenced via a pointer" {
		t.Errorf("UnmarshalFromBytes returned unexpected error: %v", err)
	}
}

type TestStructWithPointerSizedStruct struct {
	A uint32
	S *TestSizedStruct `tpm2:"sized"`
}

func TestMarshalSizedStructFromPointer(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestStructWithPointerSizedStruct
		out  []byte
	}{
		{
			desc: "Normal",
			in: TestStructWithPointerSizedStruct{
				A: 5665443,
				S: &TestSizedStruct{A: 754122, B: TestListUint32{22189, 854543, 445888654}}},
			out: []byte{0x00, 0x56, 0x72, 0xa3, 0x00, 0x14, 0x00, 0x0b, 0x81, 0xca, 0x00, 0x00,
				0x00, 0x03, 0x00, 0x00, 0x56, 0xad, 0x00, 0x0d, 0x0a, 0x0f, 0x1a, 0x93, 0xb8,
				0x8e},
		},
		{
			desc: "NilPointer",
			in:   TestStructWithPointerSizedStruct{A: 67764232},
			out:  []byte{0x04, 0x0a, 0x00, 0x08, 0x00, 0x00},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
			}

			var a TestStructWithPointerSizedStruct

			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

func TestMarshalNilPointer(t *testing.T) {
	a := TestStructWithEmbeddedStructs{A: true, B: 55422, C: TestStructSimple{}}
	_, err := MarshalToBytes(a)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal a nil pointer to a non sized struct")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestStructWithEmbeddedStructs: cannot marshal "+
		"field D: cannot marshal pointer type *tpm2.TestStructSimple: nil pointer" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

type TestUnion struct {
	A *TestStructSimple
	B TestListUint32
	C uint16
}

func (t TestUnion) Select(selector interface{}) (string, error) {
	switch selector.(uint32) {
	case 1:
		return "A", nil
	case 2:
		return "B", nil
	case 3:
		return "C", nil
	case 4:
		return "", nil
	}
	return "", invalidSelectorError{selector}
}

type TestUnionContainer struct {
	Select uint32
	Union  TestUnion `tpm2:"selector:Select"`
}

func TestMarshalUnion(t *testing.T) {
	for _, data := range []struct {
		desc string
		in   TestUnionContainer
		out  []byte
	}{
		{
			desc: "1",
			in: TestUnionContainer{
				Select: 1,
				Union: TestUnion{A: &TestStructSimple{56324, 657763432, true,
					TestListUint32{98767643, 5453423}}}},
			out: []byte{0x00, 0x00, 0x00, 0x01, 0xdc, 0x04, 0x27, 0x34, 0xac, 0x68, 0x01, 0x00, 0x00,
				0x00, 0x02, 0x05, 0xe3, 0x13, 0x1b, 0x00, 0x53, 0x36, 0x6f},
		},
		{
			desc: "2",
			in: TestUnionContainer{
				Select: 2,
				Union:  TestUnion{B: TestListUint32{3287743, 98731}}},
			out: []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x32, 0x2a, 0xbf, 0x00,
				0x01, 0x81, 0xab},
		},
		{
			desc: "3",
			in:   TestUnionContainer{Select: 3, Union: TestUnion{C: 4321}},
			out:  []byte{0x00, 0x00, 0x00, 0x03, 0x10, 0xe1},
		},
		{
			desc: "4",
			in:   TestUnionContainer{Select: 4},
			out:  []byte{0x00, 0x00, 0x00, 0x04},
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			out, err := MarshalToBytes(data.in)
			if err != nil {
				t.Fatalf("MarshalToBytes failed: %v", err)
			}

			if !bytes.Equal(out, data.out) {
				t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
			}

			var a TestUnionContainer

			n, err := UnmarshalFromBytes(out, &a)
			if err != nil {
				t.Fatalf("UnmarshalFromBytes failed: %v", err)
			}
			if n != len(out) {
				t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
			}

			if !reflect.DeepEqual(data.in, a) {
				t.Errorf("UnmarshalFromBytes didn't return the original data")
			}
		})
	}
}

func TestMarshalUnionInvalidSelector(t *testing.T) {
	a := TestUnionContainer{Select: 5}
	_, err := MarshalToBytes(a)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal a union with an invalid selector value")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestUnionContainer: cannot marshal field Union: "+
		"cannot marshal struct type tpm2.TestUnion: error marshalling union struct: cannot select "+
		"union member: invalid selector value: 5" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}

	var ao TestUnionContainer
	_, err = UnmarshalFromBytes([]byte{0x00, 0x00, 0x01, 0x03, 0x10, 0xe1}, &ao)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should fail to marshal a union with an invalid selector value")
	}
	if err.Error() != "cannot unmarshal struct type tpm2.TestUnionContainer: cannot unmarshal field "+
		"Union: cannot unmarshal struct type tpm2.TestUnion: error unmarshalling union struct: cannot "+
		"select union member: invalid selector value: 259" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}
}

type TestInvalidUnionContainer struct {
	Select uint32
	Union  TestUnion
}

func TestMarshalUnionInInvalidContainer(t *testing.T) {
	a := TestInvalidUnionContainer{
		Select: 2,
		Union:  TestUnion{B: TestListUint32{3287743, 98731}}}
	_, err := MarshalToBytes(a)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal a union inside an invalid container")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestInvalidUnionContainer: cannot marshal field "+
		"Union: cannot marshal struct type tpm2.TestUnion: error marshalling union struct: no selector "+
		"member defined in container" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}

	var ao TestInvalidUnionContainer
	_, err = UnmarshalFromBytes([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x32, 0x2a,
		0xbf, 0x00, 0x01, 0x81, 0xab}, &ao)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should fail to unmarshal to a union inside an invalid container")
	}
	if err.Error() != "cannot unmarshal struct type tpm2.TestInvalidUnionContainer: cannot unmarshal "+
		"field Union: cannot unmarshal struct type tpm2.TestUnion: error unmarshalling union struct: "+
		"no selector member defined in container" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}

	b := TestUnion{C: 5432}
	_, err = MarshalToBytes(b)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to unmarshal to a union inside an invalid container")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestUnion: error marshalling union struct: not "+
		"inside a container" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

type TestStructWithCustomMarshaller struct {
	A uint16
	B TestListUint32
}

func (t *TestStructWithCustomMarshaller) Marshal(buf io.Writer) error {
	if err := binary.Write(buf, binary.BigEndian, t.A); err != nil {
		return err
	}
	return MarshalToWriter(buf, t.B)
}

func (t *TestStructWithCustomMarshaller) Unmarshal(buf io.Reader) error {
	if err := binary.Read(buf, binary.BigEndian, &t.A); err != nil {
		return err
	}
	return UnmarshalFromReader(buf, &t.B)
}

func TestMarshalStructWithCustomMarshaller(t *testing.T) {
	a := TestStructWithCustomMarshaller{A: 44332, B: TestListUint32{885432, 31287554}}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82, 0xb8, 0x01,
		0xdd, 0x69, 0x02}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructWithCustomMarshaller
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	_, err = MarshalToBytes(a)
	if err == nil {
		t.Fatal("MarshalToBytes should fail to marshal a truct with a custom marshaller supplied " +
			"as a value")
	}
	if err.Error() != "cannot marshal non-addressable non-pointer type tpm2.TestStructWithCustomMarshaller "+
		"with custom marshaller" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

type TestStructWithEmbeddedCustomMarshallerType struct {
	A uint32
	B *TestStructWithCustomMarshaller
}

func TestMarshalStructWithCustomMarshallerFromContainer(t *testing.T) {
	a := TestStructWithEmbeddedCustomMarshallerType{
		A: 54321211,
		B: &TestStructWithCustomMarshaller{A: 44332, B: TestListUint32{885432, 31287554}}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82,
		0xb8, 0x01, 0xdd, 0x69, 0x02}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructWithEmbeddedCustomMarshallerType
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	b := TestStructWithEmbeddedCustomMarshallerType{A: 43232}
	_, err = MarshalToBytes(b)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal when encountering a nil pointer to a type with " +
			"a custom marshaller")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestStructWithEmbeddedCustomMarshallerType: cannot "+
		"marshal field B: cannot marshal nil pointer type *tpm2.TestStructWithCustomMarshaller with "+
		"custom marshaller" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

type TestStructWithEmbeddedCustomMarshallerTypeAsValue struct {
	A uint32
	B TestStructWithCustomMarshaller
}

func TestMarshalStructWithCustomMarshallerAsValueFromContainer(t *testing.T) {
	a := TestStructWithEmbeddedCustomMarshallerTypeAsValue{
		A: 54321211,
		B: TestStructWithCustomMarshaller{A: 44332, B: TestListUint32{885432, 31287554}}}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82,
		0xb8, 0x01, 0xdd, 0x69, 0x02}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructWithEmbeddedCustomMarshallerTypeAsValue
	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	// This sucks, but any container type with types that implement CustomMarshaller must be passed to
	// MarshalToBytes as a pointer. This isn't ideal, but test this case anyway
	_, err = MarshalToBytes(a)
	if err == nil {
		t.Fatal("MarshalToBytes should fail to marshal a truct with a custom marshaller supplied " +
			"as a value")
	}
	if err.Error() != "cannot marshal struct type tpm2.TestStructWithEmbeddedCustomMarshallerTypeAsValue: "+
		"cannot marshal field B: cannot marshal non-addressable non-pointer type "+
		"tpm2.TestStructWithCustomMarshaller with custom marshaller" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}
