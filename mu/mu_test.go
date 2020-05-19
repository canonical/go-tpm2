// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu_test

import (
	"bytes"
	"encoding/binary"
	"io"
	"reflect"
	"testing"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/mu"
)

func TestMarshalBasic(t *testing.T) {
	var a uint16 = 1156
	var b bool = true
	var c uint32 = 45623564
	var d bool = false

	out, err := MarshalToBytes(a, b, c, d)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x04, 0x84, 0x01, 0x02, 0xb8, 0x29, 0x0c, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao uint16
	var bo bool
	var co uint32
	var do bool

	n, err := UnmarshalFromBytes(out, &ao, &bo, &co, &do)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if a != ao || b != bo || c != co || d != do {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestMarshalPtr(t *testing.T) {
	var a uint32 = 45623564
	var b bool = true

	pa := &a
	pb := b

	out, err := MarshalToBytes(pa, pb)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x02, 0xb8, 0x29, 0x0c, 0x01}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao *uint32 // Unmarshal should allocate data for a nil pointer
	var bo bool
	pbo := &bo // Make sure that unmarshal doesn't overwrite a non-nil pointer

	n, err := UnmarshalFromBytes(out, &ao, &pbo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if *ao != a || bo != b {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestMarshalRawBytes(t *testing.T) {
	a := RawBytes{0x7a, 0x78, 0x8f, 0x56, 0xfa, 0x49, 0xae, 0x0b, 0xa5, 0xeb, 0xde, 0x78, 0x0e, 0xfe, 0x4d,
		0x6a, 0x89, 0xb5, 0xdb, 0x47}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(a, out) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	ao := make(RawBytes, len(a))

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !bytes.Equal(a, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	bo := make(RawBytes, len(a)-1)

	n, err = UnmarshalFromBytes(out, &bo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(a)-1 {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !bytes.Equal(a[:len(a)-1], bo) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}

	co := make(RawBytes, len(a)+1)

	n, err = UnmarshalFromBytes(out, &co)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should have failed")
	}
	if err.Error() != "cannot unmarshal argument at index 0: cannot process raw type mu.RawBytes: unexpected EOF" {
		t.Errorf("Unexpected error: %v", err)
	}
}

type TestSizedBuffer []byte

func TestMarshalSizedBuffer(t *testing.T) {
	a := TestSizedBuffer{0x2f, 0x74, 0x68, 0x3f, 0x15, 0x43, 0x1d, 0x01, 0xea, 0x28, 0xad, 0xe2, 0x6c, 0x4d, 0x00, 0x9b}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x10, 0x2f, 0x74, 0x68, 0x3f, 0x15, 0x43, 0x1d, 0x01, 0xea, 0x28, 0xad, 0xe2, 0x6c, 0x4d, 0x00,
		0x9b}) {
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

	// Test unmarshalling with a pre-allocated slice with a smaller capacity than required - it should be
	// reallocated automatically
	ao2 := make(TestSizedBuffer, 8, 8)

	n, err = UnmarshalFromBytes(out, &ao2)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao2) {
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

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x45, 0xa1, 0xdd, 0x00, 0x00, 0x02, 0xa6, 0x00,
		0x00, 0x30, 0x66}) {
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

	// Test unmarshalling with a pre-allocated slice with a smaller capacity than required - it should be
	// reallocated automatically
	ao2 := make(TestListUint32, 2, 2)

	n, err = UnmarshalFromBytes(out, &ao2)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao2) {
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

	if !bytes.Equal(out, []byte{0xdc, 0x04, 0x27, 0x34, 0xac, 0x68, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x10, 0x88, 0x00, 0x08,
		0xa9, 0xe9}) {
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

	if !bytes.Equal(out, []byte{0x00, 0x1d, 0xdc, 0x02, 0x1f, 0x02, 0xa4, 0x4e, 0x13, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0xa8,
		0xd5, 0x00, 0x08, 0xa1, 0xab, 0x22, 0xc7, 0x00, 0x32, 0xad, 0x7b, 0x01, 0x00, 0x00, 0x00, 0x01, 0x01, 0x51, 0xe1, 0xc8}) {
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

	// Verify that unmarshal doesn't overwrite pointers in a struct if it points to an object we've
	// already allocated
	var s TestStructSimple
	ao2 := TestStructWithEmbeddedStructs{D: &s}

	n, err = UnmarshalFromBytes(out, &ao2)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(s, *a.D) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type testUint16RawSlice struct {
	Data []uint16 `tpm2:"raw"`
}

func TestMarshalRawSlice(t *testing.T) {
	a := []uint16{56, 453, 3233}
	out, err := MarshalToBytes(testUint16RawSlice{a})
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x00, 0x38, 0x01, 0xc5, 0x0c, 0xa1}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	ao := testUint16RawSlice{make([]uint16, 3)}

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao.Data) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type testFakeRawBytes struct {
	Data []byte `tpm2:"raw"`
}

func TestMarshalFakeRawBytes(t *testing.T) {
	a := []byte{0xfa, 0xf5, 0x56, 0x44, 0x2b, 0xec, 0x56, 0xfe, 0x94, 0xf5, 0x1e, 0x13, 0x81, 0xd1, 0xb2, 0x6a}
	out, err := MarshalToBytes(testFakeRawBytes{a})
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, a) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	ao := testFakeRawBytes{make([]byte, len(a))}

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(a, ao.Data) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestStructWithRawBytes struct {
	A uint32
	B RawBytes
}

func TestMarshalRawBytesInStruct(t *testing.T) {
	a := TestStructWithRawBytes{2643267, RawBytes{0xd3, 0xb0, 0x73, 0x84, 0xd1, 0x13, 0xed, 0xec, 0x49, 0xea, 0xa6, 0x23, 0x8a, 0xd5,
		0xff, 0x00}}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x28, 0x55, 0x43, 0xd3, 0xb0, 0x73, 0x84, 0xd1, 0x13, 0xed, 0xec, 0x49, 0xea, 0xa6, 0x23, 0x8a,
		0xd5, 0xff, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	ao := TestStructWithRawBytes{B: make(RawBytes, 16)}

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

//func TestUnmarshalNilRawBytes(t *testing.T) {
//	b := []byte{0x00, 0x28, 0x55, 0x43, 0xd3, 0xb0, 0x73, 0x84, 0xd1, 0x13, 0xed, 0xec, 0x49, 0xea, 0xa6, 0x23, 0x8a, 0xd5, 0xff, 0x00}
//	var o TestStructWithRawBytes
//	_, err := UnmarshalFromBytes(b, &o)
//	if err == nil {
//		t.Fatalf("Expected UnmarshalFromBytes to fail")
//	}
//	if err.Error() != "cannot unmarshal argument at index 0: cannot process struct type mu_test.TestStructWithRawBytes: cannot "+
//		"process field B from struct type mu_test.TestStructWithRawBytes: cannot process slice type mu.RawBytes, inside container "+
//		"type mu_test.TestStructWithRawBytes: nil raw byte slice" {
//		t.Errorf("Unexpected error: %v", err)
//	}
//}

type TestSizedStruct struct {
	A uint32
	B TestListUint32
}

type TestStructWithNonPointerSizedStruct struct {
	S TestSizedStruct `tpm2:"sized"`
}

type TestStructWithPointerSizedStruct struct {
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
				S: &TestSizedStruct{A: 754122, B: TestListUint32{22189, 854543, 445888654}}},
			out: []byte{0x00, 0x14, 0x00, 0x0b, 0x81, 0xca, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x56, 0xad, 0x00, 0x0d, 0x0a, 0x0f, 0x1a,
				0x93, 0xb8, 0x8e},
		},
		{
			desc: "NilPointer",
			in:   TestStructWithPointerSizedStruct{},
			out:  []byte{0x00, 0x00},
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

func TestUnmarshalZeroSizedStructToNonNilPointer(t *testing.T) {
	a := TestStructWithPointerSizedStruct{S: &TestSizedStruct{}}

	_, err := UnmarshalFromBytes([]byte{0x00, 0x00}, &a)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should have failed")
	}
	if err.Error() != "cannot unmarshal argument at index 0: cannot process struct type mu_test.TestStructWithPointerSizedStruct: "+
		"cannot process field S from struct type mu_test.TestStructWithPointerSizedStruct: cannot process sized type "+
		"*mu_test.TestSizedStruct, inside container type mu_test.TestStructWithPointerSizedStruct: sized value is zero sized, but "+
		"destination value has been pre-allocated" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}
}

func TestMarshalNilPointer(t *testing.T) {
	a := TestStructWithEmbeddedStructs{A: true, B: 55422}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x01, 0xd8, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
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

	a.D = &TestStructSimple{}
	if !reflect.DeepEqual(a, ao) {
		// FIXME: Investigate why this fails
		t.Logf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestUnion struct {
	Data interface{}
}

func (t TestUnion) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(uint32) {
	case 1:
		return reflect.TypeOf((*TestStructSimple)(nil))
	case 2:
		return reflect.TypeOf(TestListUint32(nil))
	case 3:
		return reflect.TypeOf(uint16(0))
	case 4:
		return reflect.TypeOf(NilUnionValue)
	default:
		return nil
	}
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
				Union:  TestUnion{&TestStructSimple{56324, 657763432, true, TestListUint32{98767643, 5453423}}}},
			out: []byte{0x00, 0x00, 0x00, 0x01, 0xdc, 0x04, 0x27, 0x34, 0xac, 0x68, 0x01, 0x00, 0x00, 0x00, 0x02, 0x05, 0xe3, 0x13, 0x1b,
				0x00, 0x53, 0x36, 0x6f},
		},
		{
			desc: "2",
			in: TestUnionContainer{
				Select: 2,
				Union:  TestUnion{TestListUint32{3287743, 98731}}},
			out: []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x00, 0x32, 0x2a, 0xbf, 0x00, 0x01, 0x81, 0xab},
		},
		{
			desc: "3",
			in:   TestUnionContainer{Select: 3, Union: TestUnion{uint16(4321)}},
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

func TestMarshalUnionWithNilUnionValue(t *testing.T) {
	a := TestUnionContainer{Select: 2}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestUnionContainer

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(TestUnionContainer{Select: 2, Union: TestUnion{TestListUint32{}}}, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestMarshalUnionWithInvalidSelector(t *testing.T) {
	a := TestUnionContainer{Select: 259}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x01, 0x03}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestUnionContainer
	_, err = UnmarshalFromBytes(out, &ao)
	if err == nil {
		t.Fatalf("UnmarshalFromBytes should fail to marshal a union with an invalid selector value")
	}
	if err.Error() != "cannot unmarshal argument at index 0: cannot process struct type mu_test.TestUnionContainer: cannot process "+
		"field Union from struct type mu_test.TestUnionContainer: invalid selector value: 259" {
		t.Errorf("UnmarshalFromBytes returned an unexpected error: %v", err)
	}
}

func TestMarshalUnionWithIncorrectType(t *testing.T) {
	a := TestUnionContainer{Select: 2, Union: TestUnion{uint16(56)}}
	_, err := MarshalToBytes(a)
	if err == nil {
		t.Fatalf("MarshalToBytes should fail to marshal a union with the wrong data type")
	}
	if err.Error() != "cannot marshal argument at index 0: cannot process struct type mu_test.TestUnionContainer: cannot process field "+
		"Union from struct type mu_test.TestUnionContainer: data has incorrect type uint16 (expected mu_test.TestListUint32)" {
		t.Errorf("MarshalToBytes returned an unexpected error: %v", err)
	}
}

func TestMarshalUnionWithNilPointerValue(t *testing.T) {
	a := TestUnionContainer{Select: 1}
	out, err := MarshalToBytes(a)

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestUnionContainer

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	a.Union.Data = &TestStructSimple{}
	if !reflect.DeepEqual(a, ao) {
		// FIXME: Investigate why this fails
		t.Logf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestMarshalUnionDataImplicitTypeConversion(t *testing.T) {
	a := TestUnionContainer{Select: 3, Union: TestUnion{tpm2.AlgorithmSHA256}}
	if reflect.TypeOf(a.Union.Data) == reflect.TypeOf(uint16(0)) {
		t.Fatalf("Test requires these to be different types")
	}
	out, err := MarshalToBytes(a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x00, 0x00, 0x00, 0x03, 0x00, 0x0b}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestUnionContainer

	n, err := UnmarshalFromBytes(out, &ao)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(TestUnionContainer{Select: 3, Union: TestUnion{uint16(11)}}, ao) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

type TestStructWithCustomMarshaller struct {
	A uint16
	B TestListUint32
}

func (t *TestStructWithCustomMarshaller) Marshal(buf io.Writer) (nbytes int, err error) {
	if err := binary.Write(buf, binary.BigEndian, t.A); err != nil {
		return nbytes, err
	}
	nbytes += binary.Size(t.A)
	n, err := MarshalToWriter(buf, t.B)
	return nbytes + n, err
}

func (t *TestStructWithCustomMarshaller) Unmarshal(buf io.Reader) (nbytes int, err error) {
	if err := binary.Read(buf, binary.BigEndian, &t.A); err != nil {
		return nbytes, err
	}
	nbytes += binary.Size(t.A)
	n, err := UnmarshalFromReader(buf, &t.B)
	return nbytes + n, err
}

func TestMarshalStructWithCustomMarshaller(t *testing.T) {
	a := TestStructWithCustomMarshaller{A: 44332, B: TestListUint32{885432, 31287554}}
	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82, 0xb8, 0x01, 0xdd, 0x69, 0x02}) {
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

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82, 0xb8, 0x01, 0xdd,
		0x69, 0x02}) {
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
	out, err = MarshalToBytes(b)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}
	if !bytes.Equal(out, []byte{0x00, 0x00, 0xa8, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
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

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82, 0xb8, 0x01, 0xdd, 0x69, 0x02}) {
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
}

type TestStructWithSizedCustomMarshallerType struct {
	A uint32
	B *TestStructWithCustomMarshaller `tpm2:"sized"`
}

func TestMarshalStructWithSizedCustomMarshaller(t *testing.T) {
	a := TestStructWithSizedCustomMarshallerType{
		A: 54321211,
		B: &TestStructWithCustomMarshaller{A: 44332, B: TestListUint32{885432, 31287554}}}

	out, err := MarshalToBytes(&a)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0x00, 0x0e, 0xad, 0x2c, 0x00, 0x00, 0x00, 0x02, 0x00, 0x0d, 0x82, 0xb8, 0x01, 0xdd, 0x69, 0x02}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var ao TestStructWithSizedCustomMarshallerType
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

	b := TestStructWithSizedCustomMarshallerType{A: 54321211}

	out, err = MarshalToBytes(&b)
	if err != nil {
		t.Fatalf("MarshalToBytes failed: %v", err)
	}

	if !bytes.Equal(out, []byte{0x03, 0x3c, 0xe0, 0x3b, 0x00, 0x00}) {
		t.Errorf("MarshalToBytes returned an unexpected sequence of bytes: %x", out)
	}

	var bo TestStructWithSizedCustomMarshallerType
	n, err = UnmarshalFromBytes(out, &bo)
	if err != nil {
		t.Fatalf("UnmarshalFromBytes failed: %v", err)
	}
	if n != len(out) {
		t.Errorf("UnmarshalFromBytes consumed the wrong number of bytes (%d)", n)
	}

	if !reflect.DeepEqual(b, bo) {
		t.Errorf("UnmarshalFromBytes didn't return the original data")
	}
}

func TestDetemineTPMKind(t *testing.T) {
	for _, data := range []struct {
		desc string
		d    interface{}
		k    TPMKind
	}{
		{
			desc: "Unsupported",
			d:    [3]uint16{1, 2, 3},
			k:    TPMKindUnsupported,
		},
		{
			desc: "Primitive",
			d:    uint32(10),
			k:    TPMKindPrimitive,
		},
		{
			desc: "Sized/1",
			d:    TestSizedBuffer{},
			k:    TPMKindSized,
		},
		{
			desc: "Sized/2",
			d:    TestStructWithPointerSizedStruct{},
			k:    TPMKindSized,
		},
		{
			desc: "List",
			d:    TestListUint32{},
			k:    TPMKindList,
		},
		{
			desc: "Struct",
			d:    TestStructSimple{},
			k:    TPMKindStruct,
		},
		{
			desc: "Union",
			d:    TestUnion{},
			k:    TPMKindUnion,
		},
		{
			desc: "Custom",
			d:    TestStructWithCustomMarshaller{},
			k:    TPMKindCustom,
		},
		{
			desc: "RawBytes/1",
			d:    RawBytes{},
			k:    TPMKindRawBytes,
		},
		{
			desc: "RawBytes/2",
			d:    testFakeRawBytes{},
			k:    TPMKindRawBytes,
		},
		{
			desc: "RawList",
			d:    testUint16RawSlice{},
			k:    TPMKindRawList,
		},
	} {
		t.Run(data.desc, func(t *testing.T) {
			k := DetermineTPMKind(data.d)
			if k != data.k {
				t.Errorf("Unexpected value: %d", k)
			}
		})
	}
}
