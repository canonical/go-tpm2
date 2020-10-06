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
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type muSuite struct{}

var _ = Suite(&muSuite{})

type testMarshalAndUnmarshalData struct {
	values                []interface{}
	expected              []byte
	unmarshalDests        []interface{}
	unmarshalLen          int
	unmarshalExpectedVals []interface{}
}

func (s *muSuite) testMarshalAndUnmarshalBytes(c *C, data *testMarshalAndUnmarshalData) {
	out, err := MarshalToBytes(data.values...)
	c.Check(err, IsNil)
	c.Check(out, DeepEquals, data.expected)

	unmarshalDests := data.unmarshalDests
	if unmarshalDests == nil {
		for _, v := range data.values {
			unmarshalDests = append(unmarshalDests, reflect.New(reflect.TypeOf(v)).Interface())
		}
	}

	unmarshalLen := data.unmarshalLen
	if unmarshalLen == 0 {
		unmarshalLen = len(out)
	}

	unmarshalExpectedVals := data.unmarshalExpectedVals
	if unmarshalExpectedVals == nil {
		unmarshalExpectedVals = data.values[:len(unmarshalDests)]
	}

	n, err := UnmarshalFromBytes(out, unmarshalDests...)
	c.Check(err, IsNil)
	c.Check(n, Equals, unmarshalLen)
	var unmarshalVals []interface{}
	for _, p := range unmarshalDests {
		unmarshalVals = append(unmarshalVals, reflect.ValueOf(p).Elem().Interface())
	}
	c.Check(unmarshalVals, DeepEquals, unmarshalExpectedVals)
}

func (s *muSuite) testMarshalAndUnmarshalIO(c *C, data *testMarshalAndUnmarshalData) {
	buf := new(bytes.Buffer)
	n, err := MarshalToWriter(buf, data.values...)
	c.Check(err, IsNil)
	c.Check(n, Equals, len(data.expected))
	c.Check(buf.Bytes(), DeepEquals, data.expected)

	unmarshalDests := data.unmarshalDests
	if unmarshalDests == nil {
		for _, v := range data.values {
			unmarshalDests = append(unmarshalDests, reflect.New(reflect.TypeOf(v)).Interface())
		}
	}

	unmarshalLen := data.unmarshalLen
	if unmarshalLen == 0 {
		unmarshalLen = buf.Len()
	}

	unmarshalExpectedVals := data.unmarshalExpectedVals
	if unmarshalExpectedVals == nil {
		unmarshalExpectedVals = data.values[:len(unmarshalDests)]
	}

	n, err = UnmarshalFromReader(buf, unmarshalDests...)
	c.Check(err, IsNil)
	c.Check(n, Equals, unmarshalLen)
	var unmarshalVals []interface{}
	for _, p := range unmarshalDests {
		unmarshalVals = append(unmarshalVals, reflect.ValueOf(p).Elem().Interface())
	}
	c.Check(unmarshalVals, DeepEquals, unmarshalExpectedVals)
}

func (s *muSuite) TestMarshalAndUnmarshalPrimitives(c *C) {
	data := &testMarshalAndUnmarshalData{
		values:   []interface{}{uint16(1156), true, uint32(45623564), false},
		expected: testutil.DecodeHexString(c, "04840102b8290c00")}
	s.testMarshalAndUnmarshalBytes(c, data)
	s.testMarshalAndUnmarshalIO(c, data)
}

func (s *muSuite) TestMarshalAndUnmarshalPtrs(c *C) {
	var x uint32 = 45623564
	var y bool = true
	var z *uint16 // Test that a nil pointer is marshalled to the zero value

	var uxp *uint32
	var uy bool
	uyp := &uy
	var uzp *uint16

	var z2 uint16

	data := &testMarshalAndUnmarshalData{
		values:                []interface{}{&x, &y, z},
		expected:              testutil.DecodeHexString(c, "02b8290c010000"),
		unmarshalDests:        []interface{}{&uxp, &uyp, &uzp},
		unmarshalExpectedVals: []interface{}{&x, &y, &z2}}

	s.testMarshalAndUnmarshalBytes(c, data)
	// Make sure that unmashal didn't allocate a new value when it was passed a non-nil pointer
	c.Check(uy, Equals, y)

	uxp = nil
	uy = false
	uzp = nil

	s.testMarshalAndUnmarshalIO(c, data)
	// Make sure that unmashal didn't allocate a new value when it was passed a non-nil pointer
	c.Check(uy, Equals, y)
}

func (s *muSuite) TestMarshalAndUnmarshlRawBytes(c *C) {
	a := testutil.DecodeHexString(c, "7a788f56fa49ae0ba5ebde780efe4d6a89b5db47")
	ua := make(RawBytes, len(a))

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{RawBytes(a)},
		expected:       a,
		unmarshalDests: []interface{}{&ua}})

	ua = make(RawBytes, len(a))

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{RawBytes(a)},
		expected:       a,
		unmarshalDests: []interface{}{&ua}})
}

type testSizedBuffer []byte

func (s *muSuite) TestMarshalAndUnmarshalSizedBuffer(c *C) {
	a := testutil.DecodeHexString(c, "2f74683f15431d01ea28ade26c4d009b")
	ua := make([]byte, 8)
	ua2 := ua

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       append(testutil.DecodeHexString(c, "0010"), a...),
		unmarshalDests: []interface{}{&ua}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(ua2, DeepEquals, make([]byte, 8))

	ua3 := make(testSizedBuffer, len(a)+10)
	ua4 := ua3

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{testSizedBuffer(a)},
		expected:       append(testutil.DecodeHexString(c, "0010"), a...),
		unmarshalDests: []interface{}{&ua3}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(ua4, DeepEquals, make(testSizedBuffer, len(a)+10))
}

func (s *muSuite) TestMarshalAndUnmarshalList(c *C) {
	values := []interface{}{[]uint32{46, 4563421, 678, 12390}, []uint64{}, []uint16{59747, 22875}}
	expected := testutil.DecodeHexString(c, "000000040000002e0045a1dd000002a6000030660000000000000002e963595b")

	var ua []uint32
	var ub []uint64
	uc := make([]uint16, 1)
	uc2 := uc

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         values,
		expected:       expected,
		unmarshalDests: []interface{}{&ua, &ub, &uc}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(uc2, DeepEquals, make([]uint16, 1))

	ua = nil
	ub = nil
	uc = make([]uint16, 10)
	uc2 = uc

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         values,
		expected:       expected,
		unmarshalDests: []interface{}{&ua, &ub, &uc}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(uc2, DeepEquals, make([]uint16, 10))
}

type testStruct struct {
	A uint16
	B *uint32
	C bool
	D []uint32
}

func (s *muSuite) TestMarshalAndUnmarshalStruct(c *C) {
	var u32 uint32 = 657763432
	var u32_0 uint32

	a := testStruct{56324, &u32, true, []uint32{4232, 567785}}
	b := testStruct{34963, nil, false, []uint32{}}
	expected := testutil.DecodeHexString(c, "dc042734ac680100000002000010880008a9e98893000000000000000000dc042734ac680100000002000010880008a9e9")

	var uc_b uint32
	var ua testStruct
	var ub testStruct
	uc := testStruct{B: &uc_b, D: make([]uint32, 1)}
	uc_d := uc.D

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a, b, &a},
		expected:              expected,
		unmarshalDests:        []interface{}{&ua, &ub, &uc},
		unmarshalExpectedVals: []interface{}{a, testStruct{34963, &u32_0, false, []uint32{}}, a}})
	// Make sure that unmashal didn't allocate a new value when it was passed a non-nil pointer
	c.Check(uc_b, Equals, u32)
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(uc_d, DeepEquals, make([]uint32, 1))

	uc_b = 0
	ua = testStruct{}
	ub = testStruct{}
	uc = testStruct{B: &uc_b, D: make([]uint32, 10)}
	uc_d = uc.D

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a, b, &a},
		expected:              expected,
		unmarshalDests:        []interface{}{&ua, &ub, &uc},
		unmarshalExpectedVals: []interface{}{a, testStruct{34963, &u32_0, false, []uint32{}}, a}})
	// Make sure that unmashal didn't allocate a new value when it was passed a non-nil pointer
	c.Check(uc_b, Equals, u32)
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(uc_d, DeepEquals, make([]uint32, 10))
}

type testStructWithRawTagFields struct {
	A []uint16 `tpm2:"raw"`
	B []byte   `tpm2:"raw"`
}

func (s *muSuite) TestMarshalAndUnmarshalWithRawTag(c *C) {
	a := testStructWithRawTagFields{A: []uint16{56, 453, 3233}, B: testutil.DecodeHexString(c, "faf556442bec56fe94f51e1381d1b26a")}
	expected := testutil.DecodeHexString(c, "003801c50ca1faf556442bec56fe94f51e1381d1b26a")

	ua := testStructWithRawTagFields{A: make([]uint16, len(a.A)), B: make([]byte, len(a.B))}

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       expected,
		unmarshalDests: []interface{}{&ua}})

	ua = testStructWithRawTagFields{A: make([]uint16, len(a.A)), B: make([]byte, len(a.B))}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       expected,
		unmarshalDests: []interface{}{&ua}})
}

func (s *muSuite) TestUnmarshalNilRawTagFields(c *C) {
	a := testStructWithRawTagFields{A: []uint16{56, 453, 3233}, B: testutil.DecodeHexString(c, "faf556442bec56fe94f51e1381d1b26a")}
	expected := testutil.DecodeHexString(c, "003801c50ca1faf556442bec56fe94f51e1381d1b26a")

	ua := testStructWithRawTagFields{B: make([]byte, len(expected))}

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a},
		expected:              expected,
		unmarshalDests:        []interface{}{&ua},
		unmarshalExpectedVals: []interface{}{testStructWithRawTagFields{B: expected}}})

	ua = testStructWithRawTagFields{A: make([]uint16, len(expected)/2)}

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a},
		expected:              expected,
		unmarshalDests:        []interface{}{&ua},
		unmarshalExpectedVals: []interface{}{testStructWithRawTagFields{A: []uint16{56, 453, 3233, 64245, 22084, 11244, 22270, 38133, 7699, 33233, 45674}}}})
}

type testStructWithSizedField struct {
	A uint32
	B *testStruct `tpm2:"sized"`
}

func (s *muSuite) TestMarshalAndUnmarshalSizedStruct(c *C) {
	var u32 uint32 = 657763432
	a := testStructWithSizedField{A: 1872244400, B: &testStruct{56324, &u32, true, []uint32{4232, 567785}}}
	b := testStructWithSizedField{A: 21213504}

	expected := testutil.DecodeHexString(c, "6f982eb00013dc042734ac680100000002000010880008a9e90143b1400000")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a, b},
		expected: expected})

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a, b},
		expected: expected})
}

type testUnion struct {
	Data interface{}
}

func (t testUnion) Select(selector reflect.Value) reflect.Type {
	switch selector.Interface().(uint32) {
	case 1:
		return reflect.TypeOf((*testStruct)(nil))
	case 2:
		return reflect.TypeOf([]uint32(nil))
	case 3:
		return reflect.TypeOf(uint16(0))
	case 4:
		return reflect.TypeOf(NilUnionValue)
	default:
		return nil
	}
}

type testUnionContainer struct {
	Select uint32
	Union  testUnion `tpm2:"selector:Select"`
}

func (s *muSuite) TestMarshalAndUnmarshalUnion(c *C) {
	var u32 uint32 = 657763432
	t := testUnionContainer{Select: 1, Union: testUnion{&testStruct{56324, &u32, true, []uint32{98767643, 5453423}}}}
	u := testUnionContainer{Select: 2, Union: testUnion{[]uint32{3287743, 98731}}}
	v := testUnionContainer{Select: 3, Union: testUnion{uint16(4321)}}
	w := testUnionContainer{Select: 4}
	x := testUnionContainer{Select: 2}                                             // Test that the zero value gets marshalled
	y := testUnionContainer{Select: 1}                                             // Test that the zero value gets marshalled
	z := testUnionContainer{Select: 3, Union: testUnion{tpm2.HashAlgorithmSHA256}} // Test that implicit conversion happens

	expected := testutil.DecodeHexString(c, "00000001dc042734ac68010000000205e3131b0053366f000000020000000200322abf000181ab0000000310e100000004000000020000000000000001000000000000000000000000000003000b")

	var u32_0 uint32

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{t, u, v, w, x, y, z},
		expected: expected,
		unmarshalExpectedVals: []interface{}{t, u, v, w, testUnionContainer{Select: 2, Union: testUnion{[]uint32{}}},
			testUnionContainer{Select: 1, Union: testUnion{&testStruct{0, &u32_0, false, []uint32{}}}},
			testUnionContainer{Select: 3, Union: testUnion{uint16(tpm2.HashAlgorithmSHA256)}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{t, u, v, w, x, y, z},
		expected: expected,
		unmarshalExpectedVals: []interface{}{t, u, v, w, testUnionContainer{Select: 2, Union: testUnion{[]uint32{}}},
			testUnionContainer{Select: 1, Union: testUnion{&testStruct{0, &u32_0, false, []uint32{}}}},
			testUnionContainer{Select: 3, Union: testUnion{uint16(tpm2.HashAlgorithmSHA256)}}}})
}

type testStructWithCustomMarshaller struct {
	A uint16
	B []uint32
}

func (t testStructWithCustomMarshaller) Marshal(w io.Writer) error {
	if err := binary.Write(w, binary.LittleEndian, t.A); err != nil {
		return err
	}
	_, err := MarshalToWriter(w, t.B)
	return err
}

func (t *testStructWithCustomMarshaller) Unmarshal(r Reader) error {
	if err := binary.Read(r, binary.LittleEndian, &t.A); err != nil {
		return err
	}
	_, err := UnmarshalFromReader(r, &t.B)
	return err
}

func (s *muSuite) TestMarshalAndUnmarshalCustomMarshaller(c *C) {
	a := testStructWithCustomMarshaller{A: 44332, B: []uint32{885432, 31287554}}
	expected := testutil.DecodeHexString(c, "2cad00000002000d82b801dd6902")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
}

type testStructWithRawTagSizedFields struct {
	A [][]byte `tpm2:"raw"`
}

func (s *muSuite) TestMarshalAndUnmarshalSizedTypeInsideRawSlice(c *C) {
	a := testStructWithRawTagSizedFields{A: [][]byte{testutil.DecodeHexString(c, "a5a5a5"), testutil.DecodeHexString(c, "4d4d4d4d")}}
	expected := testutil.DecodeHexString(c, "0003a5a5a500044d4d4d4d")

	ua := testStructWithRawTagSizedFields{A: make([][]byte, len(a.A))}

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       expected,
		unmarshalDests: []interface{}{&ua}})

	ua = testStructWithRawTagSizedFields{A: make([][]byte, len(a.A))}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       expected,
		unmarshalDests: []interface{}{&ua}})
}

type testDetermineTPMKindData struct {
	d interface{}
	k TPMKind
}

func (s *muSuite) testDetermineTPMKind(c *C, data *testDetermineTPMKindData) {
	c.Check(DetermineTPMKind(data.d), Equals, data.k)
}

func (s *muSuite) TestDetermineTPMKindUnsupported(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: [3]uint16{1, 2, 3}, k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindPrimitive(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: uint32(10), k: TPMKindPrimitive})
}

func (s *muSuite) TestDetermineTPMKindSized1(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testSizedBuffer{}, k: TPMKindSized})
}

type testStructSized struct {
	*testStruct `tpm2:"sized"`
}

func (s *muSuite) TestDetermineTPMKindSized2(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStructSized{}, k: TPMKindSized})
}

func (s *muSuite) TestDetermineTPMKindSizedPtr(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: &testStructSized{}, k: TPMKindSized})
}

func (s *muSuite) TestDetermineTPMKindList(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: []uint32{}, k: TPMKindList})
}

func (s *muSuite) TestDetermineTPMKindStruct(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStruct{}, k: TPMKindStruct})
}

func (s *muSuite) TestDetermineTPMKindUnion(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testUnion{}, k: TPMKindUnion})
}

func (s *muSuite) TestDetermineTPMKindCustom(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStructWithCustomMarshaller{}, k: TPMKindCustom})
}

func (s *muSuite) TestDetermineTPMKindRawBytes1(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: RawBytes{}, k: TPMKindRawBytes})
}

type testStructWithRawByteField struct {
	A []byte `tpm2:"raw"`
}

func (s *muSuite) TestDetermineTPMKindRawBytes2(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStructWithRawByteField{}, k: TPMKindRawBytes})
}

type testStructWithRawListField struct {
	A []uint16 `tpm2:"raw"`
}

func (s *muSuite) TestDetermineTPMKindRawList(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStructWithRawListField{}, k: TPMKindRawList})
}

func (s *muSuite) TestMarshalAndUnmarshalUnionWithInvalidSelector(c *C) {
	w := testUnionContainer{Select: 259}
	b, err := MarshalToBytes(w)
	c.Check(err, IsNil)

	var uw testUnionContainer
	_, err = UnmarshalFromBytes(b, &uw)
	c.Check(err, ErrorMatches, "cannot unmarshal argument at index 0: cannot process struct type mu_test.testUnionContainer: cannot "+
		"process field Union from struct type mu_test.testUnionContainer: invalid selector value: 259")
}

func (s *muSuite) TestMarshalUnionWithIncorrectType(c *C) {
	v := testUnionContainer{Select: 1, Union: testUnion{uint16(4321)}}
	_, err := MarshalToBytes(v)
	c.Check(err, ErrorMatches, "cannot marshal argument at index 0: cannot process struct type mu_test.testUnionContainer: cannot process "+
		"field Union from struct type mu_test.testUnionContainer: data has incorrect type uint16 \\(expected \\*mu_test.testStruct\\)")
}

func (s *muSuite) TestUnmarshalZeroSizedFieldToNonNilPointer(c *C) {
	x := testStructWithSizedField{A: 56321}
	b, err := MarshalToBytes(x)
	c.Check(err, IsNil)

	ux := testStructWithSizedField{B: &testStruct{}}
	_, err = UnmarshalFromBytes(b, &ux)
	c.Check(err, ErrorMatches, "cannot unmarshal argument at index 0: cannot process struct type mu_test.testStructWithSizedField: "+
		"cannot process field B from struct type mu_test.testStructWithSizedField: cannot process sized type \\*mu_test.testStruct, "+
		"inside container type mu_test.testStructWithSizedField: sized value is zero sized, but destination value has been pre-allocated")
}

func (s *muSuite) TestUnmarshalBadSizedBuffer(c *C) {
	b := testutil.DecodeHexString(c, "ffff000000000000000000000000")
	var o []byte
	_, err := UnmarshalFromBytes(b, &o)
	c.Check(err, ErrorMatches, "cannot unmarshal argument at index 0: cannot process sized type \\[\\]uint8: sized value has a size larger than the remaining bytes")
}

func (s *muSuite) TestMarshalBadSizedBuffer(c *C) {
	x := make([]byte, 100000)
	_, err := MarshalToBytes(x)
	c.Check(err, ErrorMatches, "cannot marshal argument at index 0: cannot process sized type \\[\\]uint8: sized value size greater than 2\\^16-1")
}
