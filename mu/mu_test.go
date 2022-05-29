// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu_test

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
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
		expected: internal_testutil.DecodeHexString(c, "04840102b8290c00")}
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
		expected:              internal_testutil.DecodeHexString(c, "02b8290c010000"),
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
	a := internal_testutil.DecodeHexString(c, "7a788f56fa49ae0ba5ebde780efe4d6a89b5db47")
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

func (s *muSuite) TestMarshalAndUnmarshalSizedBuffer(c *C) {
	a := internal_testutil.DecodeHexString(c, "2f74683f15431d01ea28ade26c4d009b")
	ua := make([]byte, 8)
	ua2 := ua

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{a},
		expected:       append(internal_testutil.DecodeHexString(c, "0010"), a...),
		unmarshalDests: []interface{}{&ua}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(ua2, DeepEquals, make([]byte, 8))

	ua3 := make(testSizedBuffer, len(a)+10)
	ua4 := ua3

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         []interface{}{testSizedBuffer(a)},
		expected:       append(internal_testutil.DecodeHexString(c, "0010"), a...),
		unmarshalDests: []interface{}{&ua3}})
	// Test that unmarshalling in to a pre-allocated slice causes it to be reallocated
	c.Check(ua4, DeepEquals, make(testSizedBuffer, len(a)+10))
}

func (s *muSuite) TestMarshalAndUnmarshalList(c *C) {
	values := []interface{}{[]uint32{46, 4563421, 678, 12390}, []uint64{}, []uint16{59747, 22875}}
	expected := internal_testutil.DecodeHexString(c, "000000040000002e0045a1dd000002a6000030660000000000000002e963595b")

	ua := make([]uint32, 1)
	ua2 := ua
	var ub []uint64
	uc := make([]uint16, 2)
	uc2 := uc

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:         values,
		expected:       expected,
		unmarshalDests: []interface{}{&ua, &ub, &uc}})
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc2, DeepEquals, uc)

	// Test that a preallocated slice is reallocated if it isn't
	// large enough
	c.Check(ua2, DeepEquals, make([]uint32, 1))

	ua = make([]uint32, 1)
	ua2 = ua
	ub = nil
	uc = make([]uint16, 10)
	uc2 = uc

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:         values,
		expected:       expected,
		unmarshalDests: []interface{}{&ua, &ub, &uc}})
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc2, DeepEquals, append(uc, make([]uint16, 8)...))

	// Test that a preallocated slice is reallocated if it isn't
	// large enough
	c.Check(ua2, DeepEquals, make([]uint32, 1))
}

func (s *muSuite) TestMarshalAndUnmarshalStruct(c *C) {
	var u32 uint32 = 657763432
	var u32_0 uint32

	a := testStruct{56324, &u32, true, []uint32{4232, 567785}}
	b := testStruct{34963, nil, false, []uint32{}}
	expected := internal_testutil.DecodeHexString(c, "dc042734ac680100000002000010880008a9e98893000000000000000000dc042734ac680100000002000010880008a9e9")

	var uc_b uint32
	var ua testStruct
	var ub testStruct
	uc := testStruct{B: &uc_b, D: make([]uint32, 4)}
	uc_d := uc.D

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a, b, &a},
		expected:              expected,
		unmarshalDests:        []interface{}{&ua, &ub, &uc},
		unmarshalExpectedVals: []interface{}{a, testStruct{34963, &u32_0, false, []uint32{}}, a}})
	// Make sure that unmashal didn't allocate a new value when it was passed a non-nil pointer
	c.Check(uc_b, Equals, u32)
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc_d, DeepEquals, append(uc.D, make([]uint32, 2)...))

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
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc_d, DeepEquals, append(uc.D, make([]uint32, 8)...))
}

func (s *muSuite) TestMarshalAndUnmarshalWithRawTag(c *C) {
	a := testStructWithRawTagFields{A: []uint16{56, 453, 3233}, B: internal_testutil.DecodeHexString(c, "faf556442bec56fe94f51e1381d1b26a")}
	expected := internal_testutil.DecodeHexString(c, "003801c50ca1faf556442bec56fe94f51e1381d1b26a")

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
	a := testStructWithRawTagFields{A: []uint16{56, 453, 3233}, B: internal_testutil.DecodeHexString(c, "faf556442bec56fe94f51e1381d1b26a")}
	expected := internal_testutil.DecodeHexString(c, "003801c50ca1faf556442bec56fe94f51e1381d1b26a")

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

func (s *muSuite) TestMarshalAndUnmarshalSizedStruct(c *C) {
	var u32 uint32 = 657763432
	a := testStructWithSizedField{A: 1872244400, B: &testStruct{56324, &u32, true, []uint32{4232, 567785}}}
	b := testStructWithSizedField{A: 21213504}

	expected := internal_testutil.DecodeHexString(c, "6f982eb00013dc042734ac680100000002000010880008a9e90143b1400000")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a, b},
		expected: expected})

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a, b},
		expected: expected})
}

func (s *muSuite) TestMarshalAndUnmarshalUnion(c *C) {
	var u32 uint32 = 657763432
	v := testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{56324, &u32, true, []uint32{98767643, 5453423}}}}
	w := testTaggedUnion{Select: 2, Union: &testUnion{B: []uint32{3287743, 98731}}}
	x := testTaggedUnion{Select: 3, Union: &testUnion{C: uint16(4321)}}
	y := testTaggedUnion{Select: 4}
	z := testTaggedUnion{Select: 1} // Test that the zero value gets marshalled

	expected := internal_testutil.DecodeHexString(c, "00000001dc042734ac68010000000205e3131b0053366f000000020000000200322abf000181ab0000000310e100000004000000010000000000000000000000")

	var u32_0 uint32

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion{Select: 4, Union: &testUnion{}}, testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32{}}}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion{Select: 4, Union: &testUnion{}}, testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32{}}}}}})
}

func (s *muSuite) TestMarshalAndUnmarshalUnionUsingSelectField(c *C) {
	var u32 uint32 = 657763432
	v := testTaggedUnion2{Select: 1, Union: &testUnion{A: &testStruct{56324, &u32, true, []uint32{98767643, 5453423}}}}
	w := testTaggedUnion2{Select: 2, Union: &testUnion{B: []uint32{3287743, 98731}}}
	x := testTaggedUnion2{Select: 3, Union: &testUnion{C: uint16(4321)}}
	y := testTaggedUnion2{Select: 4}
	z := testTaggedUnion2{Select: 1} // Test that the zero value gets marshalled

	expected := internal_testutil.DecodeHexString(c, "00000001dc042734ac68010000000205e3131b0053366f000000020000000200322abf000181ab0000000310e100000004000000010000000000000000000000")

	var u32_0 uint32

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion2{Select: 4, Union: &testUnion{}}, testTaggedUnion2{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32{}}}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion2{Select: 4, Union: &testUnion{}}, testTaggedUnion2{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32{}}}}}})
}

func (s *muSuite) TestMarshalAndUnmarshalCustomMarshaller(c *C) {
	a := testStructWithCustomMarshaller{A: 44332, B: []uint32{885432, 31287554}}
	expected := internal_testutil.DecodeHexString(c, "2cad00000002000d82b801dd6902")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
}

func (s *muSuite) TestMarshalAndUnmarshalSizedTypeInsideRawSlice(c *C) {
	a := testStructWithRawTagSizedFields{A: [][]byte{internal_testutil.DecodeHexString(c, "a5a5a5"), internal_testutil.DecodeHexString(c, "4d4d4d4d")}}
	expected := internal_testutil.DecodeHexString(c, "0003a5a5a500044d4d4d4d")

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

func (s *muSuite) TestSized(c *C) {
	var u32 uint32 = 657763432
	a := &testStruct{56324, &u32, true, []uint32{4232, 567785}}
	expected := internal_testutil.DecodeHexString(c, "0013dc042734ac680100000002000010880008a9e9")

	var ua *testStruct

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)

	ua = &testStruct{}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)
}

func (s *muSuite) TestSized2(c *C) {
	var u32 uint32 = 657763432
	a := &testStructWithSizedField{A: 1872244400, B: &testStruct{56324, &u32, true, []uint32{4232, 567785}}}

	expected := internal_testutil.DecodeHexString(c, "00196f982eb00013dc042734ac680100000002000010880008a9e9")

	var ua *testStructWithSizedField

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)

	ua = &testStructWithSizedField{}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)
}

func (s *muSuite) TestSized3(c *C) {
	a := &testStructWithSizedField3{A: 1872244400, B: internal_testutil.DecodeHexString(c, "a5a5a5a5")}

	expected := internal_testutil.DecodeHexString(c, "000a6f982eb00004a5a5a5a5")

	var ua *testStructWithSizedField3

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)

	ua = &testStructWithSizedField3{}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)
}

func (s *muSuite) TestSized4(c *C) {
	var u32 uint32 = 657763432
	a := &testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{56324, &u32, true, []uint32{98767643, 5453423}}}}
	expected := internal_testutil.DecodeHexString(c, "001700000001dc042734ac68010000000205e3131b0053366f")

	var ua *testTaggedUnion

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)

	ua = &testTaggedUnion{}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)
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

func (s *muSuite) TestDetermineTPMKindUnsupported2(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Sized(uint32(0)), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported3(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Raw(uint32(0)), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported4(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Sized([]uint32{}), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported5(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Sized(testStruct{}), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported6(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Raw(testStruct{}), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported7(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Sized(&testUnion{}), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindUnsupported8(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Raw(&testUnion{}), k: TPMKindUnsupported})
}

func (s *muSuite) TestDetermineTPMKindPrimitive(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: uint32(10), k: TPMKindPrimitive})
}

func (s *muSuite) TestDetermineTPMKindSized1(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testSizedBuffer{}, k: TPMKindSized})
}

func (s *muSuite) TestDetermineTPMKindSized2(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Sized(&testStruct{}), k: TPMKindSized})
}

func (s *muSuite) TestDetermineTPMKindList(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: []uint32{}, k: TPMKindList})
}

func (s *muSuite) TestDetermineTPMKindStruct(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStruct{}, k: TPMKindStruct})
}

func (s *muSuite) TestDetermineTPMKindTaggedUnion(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testTaggedUnion{}, k: TPMKindTaggedUnion})
}

func (s *muSuite) TestDetermineTPMKindUnion(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testUnion{}, k: TPMKindUnion})
}

func (s *muSuite) TestDetermineTPMKindCustom(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: testStructWithCustomMarshaller{}, k: TPMKindCustom})
}

func (s *muSuite) TestDetermineTPMKindRaw1(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: RawBytes{}, k: TPMKindRaw})
}

func (s *muSuite) TestDetermineTPMKindRaw2(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Raw(testSizedBuffer{}), k: TPMKindRaw})
}

func (s *muSuite) TestDetermineTPMKindRaw3(c *C) {
	s.testDetermineTPMKind(c, &testDetermineTPMKindData{d: Raw([]uint32{}), k: TPMKindRaw})
}

func (s *muSuite) TestErrorSimple(c *C) {
	a := make([]byte, 70000)
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument whilst processing element of type \\[\\]uint8: sized value size of 70000 is larger than 2\\^16-1")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 0)
}

func (s *muSuite) TestErrorWithMultipleArguments(c *C) {
	a := make([]byte, 70000)
	_, err := MarshalToBytes(uint32(5), a)
	c.Check(err, ErrorMatches, "cannot marshal argument 1 whilst processing element of type \\[\\]uint8: sized value size of 70000 is larger than 2\\^16-1")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 1)
	c.Assert(e.Depth(), Equals, 0)
}

func (s *muSuite) TestErrorInStructContainer(c *C) {
	a := testStructWithSizedField{B: &testStruct{D: make([]uint32, 20000)}}
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument whilst processing element of type \\*mu_test.testStruct: sized value size of 80011 is larger than 2\\^16-1\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithSizedField field B\n"+
		"=== END STACK ===\n")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 1)
	t, i, _ := e.Container(0)
	c.Check(t, Equals, reflect.TypeOf(testStructWithSizedField{}))
	c.Check(i, Equals, 1)
}

func (s *muSuite) TestErrorInSliceContainer(c *C) {
	a := []testStructWithSizedField{{}, {}, {B: &testStruct{D: make([]uint32, 20000)}}}
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument whilst processing element of type \\*mu_test.testStruct: sized value size of 80011 is larger than 2\\^16-1\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithSizedField field B\n"+
		"... \\[\\]mu_test.testStructWithSizedField index 2\n"+
		"=== END STACK ===\n")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 2)
	t, i, _ := e.Container(1)
	c.Check(t, Equals, reflect.TypeOf(testStructWithSizedField{}))
	c.Check(i, Equals, 1)
	t, i, _ = e.Container(0)
	c.Check(t, Equals, reflect.TypeOf([]testStructWithSizedField{}))
	c.Check(i, Equals, 2)
}

func (s *muSuite) TestErrorInSliceContainerWithMultipleArguments(c *C) {
	b := internal_testutil.DecodeHexString(c, "000000000000000300000000000000000000000000000000ffffa5a5a5a5")

	var x uint32
	var y []testStructWithSizedField

	_, err := UnmarshalFromBytes(b, &x, &y)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 1 whilst processing element of type \\*mu_test.testStruct: sized value has a size of 65535 bytes which is larger than the 4 remaining bytes\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithSizedField field B\n"+
		"... \\[\\]mu_test.testStructWithSizedField index 2\n"+
		"=== END STACK ===\n")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 1)
	c.Assert(e.Depth(), Equals, 2)
	t, i, _ := e.Container(1)
	c.Check(t, Equals, reflect.TypeOf(testStructWithSizedField{}))
	c.Check(i, Equals, 1)
	t, i, _ = e.Container(0)
	c.Check(t, Equals, reflect.TypeOf([]testStructWithSizedField{}))
	c.Check(i, Equals, 2)
}

func (s *muSuite) TestErrorFromCustomType(c *C) {
	var a *testStructContainingCustomType

	_, err := UnmarshalFromBytes(internal_testutil.DecodeHexString(c, "000000000000000000040000000000000000"), &a)
	c.Check(err, ErrorMatches, "cannot unmarshal argument whilst processing element of type uint32: unexpected EOF\n\n"+
		"=== BEGIN STACK ===\n"+
		"... \\[\\]uint32 index 2\n"+
		"... mu_test.testStructWithCustomMarshaller custom type, call from mu_test.go:200 argument 1\n"+
		"... mu_test.testStructContainingCustomType field X\n"+
		"=== END STACK ===\n")
	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 3)
	t, i, _ := e.Container(2)
	c.Check(t, Equals, reflect.TypeOf([]uint32{}))
	c.Check(i, Equals, 2)
	t, i, f := e.Container(1)
	c.Check(t, Equals, reflect.TypeOf(testStructWithCustomMarshaller{}))
	c.Check(i, Equals, 1)
	c.Check(f.File, Equals, "mu_test.go")
	c.Check(f.Line, Equals, 200)
	t, i, _ = e.Container(0)
	c.Check(t, Equals, reflect.TypeOf(testStructContainingCustomType{}))
	c.Check(i, Equals, 1)
}

func (s *muSuite) TestMarshalAndUnmarshalUnionWithInvalidSelector(c *C) {
	w := testTaggedUnion{Select: 259}
	b, err := MarshalToBytes(w)
	c.Check(err, IsNil)

	var uw testTaggedUnion
	_, err = UnmarshalFromBytes(b, &uw)
	c.Check(err, ErrorMatches, "cannot unmarshal argument whilst processing element of type mu_test.testUnion: invalid selector value: 259\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testTaggedUnion field Union\n"+
		"=== END STACK ===\n")

	var e *InvalidSelectorError
	c.Check(err, internal_testutil.ErrorAs, &e)
}

func (s *muSuite) TestUnmarshalZeroSizedFieldToNonNilPointer(c *C) {
	x := testStructWithSizedField{A: 56321}
	b, err := MarshalToBytes(x)
	c.Check(err, IsNil)

	ux := testStructWithSizedField{B: &testStruct{}}
	_, err = UnmarshalFromBytes(b, &ux)
	c.Check(err, ErrorMatches, "cannot unmarshal argument whilst processing element of type \\*mu_test.testStruct: sized value is zero sized, but destination value has been pre-allocated\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithSizedField field B\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestUnmarshalBadSizedBuffer(c *C) {
	b := internal_testutil.DecodeHexString(c, "ffff000000000000000000000000")
	var o []byte
	_, err := UnmarshalFromBytes(b, &o)
	c.Check(err, ErrorMatches, "cannot unmarshal argument whilst processing element of type \\[\\]uint8: sized value has a size of 65535 bytes which is larger than the 12 remaining bytes")
}

func (s *muSuite) TestMarshalBadSizedBuffer(c *C) {
	x := make([]byte, 100000)
	_, err := MarshalToBytes(x)
	c.Check(err, ErrorMatches, "cannot marshal argument whilst processing element of type \\[\\]uint8: sized value size of 100000 is larger than 2\\^16-1")
}

func (s *muSuite) TestMarshalUnionInNoStruct(c *C) {
	a := &testUnion{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "union type mu_test.testUnion is not inside a struct")
}

func (s *muSuite) TestMarshalUnionInInvalidContainer2(c *C) {
	a := testInvalidTaggedUnion{&testUnion{}}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "selector name foo for union type mu_test.testUnion does not reference a valid field\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testInvalidTaggedUnion field A\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestMarshalInvalidSizedField(c *C) {
	a := testStructWithInvalidSizedField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testStruct \\(\"sized\" option requires a pointer field\\)")
}

func (s *muSuite) TestMarshalUnsupportedType(c *C) {
	a := "foo"
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type string \\(unsupported kind: string\\)")
}

func (s *muSuite) TestUnmarshalUnsupportedType(c *C) {
	var a [3]uint16
	c.Check(func() { UnmarshalFromBytes([]byte{}, &a) }, PanicMatches, "cannot unmarshal unsupported type \\[3\\]uint16 \\(unsupported kind: array\\)")
}

func (s *muSuite) TestUnmarshalValue(c *C) {
	var a uint16
	c.Check(func() { UnmarshalFromBytes([]byte{}, a) }, PanicMatches, "cannot unmarshal to non-pointer type uint16")
}

func (s *muSuite) TestUnmarshalNilInterface(c *C) {
	var a interface{}
	c.Check(func() { UnmarshalFromBytes([]byte{}, a) }, PanicMatches, "cannot unmarshal to non-pointer type \\%!s\\(<nil>\\)")
}

func (s *muSuite) TestUnmarshalToNilPointer(c *C) {
	var a *uint16
	c.Check(func() { UnmarshalFromBytes([]byte{}, a) }, PanicMatches, "cannot unmarshal to nil pointer of type \\*uint16")
}

func (s *muSuite) TestMarshalSizedAndRaw(c *C) {
	c.Check(func() { MarshalToBytes(Sized(Raw([]byte{}))) }, PanicMatches, "cannot marshal unsupported type mu.wrappedValue \\(struct type with unexported fields\\)")
}

type testMarshalErrorData struct {
	value interface{}
	err   string
}

type testBrokenWriter struct{}

func (*testBrokenWriter) Write(data []byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func (s *muSuite) testMarshalError(c *C, data *testMarshalErrorData) {
	_, err := MarshalToWriter(&testBrokenWriter{}, data.value)
	c.Check(err, ErrorMatches, data.err)
}

func (s *muSuite) TestMarshalErrorPrimitive(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		uint16(0),
		"cannot marshal argument whilst processing element of type uint16: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorSized1(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		[]byte{0},
		"cannot marshal argument whilst processing element of type \\[\\]uint8: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorSized2(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		testStructWithSizedField2{A: &testStruct{}},
		"cannot marshal argument whilst processing element of type \\*mu_test.testStruct: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testStructWithSizedField2 field A\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorRawField(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		testStructWithRawTagFields{A: []uint16{0}},
		"cannot marshal argument whilst processing element of type uint16: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... \\[\\]uint16 index 0\n" +
			"... mu_test.testStructWithRawTagFields field A\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorRawBytes(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		RawBytes{0},
		"cannot marshal argument whilst processing element of type mu.RawBytes: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorList(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		[]uint32{0},
		"cannot marshal argument whilst processing element of type \\[\\]uint32: io: read/write on closed pipe"})
}

func (s *muSuite) TestCopyValue(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst testStruct
	c.Check(CopyValue(&dst, src), IsNil)
	c.Check(dst, DeepEquals, testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}

type emptyInterface interface{}

func (s *muSuite) TestCopyValue2(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst emptyInterface
	c.Check(CopyValue(&dst, src), IsNil)
	c.Check(dst, DeepEquals, testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}
