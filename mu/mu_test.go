// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mu_test

import (
	"bytes"
	"io"
	"math"
	"reflect"
	"testing"

	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/mu"
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

	for i, value := range data.values {
		c.Check(mu.IsValid(value), internal_testutil.IsTrue, Commentf("value %d failed", i))
	}
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

	for i, value := range data.values {
		c.Check(mu.IsValid(value), internal_testutil.IsTrue, Commentf("value %d failed", i))
	}
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

func (s *muSuite) TestMarshalAndUnmarshlRaw(c *C) {
	a := internal_testutil.DecodeHexString(c, "7a788f56fa49ae0ba5ebde780efe4d6a89b5db47")
	ua := make([]byte, len(a))

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Raw(a)},
		expected:              a,
		unmarshalDests:        []interface{}{Raw(&ua)},
		unmarshalExpectedVals: []interface{}{*Raw(&a)}})

	ua = make([]byte, len(a))

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Raw(a)},
		expected:              a,
		unmarshalDests:        []interface{}{Raw(&ua)},
		unmarshalExpectedVals: []interface{}{*Raw(&a)}})
}

func (s *muSuite) TestMarshalAndUnmarshalSizedBuffer(c *C) {
	values := []interface{}{
		internal_testutil.DecodeHexString(c, "2f74683f15431d01ea28ade26c4d009b"),
		internal_testutil.DecodeHexString(c, "9112422c"),
		testSizedBuffer(internal_testutil.DecodeHexString(c, "74465e401880e264")),
		[]byte{}}
	expected := internal_testutil.DecodeHexString(c, "00102f74683f15431d01ea28ade26c4d009b00049112422c000874465e401880e2640000")

	ua := make([]byte, 8)
	ua2 := ua
	var ub []byte
	uc := make(testSizedBuffer, 8)
	uc2 := uc
	var ud []byte

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                values,
		expected:              expected,
		unmarshalDests:        []interface{}{&ua, &ub, &uc, &ud},
		unmarshalExpectedVals: []interface{}{values[0], values[1], values[2], []byte(nil)}})
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc2, DeepEquals, uc)

	// Test that a preallocated slice is reallocated if it isn't
	// large enough
	c.Check(ua2, DeepEquals, make([]byte, 8))

	ua = make([]byte, 8)
	ua2 = ua
	ub = nil
	uc = make(testSizedBuffer, 18)
	uc2 = uc
	ud = nil

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                values,
		expected:              expected,
		unmarshalDests:        []interface{}{&ua, &ub, &uc, &ud},
		unmarshalExpectedVals: []interface{}{values[0], values[1], values[2], []byte(nil)}})
	// Test that a preallocated slice is used if it is large enough
	c.Check(uc2, DeepEquals, append(uc, make(testSizedBuffer, 10)...))

	// Test that a preallocated slice is reallocated if it isn't
	// large enough
	c.Check(ua2, DeepEquals, make([]byte, 8))
}

func (s *muSuite) TestMarshalAndUnmarshalSized(c *C) {
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

func (s *muSuite) TestMarshalAndUnmarshalSized2(c *C) {
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

func (s *muSuite) TestMarshalAndUnmarshalSized3(c *C) {
	a := &testStructWithImplicitSizedField{A: 1872244400, B: internal_testutil.DecodeHexString(c, "a5a5a5a5")}

	expected := internal_testutil.DecodeHexString(c, "000a6f982eb00004a5a5a5a5")

	var ua *testStructWithImplicitSizedField

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)

	ua = &testStructWithImplicitSizedField{}

	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{Sized(a)},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{*Sized(&a)},
		unmarshalDests:        []interface{}{Sized(&ua)}})
	c.Check(ua, DeepEquals, a)
}

func (s *muSuite) TestSizedMarshalAndUnmarshalSized4(c *C) {
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

func (s *muSuite) TestMarshalAndUnmarshalList(c *C) {
	values := []interface{}{[]uint32{46, 4563421, 678, 12390}, []uint64(nil), []uint16{59747, 22875}}
	expected := internal_testutil.DecodeHexString(c, "000000040000002e0045a1dd000002a6000030660000000000000002e963595b")

	ua := make([]uint32, 0)
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
	c.Check(ua2, DeepEquals, make([]uint32, 0))

	ua = make([]uint32, 0)
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
	c.Check(ua2, DeepEquals, make([]uint32, 0))
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
		unmarshalExpectedVals: []interface{}{a, testStruct{34963, &u32_0, false, nil}, a}})
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
		unmarshalExpectedVals: []interface{}{a, testStruct{34963, &u32_0, false, nil}, a}})
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
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion{Select: 4, Union: &testUnion{}}, testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: nil}}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion{Select: 4, Union: &testUnion{}}, testTaggedUnion{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: nil}}}}})
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
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion2{Select: 4, Union: &testUnion{}}, testTaggedUnion2{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32(nil)}}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, testTaggedUnion2{Select: 4, Union: &testUnion{}}, testTaggedUnion2{Select: 1, Union: &testUnion{A: &testStruct{B: &u32_0, D: []uint32(nil)}}}}})
}

func (s *muSuite) TestMarshalAndUnmarshalUnion3(c *C) {
	var u32 uint32 = 657763432
	v := &testTaggedUnion3{Select: 1, Union: testUnion{A: &testStruct{56324, &u32, true, []uint32{98767643, 5453423}}}}
	w := &testTaggedUnion3{Select: 2, Union: testUnion{B: []uint32{3287743, 98731}}}
	x := &testTaggedUnion3{Select: 3, Union: testUnion{C: uint16(4321)}}
	y := &testTaggedUnion3{Select: 4}
	z := &testTaggedUnion3{Select: 1} // Test that the zero value gets marshalled

	expected := internal_testutil.DecodeHexString(c, "00000001dc042734ac68010000000205e3131b0053366f000000020000000200322abf000181ab0000000310e100000004000000010000000000000000000000")

	var u32_0 uint32

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, y, &testTaggedUnion3{Select: 1, Union: testUnion{A: &testStruct{B: &u32_0, D: nil}}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{v, w, x, y, z},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{v, w, x, y, &testTaggedUnion3{Select: 1, Union: testUnion{A: &testStruct{B: &u32_0, D: nil}}}}})
}

func (s *muSuite) TestMarshalAndUnmarshalCustomMarshaller(c *C) {
	a := testCustom{A: 44332, B: []uint32{885432, 31287554}}
	expected := internal_testutil.DecodeHexString(c, "2cad00000002000d82b801dd6902")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:   []interface{}{a},
		expected: expected})
}

func (s *muSuite) TestMarshalAndUnmarshalCustomMarshaller2(c *C) {
	a := &testCustom2{A: 44332, B: []uint32{885432, 31287554}}
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

func (s *muSuite) TestMarshalAndUnmarshalStructWithIgnoredField(c *C) {
	a := testStructWithIgnoredField{A: 10, B: []uint16{50, 300}}
	expected := internal_testutil.DecodeHexString(c, "000000020032012c")

	s.testMarshalAndUnmarshalBytes(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{testStructWithIgnoredField{B: []uint16{50, 300}}}})
	s.testMarshalAndUnmarshalIO(c, &testMarshalAndUnmarshalData{
		values:                []interface{}{a},
		expected:              expected,
		unmarshalExpectedVals: []interface{}{testStructWithIgnoredField{B: []uint16{50, 300}}}})
}

func (s *muSuite) TestUnmarshalZeroSizedFieldToNonNilPointer(c *C) {
	x := testStructWithSizedField{A: 56321}
	b, err := MarshalToBytes(x)
	c.Check(err, IsNil)

	ux := testStructWithSizedField{B: &testStruct{}}
	_, err = UnmarshalFromBytes(b, &ux)
	c.Check(err, IsNil)
	c.Check(ux.B, IsNil)
}

func (s *muSuite) testDetermineTPMKind(c *C, d interface{}, expected TPMKind) {
	c.Check(DetermineTPMKind(d), Equals, expected)
}

func (s *muSuite) TestDetermineTPMKindUnsupported(c *C) {
	s.testDetermineTPMKind(c, [3]uint16{1, 2, 3}, TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported2(c *C) {
	s.testDetermineTPMKind(c, Sized(uint32(0)), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported3(c *C) {
	s.testDetermineTPMKind(c, Raw(uint32(0)), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported4(c *C) {
	s.testDetermineTPMKind(c, Sized([]uint32{}), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported5(c *C) {
	s.testDetermineTPMKind(c, Sized(testStruct{}), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported6(c *C) {
	s.testDetermineTPMKind(c, Raw(testStruct{}), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported7(c *C) {
	s.testDetermineTPMKind(c, Sized(&testUnion{}), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindUnsupported8(c *C) {
	s.testDetermineTPMKind(c, Raw(&testUnion{}), TPMKindUnsupported)
}

func (s *muSuite) TestDetermineTPMKindPrimitive1(c *C) {
	s.testDetermineTPMKind(c, uint32(0), TPMKindPrimitive)
}

func (s *muSuite) TestDetermineTPMKindPrimitive2(c *C) {
	var x uint16
	s.testDetermineTPMKind(c, &x, TPMKindPrimitive)
}

func (s *muSuite) TestDetermineTPMKindSized1(c *C) {
	s.testDetermineTPMKind(c, testSizedBuffer{}, TPMKindSized)
}

func (s *muSuite) TestDetermineTPMKindSized2(c *C) {
	s.testDetermineTPMKind(c, Sized(&testStruct{}), TPMKindSized)
}

func (s *muSuite) TestDetermineTPMKindList(c *C) {
	s.testDetermineTPMKind(c, []uint32{}, TPMKindList)
}

func (s *muSuite) TestDetermineTPMKindStruct(c *C) {
	s.testDetermineTPMKind(c, testStruct{}, TPMKindStruct)
}

func (s *muSuite) TestDetermineTPMKindTaggedUnion(c *C) {
	s.testDetermineTPMKind(c, testTaggedUnion{}, TPMKindTaggedUnion)
}

func (s *muSuite) TestDetermineTPMKindTaggedUnion2(c *C) {
	s.testDetermineTPMKind(c, testTaggedUnion3{}, TPMKindTaggedUnion)
}

func (s *muSuite) TestDetermineTPMKindUnion(c *C) {
	s.testDetermineTPMKind(c, testUnion{}, TPMKindUnion)
}

func (s *muSuite) TestDetermineTPMKindCustom(c *C) {
	s.testDetermineTPMKind(c, testCustom{}, TPMKindCustom)
}

func (s *muSuite) TestDetermineTPMKindRaw1(c *C) {
	s.testDetermineTPMKind(c, RawBytes{}, TPMKindRaw)
}

func (s *muSuite) TestDetermineTPMKindRaw2(c *C) {
	s.testDetermineTPMKind(c, Raw(testSizedBuffer{}), TPMKindRaw)
}

func (s *muSuite) TestDetermineTPMKindRaw3(c *C) {
	s.testDetermineTPMKind(c, Raw([]uint32{}), TPMKindRaw)
}

func (s *muSuite) TestErrorSimple(c *C) {
	a := make([]byte, 70000)
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument 0 whilst processing element of type \\[\\]uint8: sized value size of 70000 is larger than 2\\^16-1")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 0)

	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestErrorWithMultipleArguments(c *C) {
	a := make([]byte, 70000)
	_, err := MarshalToBytes(uint32(5), a)
	c.Check(err, ErrorMatches, "cannot marshal argument 1 whilst processing element of type \\[\\]uint8: sized value size of 70000 is larger than 2\\^16-1")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 1)
	c.Assert(e.Depth(), Equals, 0)

	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestErrorInStructContainer(c *C) {
	a := testStructWithSizedField{B: &testStruct{D: make([]uint32, 20000)}}
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument 0 whilst processing element of type \\*mu_test.testStruct: sized value size of 80011 is larger than 2\\^16-1\n\n"+
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

	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestErrorInSliceContainer(c *C) {
	a := []testStructWithSizedField{{}, {}, {B: &testStruct{D: make([]uint32, 20000)}}}
	_, err := MarshalToBytes(a)
	c.Check(err, ErrorMatches, "cannot marshal argument 0 whilst processing element of type \\*mu_test.testStruct: sized value size of 80011 is larger than 2\\^16-1\n\n"+
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

	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestErrorInSliceContainerWithMultipleArguments(c *C) {
	b := internal_testutil.DecodeHexString(c, "000000000000000300000000000000000000000000000000ffffa5a5a5a5")

	var x uint32
	var y []testStructWithSizedField

	_, err := UnmarshalFromBytes(b, &x, &y)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 1 whilst processing element of type uint32: unexpected EOF\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStruct field B\n"+
		"... mu_test.testStructWithSizedField field B\n"+
		"... \\[\\]mu_test.testStructWithSizedField index 2\n"+
		"=== END STACK ===\n")

	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 1)
	c.Assert(e.Depth(), Equals, 3)
	t, i, _ := e.Container(1)
	c.Check(t, Equals, reflect.TypeOf(testStructWithSizedField{}))
	c.Check(i, Equals, 1)
	t, i, _ = e.Container(0)
	c.Check(t, Equals, reflect.TypeOf([]testStructWithSizedField{}))
	c.Check(i, Equals, 2)
}

func (s *muSuite) TestErrorFromCustomType(c *C) {
	var a *testStructContainingCustom

	_, err := UnmarshalFromBytes(internal_testutil.DecodeHexString(c, "000000000000000000040000000000000000"), &a)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type uint32: unexpected EOF\n\n"+
		"=== BEGIN STACK ===\n"+
		"... \\[\\]uint32 index 2\n"+
		"... mu_test.testCustom location foo.go:200, argument 1\n"+
		"... mu_test.testStructContainingCustom field X\n"+
		"=== END STACK ===\n")
	c.Assert(err, internal_testutil.ConvertibleTo, &Error{})
	e := err.(*Error)
	c.Check(e.Index, Equals, 0)
	c.Assert(e.Depth(), Equals, 3)
	t, i, _ := e.Container(2)
	c.Check(t, Equals, reflect.TypeOf([]uint32{}))
	c.Check(i, Equals, 2)
	t, i, f := e.Container(1)
	c.Check(t, Equals, reflect.TypeOf(testCustom{}))
	c.Check(i, Equals, 1)
	c.Check(f.File, Equals, "foo.go")
	c.Check(f.Line, Equals, 200)
	t, i, _ = e.Container(0)
	c.Check(t, Equals, reflect.TypeOf(testStructContainingCustom{}))
	c.Check(i, Equals, 1)
}

func (s *muSuite) TestMarshalAndUnmarshalUnionWithInvalidSelector(c *C) {
	w := testTaggedUnion{Select: 259}
	b, err := MarshalToBytes(w)
	c.Check(err, IsNil)

	var uw testTaggedUnion
	_, err = UnmarshalFromBytes(b, &uw)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type mu_test.testUnion: invalid selector value: 259\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testTaggedUnion field Union\n"+
		"=== END STACK ===\n")

	var e *InvalidSelectorError
	c.Check(err, internal_testutil.ErrorAs, &e)

	c.Check(IsValid(w), internal_testutil.IsFalse)
}

func (s *muSuite) TestUnmarshalBadSizedBuffer(c *C) {
	b := internal_testutil.DecodeHexString(c, "ffff000000000000000000000000")
	var o []byte
	_, err := UnmarshalFromBytes(b, &o)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type \\[\\]uint8: unexpected EOF")
}

func (s *muSuite) TestUnmarshalBadList(c *C) {
	b := internal_testutil.DecodeHexString(c, "800000010000")
	var o []uint16
	_, err := UnmarshalFromBytes(b, &o)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type \\[\\]uint16: list length of 2147483649 is out of range")
}

func (s *muSuite) TestMarshalBadSizedBuffer(c *C) {
	x := make([]byte, 100000)
	_, err := MarshalToBytes(x)
	c.Check(err, ErrorMatches, "cannot marshal argument 0 whilst processing element of type \\[\\]uint8: sized value size of 100000 is larger than 2\\^16-1")
	c.Check(IsValid(x), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalUnionInNoStruct(c *C) {
	a := &testUnion{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "union type mu_test.testUnion is not inside a struct")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidTaggedUnion(c *C) {
	a := testInvalidTaggedUnion{A: &testUnion{}}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "selector name foo for union type mu_test.testUnion does not reference a valid field\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testInvalidTaggedUnion field A\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalNonAddressableUnion(c *C) {
	a := testTaggedUnion3{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "union type mu_test.testUnion needs to be addressable\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testTaggedUnion3 field Union\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidSizedField(c *C) {
	a := testStructWithInvalidSizedField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testStruct \\(\"sized\" option requires a pointer field\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidSizedField field A\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidRawField(c *C) {
	a := testStructWithInvalidRawField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testStruct \\(\"raw\" option is invalid with struct types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidRawField field A\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidUnionField(c *C) {
	a := testStructWithInvalidUnionField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testStruct \\(\"selector\" option is invalid with struct types that don't represent unions\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidUnionField field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalUnsupportedType(c *C) {
	a := "foo"
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type string \\(unsupported kind: string\\)")
	c.Check(IsValid(a), internal_testutil.IsFalse)
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
	a := Sized(Raw([]byte{}))
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu.wrappedValue \\(struct type with unexported fields\\)")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalUnaddressableCustom(c *C) {
	a := testCustom2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "custom type mu_test.testCustom2 needs to be addressable")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalUnaddressableCustom2(c *C) {
	a := testStructContainingCustom2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "custom type mu_test.testCustom2 needs to be addressable\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructContainingCustom2 field X\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidCustomField(c *C) {
	a := testStructContainingInvalidCustomField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testCustom \\(\"raw\", \"sized\" and \"selector\" options are invalid with custom types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructContainingInvalidCustomField field X\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidCustomField2(c *C) {
	a := testStructContainingInvalidCustomField2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testCustom \\(\"raw\", \"sized\" and \"selector\" options are invalid with custom types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructContainingInvalidCustomField2 field X\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidCustomField3(c *C) {
	a := testStructContainingInvalidCustomField3{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testCustom \\(\"raw\", \"sized\" and \"selector\" options are invalid with custom types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructContainingInvalidCustomField3 field X\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidPrimitiveField(c *C) {
	a := testStructWithInvalidPrimitiveField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type uint16 \\(\"sized\", \"raw\" and \"selector\" options are invalid with primitive types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidPrimitiveField field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidPrimitiveField2(c *C) {
	a := testStructWithInvalidPrimitiveField2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type uint16 \\(\"sized\", \"raw\" and \"selector\" options are invalid with primitive types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidPrimitiveField2 field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidPrimitiveField3(c *C) {
	a := testStructWithInvalidPrimitiveField3{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type uint16 \\(\"sized\", \"raw\" and \"selector\" options are invalid with primitive types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidPrimitiveField3 field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidSliceField(c *C) {
	a := testStructWithInvalidSliceField{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type \\[\\]uint32 \\(\"sized\" and \"selector\" options are invalid with slice types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidSliceField field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalStructContainingInvalidSliceField2(c *C) {
	a := testStructWithInvalidSliceField2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type \\[\\]uint32 \\(\"sized\" and \"selector\" options are invalid with slice types\\)\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testStructWithInvalidSliceField2 field B\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidTaggedUnion2(c *C) {
	a := testInvalidTaggedUnion2{}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "cannot marshal unsupported type mu_test.testInvalidTaggedUnion2 \\(struct type cannot represent both a union and tagged union\\)")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

func (s *muSuite) TestMarshalInvalidUnion(c *C) {
	a := testTaggedUnion{Select: math.MaxUint32}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "Union.Select implementation for type mu_test.testUnion returned a non-member pointer\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testTaggedUnion field Union\n"+
		"=== END STACK ===\n")
	c.Check(IsValid(a), internal_testutil.IsFalse)
}

type testMarshalErrorData struct {
	value      interface{}
	after      int
	checkValid bool
	err        string
}

type testBrokenWriter struct {
	limit int
	n     int
}

func (w *testBrokenWriter) Write(data []byte) (int, error) {
	w.n += len(data)
	if w.n > w.limit {
		return 0, io.ErrClosedPipe
	}
	return len(data), nil
}

func (s *muSuite) testMarshalError(c *C, data *testMarshalErrorData) {
	_, err := MarshalToWriter(&testBrokenWriter{limit: data.after}, data.value)
	c.Check(err, ErrorMatches, data.err)
	if data.checkValid {
		c.Check(IsValid(data.value), internal_testutil.IsFalse)
	}
}

func (s *muSuite) TestMarshalErrorPrimitive(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: uint16(0),
		err:   "cannot marshal argument 0 whilst processing element of type uint16: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorSized1(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: []byte{0},
		err:   "cannot marshal argument 0 whilst processing element of type \\[\\]uint8: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorSized2(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: testStructWithSizedField{B: &testStruct{}},
		after: 4,
		err: "cannot marshal argument 0 whilst processing element of type \\*mu_test.testStruct: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testStructWithSizedField field B\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorSized3(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: testStructWithSizedField{B: &testStruct{}},
		after: 6,
		err: "cannot marshal argument 0 whilst processing element of type \\*mu_test.testStruct: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testStructWithSizedField field B\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorSized4(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value:      testStructWithSizedField2{A: &testStructWithImplicitSizedField{B: make([]byte, 70000)}},
		after:      8,
		checkValid: true,
		err: "cannot marshal argument 0 whilst processing element of type \\[\\]uint8: sized value size of 70000 is larger than 2\\^16-1\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testStructWithImplicitSizedField field B\n" +
			"... mu_test.testStructWithSizedField2 field A\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorSizedNil(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: testStructWithSizedField{},
		after: 4,
		err: "cannot marshal argument 0 whilst processing element of type \\*mu_test.testStruct: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testStructWithSizedField field B\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorRawField(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: testStructWithRawTagFields{A: []uint16{0}},
		err: "cannot marshal argument 0 whilst processing element of type uint16: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... \\[\\]uint16 index 0\n" +
			"... mu_test.testStructWithRawTagFields field A\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestMarshalErrorRawBytes(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: RawBytes{0},
		err:   "cannot marshal argument 0 whilst processing element of type mu.RawBytes: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorList(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: []uint32{0},
		err:   "cannot marshal argument 0 whilst processing element of type \\[\\]uint32: io: read/write on closed pipe"})
}

func (s *muSuite) TestMarshalErrorCustom(c *C) {
	s.testMarshalError(c, &testMarshalErrorData{
		value: testCustom{},
		err: "cannot marshal argument 0 whilst processing element of type uint16: io: read/write on closed pipe\n\n" +
			"=== BEGIN STACK ===\n" +
			"... mu_test.testCustom location foo.go:150, argument 0\n" +
			"=== END STACK ===\n"})
}

func (s *muSuite) TestUnmarshalErrorList(c *C) {
	b := internal_testutil.DecodeHexString(c, "000000")
	var a []uint32
	_, err := UnmarshalFromBytes(b, &a)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type \\[\\]uint32: unexpected EOF")
}

func (s *muSuite) TestUnmarshalErrorSized(c *C) {
	b := internal_testutil.DecodeHexString(c, "00")
	var a []byte
	_, err := UnmarshalFromBytes(b, &a)
	c.Check(err, ErrorMatches, "cannot unmarshal argument 0 whilst processing element of type \\[\\]uint8: unexpected EOF")
}

func (s *muSuite) TestCopyValue(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst testStruct
	c.Check(CopyValue(&dst, src), IsNil)
	c.Check(dst, DeepEquals, testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}

type emptyInterface interface{}

func (s *muSuite) TestCopyValueToInterface(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst emptyInterface
	c.Check(CopyValue(&dst, src), IsNil)
	c.Check(dst, DeepEquals, testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}

func (s *muSuite) TestCopyValueSized(c *C) {
	src := &testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst *testStruct
	c.Check(CopyValue(&dst, Sized(src)), IsNil)
	c.Check(dst, DeepEquals, &testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}

func (s *muSuite) TestCopyValueZeroSized(c *C) {
	var src *testStruct
	var dst *testStruct
	c.Check(CopyValue(&dst, Sized(src)), IsNil)
	c.Check(dst, IsNil)
}

func (s *muSuite) TestCopyValueSizedToInterface(c *C) {
	src := &testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst emptyInterface
	c.Check(CopyValue(&dst, Sized(src)), IsNil)
	c.Check(dst, DeepEquals, &testStruct{A: 10, B: new(uint32), C: true, D: []uint32{54353, 431}})
}

func (s *muSuite) TestCopyValueZeroSizedToInterface(c *C) {
	var src *testStruct
	var dst emptyInterface
	c.Check(CopyValue(&dst, Sized(src)), IsNil)
	c.Check(dst, IsNil)
}

func (s *muSuite) TestCopyValueRaw(c *C) {
	src := []uint8{1, 2, 3, 4}
	dst := make([]uint8, len(src))
	c.Check(CopyValue(&dst, Raw(src)), IsNil)
	c.Check(dst, DeepEquals, src)
}

func (s *muSuite) TestCopyValueRawiTruncated(c *C) {
	src := []uint8{1, 2, 3, 4}
	dst := make([]uint8, 3)
	c.Check(CopyValue(&dst, Raw(src)), IsNil)
	c.Check(dst, DeepEquals, []uint8{1, 2, 3})
}

func (s *muSuite) TestCopyValueToNonPointer(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	var dst testStruct
	c.Check(func() { CopyValue(dst, src) }, PanicMatches, "cannot unmarshal to non-pointer type mu_test.testStruct")
}

func (s *muSuite) TestCopyValueToNilPointer(c *C) {
	src := testStruct{A: 10, C: true, D: []uint32{54353, 431}}
	c.Check(func() { CopyValue((*testStruct)(nil), src) }, PanicMatches, "cannot unmarshal to nil pointer of type \\*mu_test.testStruct")
}

func (s *muSuite) TestPanicFromCustom(c *C) {
	a := new(testStructContainingPanicCustom)
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "some error\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testPanicCustom\n"+
		"... mu_test.testStructContainingPanicCustom field A\n"+
		"=== END STACK ===\n")
	c.Check(func() { UnmarshalFromBytes(nil, &a) }, PanicMatches, "some error\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testPanicCustom\n"+
		"... mu_test.testStructContainingPanicCustom field A\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestPanicAcrossCustom(c *C) {
	a := new(testPanicCustom2)
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "some error\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testPanicCustom\n"+
		"... mu_test.testStructContainingPanicCustom field A\n"+
		"... mu_test.testPanicCustom2 location foo.go:550, argument 0\n"+
		"=== END STACK ===\n")
	c.Check(func() { UnmarshalFromBytes(nil, &a) }, PanicMatches, "some error\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testPanicCustom\n"+
		"... mu_test.testStructContainingPanicCustom field A\n"+
		"... mu_test.testPanicCustom2 location foo.go:600, argument 0\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestDetectRecursion(c *C) {
	a := new(testRecursiveStruct)
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "infinite recursion detected when processing type mu_test.testRecursiveStruct\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testRecursiveStruct field A\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestDetectRecursion2(c *C) {
	a := &testRecursiveStruct2{A: []*testRecursiveStruct3{&testRecursiveStruct3{A: &testRecursiveStruct2{A: []*testRecursiveStruct3{new(testRecursiveStruct3)}}}}}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "infinite recursion detected when processing type mu_test.testRecursiveStruct2\n\n"+
		"=== BEGIN STACK ===\n"+
		"... mu_test.testRecursiveStruct3 field A\n"+
		"... \\[\\]\\*mu_test.testRecursiveStruct3 index 0\n"+
		"... mu_test.testRecursiveStruct2 field A\n"+
		"=== END STACK ===\n")
}

func (s *muSuite) TestDetectRecursion3(c *C) {
	a := &testRecursiveStruct4{A: testRecursiveCustom{A: []*testRecursiveStruct4{new(testRecursiveStruct4)}}}
	c.Check(func() { MarshalToBytes(a) }, PanicMatches, "infinite recursion detected when processing type mu_test.testRecursiveStruct4\n\n"+
		"=== BEGIN STACK ===\n"+
		"... \\[\\]\\*mu_test.testRecursiveStruct4 index 0\n"+
		"... mu_test.testRecursiveCustom location foo.go:750, argument 0\n"+
		"... mu_test.testRecursiveStruct4 field A\n"+
		"=== END STACK ===\n")
}
