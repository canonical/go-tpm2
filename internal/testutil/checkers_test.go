// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"errors"
	"io"
	"math"
	"os"
	"reflect"

	"golang.org/x/xerrors"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2/internal/testutil"
)

func testInfo(c *C, checker Checker, name string, paramNames []string) {
	info := checker.Info()
	if info.Name != name {
		c.Fatalf("Got name %s, expected %s", info.Name, name)
	}
	if !reflect.DeepEqual(info.Params, paramNames) {
		c.Fatalf("Got param names %#v, expected %#v", info.Params, paramNames)
	}
}

func testCheck(c *C, checker Checker, result bool, error string, params ...interface{}) ([]interface{}, []string) {
	info := checker.Info()
	if len(params) != len(info.Params) {
		c.Fatalf("unexpected param count in test; expected %d got %d", len(info.Params), len(params))
	}
	names := append([]string{}, info.Params...)
	resultActual, errorActual := checker.Check(params, names)
	if resultActual != result || errorActual != error {
		c.Fatalf("%s.Check(%#v) returned (%#v, %#v) rather than (%#v, %#v)",
			info.Name, params, resultActual, errorActual, result, error)
	}
	return params, names
}

type checkersSuite struct{}

var _ = Suite(&checkersSuite{})

func (s *checkersSuite) TestInSlice(c *C) {
	testInfo(c, InSlice(Equals), "InSlice(Equals)", []string{"obtained", "[]expected"})
	testCheck(c, InSlice(Equals), true, "", 1, []int{2, 1, 5})
	testCheck(c, InSlice(Equals), false, "", 10, []int{2, 1, 5})
	testCheck(c, InSlice(Equals), true, "", "foo", []string{"foo", "bar"})
	testCheck(c, InSlice(Equals), false, "", "baz", []string{"foo", "bar"})

	c.Check(func() { testCheck(c, InSlice(IsNil), false, "") }, Panics, "InSlice must be used with a checker that requires 2 parameters")
	testCheck(c, InSlice(Equals), false, "[]expected has the wrong kind", 1, 1)
}

func (s *checkersSuite) TestIsTrue(c *C) {
	testInfo(c, IsTrue, "IsTrue", []string{"value"})
	testCheck(c, IsTrue, true, "", true)
	testCheck(c, IsTrue, false, "", false)
	testCheck(c, IsTrue, false, "value is not a bool", 1)
}

func (s *checkersSuite) TestIsFalse(c *C) {
	testInfo(c, IsFalse, "IsFalse", []string{"value"})
	testCheck(c, IsFalse, true, "", false)
	testCheck(c, IsFalse, false, "", true)
	testCheck(c, IsFalse, false, "value is not a bool", 1)
}

type testError struct {
	err error
}

func (e testError) Error() string { return "error: " + e.err.Error() }
func (e testError) Unwrap() error { return e.err }

func (s *checkersSuite) TestConvertibleTo(c *C) {
	testInfo(c, ConvertibleTo, "ConvertibleTo", []string{"value", "sample"})
	testCheck(c, ConvertibleTo, true, "", testError{}, testError{})
	testCheck(c, ConvertibleTo, false, "", &testError{}, testError{})
	testCheck(c, ConvertibleTo, false, "", testError{}, &testError{})

	var e error = testError{}
	testCheck(c, ConvertibleTo, true, "", e, testError{})
	testCheck(c, ConvertibleTo, false, "", e, errors.New(""))

	e = new(os.PathError)
	testCheck(c, ConvertibleTo, true, "", e, &os.PathError{})
	testCheck(c, ConvertibleTo, false, "", e, testError{})
}

func (s *checkersSuite) TestErrorIs(c *C) {
	testInfo(c, ErrorIs, "ErrorIs", []string{"value", "expected"})
	testCheck(c, ErrorIs, true, "", os.ErrNotExist, os.ErrNotExist)
	testCheck(c, ErrorIs, false, "", os.ErrNotExist, io.EOF)
	testCheck(c, ErrorIs, false, "value is not an error", "foo", io.EOF)
	testCheck(c, ErrorIs, false, "expected is not an error", io.EOF, "foo")
}

func (s *checkersSuite) TestErrorAs(c *C) {
	testInfo(c, ErrorAs, "ErrorAs", []string{"value", "target"})

	var e testError
	testCheck(c, ErrorAs, true, "", testError{io.EOF}, &e)
	c.Check(e, ErrorIs, io.EOF)

	testCheck(c, ErrorAs, true, "", xerrors.Errorf(": %w", testError{io.EOF}), &e)
	c.Check(e, ErrorIs, io.EOF)

	var e2 *os.PathError
	testCheck(c, ErrorAs, false, "", testError{io.EOF}, &e2)

	testCheck(c, ErrorAs, false, "value is not an error", "foo", &e)
}

func (s *checkersSuite) TestIntLess(c *C) {
	testInfo(c, IntLess, "IntLess", []string{"x", "y"})
	testCheck(c, IntLess, true, "", 5, 10)
	testCheck(c, IntLess, false, "", 10, 10)
	testCheck(c, IntLess, false, "", 10, 5)
	testCheck(c, IntLess, true, "", math.MinInt64, math.MaxInt64)
}

func (s *checkersSuite) TestIntLessEqual(c *C) {
	testInfo(c, IntLessEqual, "IntLessEqual", []string{"x", "y"})
	testCheck(c, IntLessEqual, true, "", 5, 10)
	testCheck(c, IntLessEqual, true, "", 10, 10)
	testCheck(c, IntLessEqual, false, "", 10, 5)
}

func (s *checkersSuite) TestIntEqual(c *C) {
	testInfo(c, IntEqual, "IntEqual", []string{"x", "y"})
	testCheck(c, IntEqual, false, "", 5, 10)
	testCheck(c, IntEqual, true, "", 10, 10)
	testCheck(c, IntEqual, false, "", 10, 5)
}

func (s *checkersSuite) TestIntNotEqual(c *C) {
	testInfo(c, IntNotEqual, "IntNotEqual", []string{"x", "y"})
	testCheck(c, IntNotEqual, true, "", 5, 10)
	testCheck(c, IntNotEqual, false, "", 10, 10)
	testCheck(c, IntNotEqual, true, "", 10, 5)
}

func (s *checkersSuite) TestIntGreater(c *C) {
	testInfo(c, IntGreater, "IntGreater", []string{"x", "y"})
	testCheck(c, IntGreater, false, "", 5, 10)
	testCheck(c, IntGreater, false, "", 10, 10)
	testCheck(c, IntGreater, true, "", 10, 5)
	testCheck(c, IntGreater, true, "", math.MaxInt64, math.MinInt64)
}

func (s *checkersSuite) TestIntGreaterEqual(c *C) {
	testInfo(c, IntGreaterEqual, "IntGreaterEqual", []string{"x", "y"})
	testCheck(c, IntGreaterEqual, false, "", 5, 10)
	testCheck(c, IntGreaterEqual, true, "", 10, 10)
	testCheck(c, IntGreaterEqual, true, "", 10, 5)
}

func (s *checkersSuite) TestIntChecker(c *C) {
	testCheck(c, IntEqual, false, "x has invalid kind (must be an int)", uint(10), 10)
	testCheck(c, IntEqual, false, "y has invalid kind (must be an int)", 10, uint(10))
	testCheck(c, IntEqual, false, "y cannot be represented by the type of x", int8(10), 128)
}

func (s *checkersSuite) TestUintLess(c *C) {
	testInfo(c, UintLess, "UintLess", []string{"x", "y"})
	testCheck(c, UintLess, true, "", uint(5), 10)
	testCheck(c, UintLess, false, "", uint(10), 10)
	testCheck(c, UintLess, false, "", uint(10), 5)
}

func (s *checkersSuite) TestUintLessEqual(c *C) {
	testInfo(c, UintLessEqual, "UintLessEqual", []string{"x", "y"})
	testCheck(c, UintLessEqual, true, "", uint(5), 10)
	testCheck(c, UintLessEqual, true, "", uint(10), 10)
	testCheck(c, UintLessEqual, false, "", uint(10), 5)
}

func (s *checkersSuite) TestUintEqual(c *C) {
	testInfo(c, UintEqual, "UintEqual", []string{"x", "y"})
	testCheck(c, UintEqual, false, "", uint(5), 10)
	testCheck(c, UintEqual, true, "", uint(10), 10)
	testCheck(c, UintEqual, false, "", uint(10), 5)
}

func (s *checkersSuite) TestUintNotEqual(c *C) {
	testInfo(c, UintNotEqual, "UintNotEqual", []string{"x", "y"})
	testCheck(c, UintNotEqual, true, "", uint(5), 10)
	testCheck(c, UintNotEqual, false, "", uint(10), 10)
	testCheck(c, UintNotEqual, true, "", uint(10), 5)
}

func (s *checkersSuite) TestUintGreater(c *C) {
	testInfo(c, UintGreater, "UintGreater", []string{"x", "y"})
	testCheck(c, UintGreater, false, "", uint(5), 10)
	testCheck(c, UintGreater, false, "", uint(10), 10)
	testCheck(c, UintGreater, true, "", uint(10), 5)
}

func (s *checkersSuite) TestUintGreaterEqual(c *C) {
	testInfo(c, UintGreaterEqual, "UintGreaterEqual", []string{"x", "y"})
	testCheck(c, UintGreaterEqual, false, "", uint(5), 10)
	testCheck(c, UintGreaterEqual, true, "", uint(10), 10)
	testCheck(c, UintGreaterEqual, true, "", uint(10), 5)
}

func (s *checkersSuite) TestUintChecker(c *C) {
	testCheck(c, UintEqual, false, "x has invalid kind (must be an unsigned int)", 10, 10)
	testCheck(c, UintEqual, false, "y has invalid kind (must be an unsigned int or a plain int)", uint(10), int64(10))
	testCheck(c, UintEqual, false, "y cannot be represented by the type of x", uint8(10), 256)
	testCheck(c, UintEqual, true, "", uint64(math.MaxUint64), uint64(math.MaxUint64))
}

func (s *checkersSuite) TestLenEquals(c *C) {
	testInfo(c, LenEquals, "LenEquals", []string{"value", "n"})
	testCheck(c, LenEquals, true, "", []int{0, 0, 0, 0}, 4)
	testCheck(c, LenEquals, true, "", map[int]int{0: 0, 1: 1}, 2)
	testCheck(c, LenEquals, true, "", "foo", 3)
	testCheck(c, LenEquals, true, "", [2]int{0, 0}, 2)
	testCheck(c, LenEquals, false, "actual length: 3", "foo", 4)
	testCheck(c, LenEquals, false, "value doesn't have a length", 4, 4)
}
