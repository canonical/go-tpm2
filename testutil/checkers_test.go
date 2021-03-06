// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"reflect"

	. "github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
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

	testCheck(c, InSlice(IsNil), false, "InSlice can only be used with checkers that require 2 parameters", nil, nil)
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
