// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"errors"
	"fmt"
	"reflect"

	. "gopkg.in/check.v1"
)

type isOneOfChecker struct {
	sub Checker
}

func (checker *isOneOfChecker) Info() *CheckerInfo {
	info := *checker.sub.Info()
	info.Name = "IsOneOf(" + info.Name + ")"
	info.Params = append([]string{}, info.Params...)
	if len(info.Params) > 2 {
		info.Params = info.Params[:2]
	}
	if len(info.Params) == 2 {
		info.Params[1] = "[]" + info.Params[1]
	} else {
		info.Params = append(info.Params, "[]expected")
	}
	return &info
}

func (checker *isOneOfChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(checker.sub.Info().Params) != 2 {
		return false, "IsOneOf must be used with a checker that requires 2 parameters"
	}

	slice := reflect.ValueOf(params[1])
	if slice.Kind() != reflect.Slice {
		return false, names[1] + " has the wrong kind"
	}

	for i := 0; i < slice.Len(); i++ {
		if result, _ := checker.sub.Check([]interface{}{params[0], slice.Index(i).Interface()}, []string{names[0], checker.sub.Info().Params[1]}); result {
			return true, ""
		}
	}
	return false, ""
}

// IsOneOf determines whether a value is contained in the provided slice, using
// the specified checker.
//
// For example:
//
//	c.Check(value, IsOneOf(Equals), []int{1, 2, 3})
func IsOneOf(checker Checker) Checker {
	return &isOneOfChecker{checker}
}

type isTrueChecker struct {
	*CheckerInfo
}

// IsTrue determines whether a boolean value is true.
var IsTrue Checker = &isTrueChecker{
	&CheckerInfo{Name: "IsTrue", Params: []string{"value"}}}

func (checker *isTrueChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value, ok := params[0].(bool)
	if !ok {
		return false, names[0] + " is not a bool"
	}
	return value, ""
}

type isFalseChecker struct {
	*CheckerInfo
}

// IsFalse determines whether a boolean value is false.
var IsFalse Checker = &isFalseChecker{
	&CheckerInfo{Name: "IsFalse", Params: []string{"value"}}}

func (checker *isFalseChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value, ok := params[0].(bool)
	if !ok {
		return false, names[0] + " is not a bool"
	}
	return !value, ""
}

type convertibleToChecker struct {
	*CheckerInfo
}

// ConvertibleTo determines whether a value of one type can
// be converted to another type.
//
// For example:
//
//	c.Check(err, ConvertibleTo, *os.PathError{})
var ConvertibleTo Checker = &convertibleToChecker{
	&CheckerInfo{Name: "ConvertibleTo", Params: []string{"value", "sample"}}}

func (checker *convertibleToChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value := reflect.ValueOf(params[0])
	sample := reflect.ValueOf(params[1])

	if !value.IsValid() {
		return false, ""
	}
	if !sample.IsValid() {
		return false, "invalid sample value"
	}

	return value.Type().ConvertibleTo(sample.Type()), ""
}

type errorIsChecker struct {
	*CheckerInfo
}

// ErrorIs determines whether any error in a chain has a specific
// value, using errors.Is
//
// For example:
//
//	c.Check(err, ErrorIs, io.EOF)
var ErrorIs Checker = &errorIsChecker{
	&CheckerInfo{Name: "ErrorIs", Params: []string{"value", "expected"}}}

func (checker *errorIsChecker) Check(params []interface{}, names []string) (result bool, errStr string) {
	err, ok := params[0].(error)
	if !ok {
		return false, "value is not an error"
	}

	expected, ok := params[1].(error)
	if !ok {
		return false, "expected is not an error"
	}

	return errors.Is(err, expected), ""
}

type errorAsChecker struct {
	*CheckerInfo
}

// ErrorAs determines whether any error in a chain has a specific
// type, using errors.As.
//
// For example:
//
//	var e *os.PathError
//	c.Check(err, ErrorAs, &e)
//	c.Check(e.Path, Equals, "/foo/bar")
var ErrorAs Checker = &errorAsChecker{
	&CheckerInfo{Name: "ErrorAs", Params: []string{"value", "target"}}}

func (checker *errorAsChecker) Check(params []interface{}, names []string) (result bool, errStr string) {
	err, ok := params[0].(error)
	if !ok {
		return false, "value is not an error"
	}

	return errors.As(err, params[1]), ""
}

type intChecker struct {
	*CheckerInfo
}

func (checker *intChecker) Check(params []interface{}, names []string) (result bool, err string) {
	x := reflect.ValueOf(params[0])
	switch x.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	default:
		return false, names[0] + " has invalid kind (must be an int)"
	}

	y := reflect.ValueOf(params[1])
	switch y.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
	default:
		return false, names[1] + " has invalid kind (must be an int)"
	}

	y64 := y.Convert(reflect.TypeOf(int64(0))).Interface().(int64)
	if x.OverflowInt(y64) {
		return false, names[1] + " cannot be represented by the type of " + names[0]
	}

	x64 := x.Convert(reflect.TypeOf(int64(0))).Interface().(int64)

	switch checker.Name {
	case "IntLess":
		return x64 < y64, ""
	case "IntLessEqual":
		return x64 <= y64, ""
	case "IntEqual":
		return x64 == y64, ""
	case "IntNotEqual":
		return x64 != y64, ""
	case "IntGreater":
		return x64 > y64, ""
	case "IntGreaterEqual":
		return x64 >= y64, ""
	default:
		return false, "unexpected name " + checker.Name
	}
}

// IntLess checks that x is less than y. Both values must be an
// integer kind. They don't have to have the same type, although
// y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntLess, 10)
var IntLess Checker = &intChecker{
	&CheckerInfo{Name: "IntLess", Params: []string{"x", "y"}}}

// IntLessEqual checks that x is less than or equal to y. Both values
// must be an integer kind. They don't have to have the same type,
// although y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntLessEqual, 10)
var IntLessEqual Checker = &intChecker{
	&CheckerInfo{Name: "IntLessEqual", Params: []string{"x", "y"}}}

// IntEqual checks that x is equal to y. Both values must be an
// integer kind. They don't have to have the same type, although y
// must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntEqual, 10)
var IntEqual Checker = &intChecker{
	&CheckerInfo{Name: "IntEqual", Params: []string{"x", "y"}}}

// IntNotEqual checks that x is not equal to y. Both values must be
// an integer kind. They don't have to have the same type, although y
// must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntNotEqual, 10)
var IntNotEqual Checker = &intChecker{
	&CheckerInfo{Name: "IntNotEqual", Params: []string{"x", "y"}}}

// IntGreater checks that x is greater than y. Both values must be an
// integer kind. They don't have to have the same type, although y
// must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntGreater, 10)
var IntGreater Checker = &intChecker{
	&CheckerInfo{Name: "IntGreater", Params: []string{"x", "y"}}}

// IntGreaterEqual checks that x is greater than or equal to y. Both
// values must be an integer kind. They don't have to have the same type,
// although y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, IntGreaterEqual, 10)
var IntGreaterEqual Checker = &intChecker{
	&CheckerInfo{Name: "IntGreaterEqual", Params: []string{"x", "y"}}}

type uintChecker struct {
	*CheckerInfo
}

func (checker *uintChecker) Check(params []interface{}, names []string) (result bool, err string) {
	x := reflect.ValueOf(params[0])
	switch x.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return false, names[0] + " has invalid kind (must be an unsigned int)"
	}

	y := reflect.ValueOf(params[1])
	switch y.Kind() {
	case reflect.Int:
		// Allow y to be an int to simplify test writing
		if y.Convert(reflect.TypeOf(int(0))).Interface().(int) < 0 {
			return false, names[1] + " cannot be negative"
		}
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
	default:
		return false, names[1] + " has invalid kind (must be an unsigned int or a plain int)"
	}

	y64 := y.Convert(reflect.TypeOf(uint64(0))).Interface().(uint64)
	if x.OverflowUint(y64) {
		return false, names[1] + " cannot be represented by the type of " + names[0]
	}

	x64 := x.Convert(reflect.TypeOf(uint64(0))).Interface().(uint64)

	switch checker.Name {
	case "UintLess":
		return x64 < y64, ""
	case "UintLessEqual":
		return x64 <= y64, ""
	case "UintEqual":
		return x64 == y64, ""
	case "UintNotEqual":
		return x64 != y64, ""
	case "UintGreater":
		return x64 > y64, ""
	case "UintGreaterEqual":
		return x64 >= y64, ""
	default:
		return false, "unexpected name " + checker.Name
	}
}

// UintLess checks that x is less than y. Both values must be an
// unsigned integer kind. They don't have to have the same type,
// although y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintLess, 10)
var UintLess Checker = &uintChecker{
	&CheckerInfo{Name: "UintLess", Params: []string{"x", "y"}}}

// UintLessEqual checks that x is less than or equal to y. Both values
// must be an unsigned integer kind. They don't have to have the same
// type, although y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintLessEqual, 10)
var UintLessEqual Checker = &uintChecker{
	&CheckerInfo{Name: "UintLessEqual", Params: []string{"x", "y"}}}

// UintEqual checks that x is equal to y. Both values must be an
// unsigned integer kind. They don't have to have the same type, although
// y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintEqual, 10)
var UintEqual Checker = &uintChecker{
	&CheckerInfo{Name: "UintEqual", Params: []string{"x", "y"}}}

// UintNotEqual checks that x is not equal to y. Both values must be
// an unsigned integer kind. They don't have to have the same type, although
// y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintNotEqual, 10)
var UintNotEqual Checker = &uintChecker{
	&CheckerInfo{Name: "UintNotEqual", Params: []string{"x", "y"}}}

// UintGreater checks that x is greater than y. Both values must be an
// unsigned integer kind. They don't have to have the same type, although y
// must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintGreater, 10)
var UintGreater Checker = &uintChecker{
	&CheckerInfo{Name: "UintGreater", Params: []string{"x", "y"}}}

// UintGreaterEqual checks that x is greater than or equal to y. Both
// values must be an unsigned integer kind. They don't have to have the
// same type, although y must be representable by the type of x.
//
// For example:
//
//	c.Check(x, UintGreaterEqual, 10)
var UintGreaterEqual Checker = &uintChecker{
	&CheckerInfo{Name: "UintGreaterEqual", Params: []string{"x", "y"}}}

type hasLenChecker struct {
	*CheckerInfo
	cmp Checker
}

func (checker *hasLenChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value := reflect.ValueOf(params[0])
	switch value.Kind() {
	case reflect.Array, reflect.Chan, reflect.Map, reflect.Slice, reflect.String:
	default:
		return false, "value doesn't have a length"
	}

	result, error = checker.cmp.Check([]interface{}{value.Len(), params[1]}, []string{"len", names[1]})
	if !result && error == "" {
		error = fmt.Sprintf("actual length: %d", value.Len())
	}
	return result, error
}

// LenEquals checks that the value has the specified length. This differs from
// check.HasLen in that it returns an error string containing the actual length
// if the check fails.
//
// For example:
//
//	c.Check(value, LenEquals, 5)
var LenEquals Checker = &hasLenChecker{
	&CheckerInfo{Name: "LenEquals", Params: []string{"value", "n"}}, IntEqual}
