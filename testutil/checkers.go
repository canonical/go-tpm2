// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"reflect"

	. "gopkg.in/check.v1"
)

type inSliceChecker struct {
	sub Checker
}

func (checker *inSliceChecker) Info() *CheckerInfo {
	info := *checker.sub.Info()
	info.Name = "InSlice(" + info.Name + ")"
	info.Params = append([]string{}, info.Params...)
	if len(info.Params) >= 2 {
		info.Params[1] = "[]" + info.Params[1]
	} else {
		info.Params = append(info.Params, "[]expected")
	}
	info.Params = info.Params[:2]
	return &info
}

func (checker *inSliceChecker) Check(params []interface{}, names []string) (result bool, error string) {
	if len(params) != len(checker.sub.Info().Params) {
		return false, "InSlice can only be used with checkers that require 2 parameters"
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

// InSlice determines whether a value is contained in the provided slice, using
// the specified checker.
//
// For example:
//
//  c.Check(value, InSlice(Equals), []int{1, 2, 3})
//
func InSlice(checker Checker) Checker {
	return &inSliceChecker{checker}
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
//  c.Check(err, ConvertibleTo, *os.PathError{})
//
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
