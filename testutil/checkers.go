// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"reflect"

	. "gopkg.in/check.v1"
)

type sliceContainsChecker struct {
	*CheckerInfo
}

var SliceContains Checker = &sliceContainsChecker{
	&CheckerInfo{Name: "SliceContains", Params: []string{"value", "slice"}}}

func (checker *sliceContainsChecker) Check(params []interface{}, names []string) (result bool, error string) {
	list := reflect.ValueOf(params[1])
	if list.Kind() != reflect.Slice {
		return false, names[1] + "has the wrong kind"
	}
	if reflect.TypeOf(params[0]) != list.Type().Elem() {
		return false, names[0] + "has the wrong type"
	}
	for i := 0; i < list.Len(); i++ {
		if params[0] == list.Index(i).Interface() {
			return true, ""
		}
	}
	return false, ""
}

type isTrueChecker struct {
	*CheckerInfo
}

var IsTrue Checker = &isTrueChecker{
	&CheckerInfo{Name: "IsTrue", Params: []string{"value"}}}

func (checker *isTrueChecker) Check(params []interface{}, names []string) (result bool, error string) {
	value := reflect.ValueOf(params[0])
	if value.Kind() != reflect.Bool {
		return false, names[0] + "is not a bool"
	}
	return value.Bool(), ""
}

type isFalseChecker struct {
	Checker
}

var IsFalse Checker = &isFalseChecker{IsTrue}

func (checker *isFalseChecker) Check(params []interface{}, names []string) (result bool, error string) {
	r, err := checker.Checker.Check(params, names)
	return !r, err
}
