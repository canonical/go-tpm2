// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	"reflect"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2/mu"
)

type tpmValueDeepEqualsChecker struct {
	*CheckerInfo
}

// TPMValueDeepEquals checks that the obtained TPM value is deeply
// equal to the expected TPM value. This works by first converting
// both values to a canonical form by serializing and unserializing
// them. Both values need to be valid TPM types for this to work.
//
// For example:
//
//  expected := &tpm2.NVPublic{
//	Index: 0x0180000,
//	NameAlg: tpm2.HashAlgorithmSHA256,
//	Attrs: tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite|tpm2.AttrNVAuthRead|tpm2.AttrNVWritten),
//	Size: 8}
//  c.Check(public, TPMValueDeepEquals, expected)
//
var TPMValueDeepEquals Checker = &tpmValueDeepEqualsChecker{
	&CheckerInfo{Name: "TPMValueDeepEquals", Params: []string{"obtained", "expected"}}}

func (c *tpmValueDeepEqualsChecker) Check(params []interface{}, names []string) (result bool, err string) {
	var obtained interface{}
	var expected interface{}

	if k := mu.DetermineTPMKind(params[0]); k == mu.TPMKindUnsupported {
		return false, "obtained value is not a valid TPM value"
	}
	if k := mu.DetermineTPMKind(params[1]); k == mu.TPMKindUnsupported {
		return false, "expected value is not a valid TPM value"
	}

	if err := mu.CopyValue(&obtained, params[0]); err != nil {
		return false, "cannot copy obtained value to canonical form: " + err.Error()
	}
	if err := mu.CopyValue(&expected, params[1]); err != nil {
		return false, "cannot copy expected value to canonical form: " + err.Error()
	}

	return reflect.DeepEqual(obtained, expected), ""
}
