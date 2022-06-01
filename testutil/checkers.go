// Copyright 2022 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil

import (
	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2/mu"
)

type tpmValueDeepEqualsChecker struct {
	*CheckerInfo
}

// TPMValueDeepEquals checks that the obtained TPM value is deeply
// equal to the expected TPM value. This works by first converting
// both values to a canonical form by serializing and unserializing
// them. Both values need to be valid TPM types for this to work,
// and they need to be representable by the TPM wire format.
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
	if !mu.IsValid(params[0]) {
		return false, "obtained value is not a valid TPM value"
	}
	if !mu.IsValid(params[1]) {
		return false, "expected value is not a valid TPM value"
	}

	return mu.DeepEqual(params[0], params[1]), ""
}
