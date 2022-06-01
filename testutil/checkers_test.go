// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	"reflect"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	. "github.com/canonical/go-tpm2/testutil"
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

func (s *checkersSuite) TestTPMValueDeepEquals(c *C) {
	testInfo(c, TPMValueDeepEquals, "TPMValueDeepEquals", []string{"obtained", "expected"})

	expected := tpm2.NVPublic{
		Index:   0x0180000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVWritten),
		Size:    8}

	obtained := tpm2.NVPublic{
		Index:   0x0180000,
		NameAlg: tpm2.HashAlgorithmSHA256,
		Attrs:   tpm2.NVTypeOrdinary.WithAttrs(tpm2.AttrNVAuthWrite | tpm2.AttrNVAuthRead | tpm2.AttrNVWritten),
		Size:    8}

	c.Check(obtained, DeepEquals, expected)
	testCheck(c, TPMValueDeepEquals, true, "", obtained, expected)
	testCheck(c, TPMValueDeepEquals, true, "", &obtained, &expected)
	testCheck(c, TPMValueDeepEquals, false, "", obtained, &expected)
	testCheck(c, TPMValueDeepEquals, false, "", &obtained, expected)

	expected.AuthPolicy = tpm2.Digest{}

	c.Check(obtained, Not(DeepEquals), expected)
	testCheck(c, TPMValueDeepEquals, true, "", obtained, expected)

	obtained.AuthPolicy = make([]byte, 32)
	testCheck(c, TPMValueDeepEquals, false, "", obtained, expected)

	testCheck(c, TPMValueDeepEquals, false, "obtained value is not a valid TPM value", 1, uint16(1))
	testCheck(c, TPMValueDeepEquals, false, "expected value is not a valid TPM value", uint16(1), 1)
}
