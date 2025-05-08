// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
)

type typesConstantsSuite struct{}

var _ = Suite(&typesConstantsSuite{})

func (*typesConstantsSuite) TestResponseBadTag(c *C) {
	rc := ResponseBadTag

	c.Check(rc.E(), internal_testutil.IntEqual, 0x1e)
	c.Check(rc.F(), internal_testutil.IsFalse)
	c.Check(rc.V(), internal_testutil.IsFalse)
	c.Check(rc.T(), internal_testutil.IsFalse)
	c.Check(rc.S(), internal_testutil.IsFalse)
	c.Check(func() { rc.P() }, PanicMatches, `not a format-1 response code`)
	c.Check(func() { rc.N() }, PanicMatches, `not a format-1 response code`)

	c.Check(rc.Base(), Equals, ResponseBadTag)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat0)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeNone)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM12)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 0)
}

func (*typesConstantsSuite) TestResponseNeedsTest(c *C) {
	rc := ResponseNeedsTest

	c.Check(rc.E(), internal_testutil.IntEqual, 0x53)
	c.Check(rc.F(), internal_testutil.IsFalse)
	c.Check(rc.V(), internal_testutil.IsTrue)
	c.Check(rc.T(), internal_testutil.IsFalse)
	c.Check(rc.S(), internal_testutil.IsFalse)
	c.Check(func() { rc.P() }, PanicMatches, `not a format-1 response code`)
	c.Check(func() { rc.N() }, PanicMatches, `not a format-1 response code`)

	c.Check(rc.Base(), Equals, ResponseNeedsTest)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat0)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeNone)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 0)
}

func (*typesConstantsSuite) TestResponseAuthType(c *C) {
	rc := ResponseAuthType

	c.Check(rc.E(), internal_testutil.IntEqual, 0x24)
	c.Check(rc.F(), internal_testutil.IsFalse)
	c.Check(rc.V(), internal_testutil.IsTrue)
	c.Check(rc.T(), internal_testutil.IsFalse)
	c.Check(rc.S(), internal_testutil.IsFalse)
	c.Check(func() { rc.P() }, PanicMatches, `not a format-1 response code`)
	c.Check(func() { rc.N() }, PanicMatches, `not a format-1 response code`)

	c.Check(rc.Base(), Equals, ResponseAuthType)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat0)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeNone)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 0)
}

func (*typesConstantsSuite) TestResponseAuthFail(c *C) {
	rc := ResponseAuthFail + ResponseS + Response1

	c.Check(rc.E(), internal_testutil.IntEqual, 0x0e)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsFalse)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x9)

	c.Check(rc.Base(), Equals, ResponseAuthFail)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeSession)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 1)
}

func (*typesConstantsSuite) TestResponseMode(c *C) {
	rc := ResponseMode + ResponseP + Response4

	c.Check(rc.E(), internal_testutil.IntEqual, 0x09)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsTrue)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x4)

	c.Check(rc.Base(), Equals, ResponseMode)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeParameter)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 4)
}

func (*typesConstantsSuite) TestResponseKey(c *C) {
	rc := ResponseKey + ResponseH + Response2

	c.Check(rc.E(), internal_testutil.IntEqual, 0x1c)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsFalse)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x2)

	c.Check(rc.Base(), Equals, ResponseKey)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeHandle)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 2)
}

func (*typesConstantsSuite) TestResponseTesting(c *C) {
	rc := ResponseTesting

	c.Check(rc.E(), internal_testutil.IntEqual, 0x0a)
	c.Check(rc.F(), internal_testutil.IsFalse)
	c.Check(rc.V(), internal_testutil.IsTrue)
	c.Check(rc.T(), internal_testutil.IsFalse)
	c.Check(rc.S(), internal_testutil.IsTrue)
	c.Check(func() { rc.P() }, PanicMatches, `not a format-1 response code`)
	c.Check(func() { rc.N() }, PanicMatches, `not a format-1 response code`)

	c.Check(rc.Base(), Equals, ResponseTesting)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat0)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeNone)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityWarning)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 0)
}

func (*typesConstantsSuite) TestVendorResponse(c *C) {
	rc := ResponseCode(0x57e)

	c.Check(rc.E(), internal_testutil.IntEqual, 0x7e)
	c.Check(rc.F(), internal_testutil.IsFalse)
	c.Check(rc.V(), internal_testutil.IsTrue)
	c.Check(rc.T(), internal_testutil.IsTrue)
	c.Check(rc.S(), internal_testutil.IsFalse)
	c.Check(func() { rc.P() }, PanicMatches, `not a format-1 response code`)
	c.Check(func() { rc.N() }, PanicMatches, `not a format-1 response code`)

	c.Check(rc.Base(), Equals, ResponseCode(0x57e))

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat0)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeNone)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecVendor)

	c.Check(rc.Index(), internal_testutil.IntEqual, 0)
}

func (*typesConstantsSuite) TestResponseCodeIndex(c *C) {
	c.Check(ResponseCodeIndex(1), Equals, Response1)
	c.Check(ResponseCodeIndex(4), Equals, Response4)
	c.Check(ResponseCodeIndex(15), Equals, ResponseF)
}

func (*typesConstantsSuite) TestResponseCodeIndexPanics(c *C) {
	c.Check(func() { ResponseCodeIndex(16) }, PanicMatches, `invalid handle, parameter, or session index \(> 0xf\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetHandleIndex(c *C) {
	rc := ResponseKey.SetHandleIndex(2)

	c.Check(rc.E(), internal_testutil.IntEqual, 0x1c)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsFalse)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x2)

	c.Check(rc.Base(), Equals, ResponseKey)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeHandle)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 2)
}

func (*typesConstantsSuite) TestResponseCodeSetHandleIndexFormat0Panics(c *C) {
	c.Check(func() { ResponseDisabled.SetHandleIndex(1) }, PanicMatches, `invalid response code 0x00000120 \(base response code is not a format-1 response code\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetHandleIndexInvalidIndexPanics(c *C) {
	c.Check(func() { ResponseHandle.SetHandleIndex(10) }, PanicMatches, `invalid response code 0x00000a8b \(invalid handle index overflows bits 8-10\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetParameterIndex(c *C) {
	rc := ResponseMode.SetParameterIndex(4)

	c.Check(rc.E(), internal_testutil.IntEqual, 0x09)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsTrue)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x4)

	c.Check(rc.Base(), Equals, ResponseMode)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeParameter)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 4)
}

func (*typesConstantsSuite) TestResponseCodeSetParameterIndexFormat0Panics(c *C) {
	c.Check(func() { ResponseDisabled.SetParameterIndex(1) }, PanicMatches, `invalid response code 0x00000120 \(base response code is not a format-1 response code\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetParameterIndexInvalidIndexPanics(c *C) {
	c.Check(func() { ResponseValue.SetParameterIndex(20) }, PanicMatches, `invalid response code 0x000014c4 \(invalid parameter index overflows bits 8-11\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetSessionIndex(c *C) {
	rc := ResponseAuthFail.SetSessionIndex(1)

	c.Check(rc.E(), internal_testutil.IntEqual, 0x0e)
	c.Check(rc.F(), internal_testutil.IsTrue)
	c.Check(func() { rc.V() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.T() }, PanicMatches, `not a format-0 response code`)
	c.Check(func() { rc.S() }, PanicMatches, `not a format-0 response code`)
	c.Check(rc.P(), internal_testutil.IsFalse)
	c.Check(rc.N(), internal_testutil.IntEqual, 0x9)

	c.Check(rc.Base(), Equals, ResponseAuthFail)

	rcType := rc.Type()
	c.Check(rcType.Format(), Equals, ResponseCodeFormat1)
	c.Check(rcType.IndexType(), Equals, ResponseCodeIndexTypeSession)
	c.Check(rcType.Version(), Equals, ResponseCodeVersionTPM2)
	c.Check(rcType.Severity(), Equals, ResponseCodeSeverityError)
	c.Check(rcType.Spec(), Equals, ResponseCodeSpecTCG)

	c.Check(rc.Index(), internal_testutil.IntEqual, 1)
}

func (*typesConstantsSuite) TestResponseCodeSetSessionIndexFormat0Panics(c *C) {
	c.Check(func() { ResponseDisabled.SetSessionIndex(1) }, PanicMatches, `invalid response code 0x00000120 \(base response code is not a format-1 response code\)`)
}

func (*typesConstantsSuite) TestResponseCodeSetSessionIndexInvalidIndexPanics(c *C) {
	c.Check(func() { ResponseBadAuth.SetSessionIndex(11) }, PanicMatches, `invalid response code 0x000013a2 \(invalid session index overflows bits 8-10\)`)
}
