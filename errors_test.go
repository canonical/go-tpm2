// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestDecodeSuccess(c *C) {
	c.Check(DecodeResponseCode(CommandClear, ResponseSuccess), IsNil)
}

func (s *errorsSuite) TestDecodeBadTag(c *C) {
	err := DecodeResponseCode(CommandGetCapability, ResponseBadTag)
	c.Check(err, ErrorMatches, "TPM returned an error whilst executing command TPM_CC_GetCapability: TPM_RC_BAD_TAG")
	c.Assert(err, testutil.ConvertibleTo, &TPMError{})
	c.Check(err.(*TPMError), DeepEquals, &TPMError{Command: CommandGetCapability, Code: ErrorBadTag})
	c.Check(err.(*TPMError).ResponseCode(), Equals, ResponseBadTag)
}

func (s *errorsSuite) TestDecodeInvalid(c *C) {
	err := DecodeResponseCode(CommandGetCapability, 0x1)
	c.Check(err, ErrorMatches, "invalid response code 0x00000001")
	c.Assert(err, testutil.ConvertibleTo, InvalidResponseCodeError(0))
	c.Check(ResponseCode(err.(InvalidResponseCodeError)), Equals, ResponseCode(0x1))
}

func (s *errorsSuite) TestDecodeVendorError(c *C) {
	rc := ResponseCode(0xa5a5057e)
	err := DecodeResponseCode(CommandLoad, rc)
	c.Check(err, ErrorMatches, "TPM returned a vendor defined error whilst executing command TPM_CC_Load: 0xa5a5057e")
	c.Assert(err, testutil.ConvertibleTo, &TPMVendorError{})
	c.Check(err.(*TPMVendorError), DeepEquals, &TPMVendorError{Command: CommandLoad, Code: rc})
}

func (s *errorsSuite) TestDecodeWarning(c *C) {
	err := DecodeResponseCode(CommandNVWrite, 0x923)
	c.Check(err, ErrorMatches, "TPM returned a warning whilst executing command TPM_CC_NV_Write: TPM_RC_NV_UNAVAILABLE \\(the command may require writing of NV and NV is not current accessible\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMWarning{})
	c.Check(err.(*TPMWarning), DeepEquals, &TPMWarning{Command: CommandNVWrite, Code: WarningNVUnavailable})
	c.Check(err.(*TPMWarning).ResponseCode(), Equals, ResponseCode(0x923))
}

func (s *errorsSuite) TestDecodeError0(c *C) {
	err := DecodeResponseCode(CommandUnseal, 0x128)
	c.Check(err, ErrorMatches, "TPM returned an error whilst executing command TPM_CC_Unseal: TPM_RC_PCR_CHANGED \\(PCR have changed since checked\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMError{})
	c.Check(err.(*TPMError), DeepEquals, &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged})
	c.Check(err.(*TPMError).ResponseCode(), Equals, ResponseCode(0x128))
}

func (s *errorsSuite) TestDecodeError1(c *C) {
	err := DecodeResponseCode(CommandGetRandom, 0x9a)
	c.Check(err, ErrorMatches, "TPM returned an error whilst executing command TPM_CC_GetRandom: TPM_RC_INSUFFICIENT \\(the TPM was unable to unmarshal a value because there were not enough octets in the input buffer\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMError{})
	c.Check(err.(*TPMError), DeepEquals, &TPMError{Command: CommandGetRandom, Code: ErrorInsufficient})
	c.Check(err.(*TPMError).ResponseCode(), Equals, ResponseCode(0x9a))
}

func (s *errorsSuite) TestDecodeParameterError(c *C) {
	err := DecodeResponseCode(CommandStartAuthSession, 0x4c9)
	c.Check(err, ErrorMatches, "TPM returned an error for parameter 4 whilst executing command TPM_CC_StartAuthSession: TPM_RC_MODE \\(mode of operation not supported\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMParameterError{})
	c.Check(err.(*TPMParameterError), DeepEquals, &TPMParameterError{TPMError: &TPMError{Command: CommandStartAuthSession, Code: ErrorMode}, Index: 4})
	c.Check(err.(*TPMParameterError).ResponseCode(), Equals, ResponseCode(0x4c9))
}

func (s *errorsSuite) TestDecodeSessionError(c *C) {
	err := DecodeResponseCode(CommandUnseal, 0x98e)
	c.Check(err, ErrorMatches, "TPM returned an error for session 1 whilst executing command TPM_CC_Unseal: TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMSessionError{})
	c.Check(err.(*TPMSessionError), DeepEquals, &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorAuthFail}, Index: 1})
	c.Check(err.(*TPMSessionError).ResponseCode(), Equals, ResponseCode(0x98e))
}

func (s *errorsSuite) TestDecodeHandleError(c *C) {
	err := DecodeResponseCode(CommandCertify, 0x29c)
	c.Check(err, ErrorMatches, "TPM returned an error for handle 2 whilst executing command TPM_CC_Certify: TPM_RC_KEY \\(key fields are not compatible with the selected use\\)")
	c.Assert(err, testutil.ConvertibleTo, &TPMHandleError{})
	c.Check(err.(*TPMHandleError), DeepEquals, &TPMHandleError{TPMError: &TPMError{Command: CommandCertify, Code: ErrorKey}, Index: 2})
	c.Check(err.(*TPMHandleError).ResponseCode(), Equals, ResponseCode(0x29c))
}
