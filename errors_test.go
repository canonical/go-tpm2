// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"errors"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
)

type errorsSuite struct{}

var _ = Suite(&errorsSuite{})

func (s *errorsSuite) TestDecodeSuccess(c *C) {
	c.Check(DecodeResponseCode(CommandClear, ResponseSuccess), IsNil)
}

func (s *errorsSuite) TestDecodeBadTag(c *C) {
	err := DecodeResponseCode(CommandGetCapability, ResponseBadTag)
	c.Check(err, ErrorMatches, "TPM returned a TPM_RC_BAD_TAG error whilst executing command TPM_CC_GetCapability")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMErrorBadTag{})
	c.Check(err.(*TPMErrorBadTag), DeepEquals, &TPMErrorBadTag{Command: CommandGetCapability})
	c.Check(err.(*TPMErrorBadTag).ResponseCode(), Equals, ResponseBadTag)
}

func (s *errorsSuite) TestDecodeInvalid(c *C) {
	err := DecodeResponseCode(CommandGetCapability, 0x1)
	c.Check(err, ErrorMatches, "invalid response code 0x00000001")
	c.Assert(err, internal_testutil.ConvertibleTo, InvalidResponseCodeError(0))
	c.Check(err.(InvalidResponseCodeError), Equals, InvalidResponseCodeError(0x1))
}

func (s *errorsSuite) TestDecodeInvalidParameter(c *C) {
	err := DecodeResponseCode(CommandStartAuthSession, 0xc9)
	c.Check(err, ErrorMatches, "invalid response code 0x000000c9")
	c.Assert(err, internal_testutil.ConvertibleTo, InvalidResponseCodeError(0))
	c.Check(err.(InvalidResponseCodeError), Equals, InvalidResponseCodeError(0xc9))
}

func (s *errorsSuite) TestDecodeInvalidSession(c *C) {
	err := DecodeResponseCode(CommandUnseal, 0x88e)
	c.Check(err, ErrorMatches, "invalid response code 0x0000088e")
	c.Assert(err, internal_testutil.ConvertibleTo, InvalidResponseCodeError(0))
	c.Check(err.(InvalidResponseCodeError), Equals, InvalidResponseCodeError(0x88e))
}

func (s *errorsSuite) TestDecodeVendorError(c *C) {
	rc := ResponseCode(0xa5a5057e)
	err := DecodeResponseCode(CommandLoad, rc)
	c.Check(err, ErrorMatches, "TPM returned a vendor defined error whilst executing command TPM_CC_Load: 0xa5a5057e")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMVendorError{})
	c.Check(err.(*TPMVendorError), DeepEquals, &TPMVendorError{Command: CommandLoad, Code: rc})
}

func (s *errorsSuite) TestDecodeWarning(c *C) {
	err := DecodeResponseCode(CommandNVWrite, 0x923)
	c.Check(err, ErrorMatches, "TPM returned a warning whilst executing command TPM_CC_NV_Write: TPM_RC_NV_UNAVAILABLE \\(the command may require writing of NV and NV is not current accessible\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMWarning{})
	c.Check(err.(*TPMWarning), DeepEquals, &TPMWarning{Command: CommandNVWrite, Code: WarningNVUnavailable})
	c.Check(err.(*TPMWarning).ResponseCode(), Equals, ResponseCode(0x923))
}

func (s *errorsSuite) TestDecodeWarningSelfTest(c *C) {
	err := DecodeResponseCode(CommandGetRandom, 0x90a)
	c.Check(err, ErrorMatches, "TPM returned a warning whilst executing command TPM_CC_GetRandom: TPM_RC_TESTING \\(TPM is performing self-tests\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMWarning{})
	c.Check(err.(*TPMWarning), DeepEquals, &TPMWarning{Command: CommandGetRandom, Code: WarningTesting})
	c.Check(err.(*TPMWarning).ResponseCode(), Equals, ResponseCode(0x90a))
}

func (s *errorsSuite) TestDecodeAsyncSelfTest(c *C) {
	err := DecodeResponseCode(CommandSelfTest, 0x90a)
	c.Check(err, IsNil)
}

func (s *errorsSuite) TestDecodeError0(c *C) {
	err := DecodeResponseCode(CommandUnseal, 0x128)
	c.Check(err, ErrorMatches, "TPM returned an error whilst executing command TPM_CC_Unseal: TPM_RC_PCR_CHANGED \\(PCR have changed since checked\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMError{})
	c.Check(err.(*TPMError), DeepEquals, &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged})
	c.Check(err.(*TPMError).ResponseCode(), Equals, ResponseCode(0x128))
}

func (s *errorsSuite) TestDecodeError1(c *C) {
	err := DecodeResponseCode(CommandGetRandom, 0x9a)
	c.Check(err, ErrorMatches, "TPM returned an error whilst executing command TPM_CC_GetRandom: TPM_RC_INSUFFICIENT \\(the TPM was unable to unmarshal a value because there were not enough octets in the input buffer\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMError{})
	c.Check(err.(*TPMError), DeepEquals, &TPMError{Command: CommandGetRandom, Code: ErrorInsufficient})
	c.Check(err.(*TPMError).ResponseCode(), Equals, ResponseCode(0x9a))
}

func (s *errorsSuite) TestDecodeParameterError(c *C) {
	err := DecodeResponseCode(CommandStartAuthSession, 0x4c9)
	c.Check(err, ErrorMatches, "TPM returned an error for parameter 4 whilst executing command TPM_CC_StartAuthSession: TPM_RC_MODE \\(mode of operation not supported\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMParameterError{})
	c.Check(err.(*TPMParameterError), DeepEquals, &TPMParameterError{TPMError: &TPMError{Command: CommandStartAuthSession, Code: ErrorMode}, Index: 4})
	c.Check(err.(*TPMParameterError).ResponseCode(), Equals, ResponseCode(0x4c9))
}

func (s *errorsSuite) TestDecodeSessionError(c *C) {
	err := DecodeResponseCode(CommandUnseal, 0x98e)
	c.Check(err, ErrorMatches, "TPM returned an error for session 1 whilst executing command TPM_CC_Unseal: TPM_RC_AUTH_FAIL \\(the authorization HMAC check failed and DA counter incremented\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMSessionError{})
	c.Check(err.(*TPMSessionError), DeepEquals, &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorAuthFail}, Index: 1})
	c.Check(err.(*TPMSessionError).ResponseCode(), Equals, ResponseCode(0x98e))
}

func (s *errorsSuite) TestDecodeHandleError(c *C) {
	err := DecodeResponseCode(CommandCertify, 0x29c)
	c.Check(err, ErrorMatches, "TPM returned an error for handle 2 whilst executing command TPM_CC_Certify: TPM_RC_KEY \\(key fields are not compatible with the selected use\\)")
	c.Assert(err, internal_testutil.ConvertibleTo, &TPMHandleError{})
	c.Check(err.(*TPMHandleError), DeepEquals, &TPMHandleError{TPMError: &TPMError{Command: CommandCertify, Code: ErrorKey}, Index: 2})
	c.Check(err.(*TPMHandleError).ResponseCode(), Equals, ResponseCode(0x29c))
}

func (s *errorsSuite) TestTPMErrorIs1(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(&TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMErrorIs2(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(&TPMError{Command: AnyCommandCode, Code: ErrorPCRChanged}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMErrorIs3(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(&TPMError{Command: CommandUnseal, Code: AnyErrorCode}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMErrorIs4(c *C) {
	err := &TPMError{Command: CommandContextLoad, Code: ErrorAuthContext}
	c.Check(err.Is(&TPMError{Command: CommandContextLoad, Code: ErrorAuthContext}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMErrorIs5(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(&TPMError{Command: CommandSign, Code: ErrorPCRChanged}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMErrorIs6(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(&TPMError{Command: CommandUnseal, Code: ErrorInsufficient}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMErrorIs7(c *C) {
	err := &TPMError{Command: CommandUnseal, Code: ErrorPCRChanged}
	c.Check(err.Is(errors.New("error")), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMWarningIs1(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(&TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMWarningIs2(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(&TPMWarning{Command: AnyCommandCode, Code: WarningContextGap}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMWarningIs3(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(&TPMWarning{Command: CommandStartAuthSession, Code: AnyWarningCode}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMWarningIs4(c *C) {
	err := &TPMWarning{Command: CommandLoad, Code: WarningObjectMemory}
	c.Check(err.Is(&TPMWarning{Command: CommandLoad, Code: WarningObjectMemory}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMWarningIs5(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(&TPMWarning{Command: CommandContextLoad, Code: WarningContextGap}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMWarningIs6(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(&TPMWarning{Command: CommandStartAuthSession, Code: WarningSessionMemory}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMWarningIs7(c *C) {
	err := &TPMWarning{Command: CommandStartAuthSession, Code: WarningContextGap}
	c.Check(err.Is(errors.New("error")), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMParameterErrorIs1(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMParameterErrorIs2(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: AnyCommandCode, Code: ErrorValue}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMParameterErrorIs3(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: AnyErrorCode}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMParameterErrorIs4(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: AnyParameterIndex}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMParameterErrorIs5(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandVerifySignature, Code: ErrorSignature}, Index: 2}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandVerifySignature, Code: ErrorSignature}, Index: 2}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMParameterErrorIs6(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandActivateCredential, Code: ErrorValue}, Index: 1}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMParameterErrorIs7(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorIntegrity}, Index: 1}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMParameterErrorIs8(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 2}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMParameterErrorIs9(c *C) {
	err := &TPMParameterError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorValue}, Index: 1}
	c.Check(err.Is(&TPMError{Command: CommandLoad, Code: ErrorValue}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMSessionErrorIs1(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMSessionErrorIs2(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: AnyCommandCode, Code: ErrorHandle}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMSessionErrorIs3(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: AnyErrorCode}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMSessionErrorIs4(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: AnySessionIndex}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMSessionErrorIs5(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorAttributes}, Index: 3}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorAttributes}, Index: 3}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestTPMSessionErrorIs6(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandLoad, Code: ErrorHandle}, Index: 1}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMSessionErrorIs7(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorAttributes}, Index: 1}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMSessionErrorIs8(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 3}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestTPMSessionErrorIs9(c *C) {
	err := &TPMSessionError{TPMError: &TPMError{Command: CommandUnseal, Code: ErrorHandle}, Index: 1}
	c.Check(err.Is(&TPMError{Command: CommandUnseal, Code: ErrorHandle}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestIsTPMHandleError1(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestIsTPMHandleError2(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: AnyCommandCode, Code: ErrorValue}, Index: 2}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestIsTPMHandleError3(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: AnyErrorCode}, Index: 2}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestIsTPMHandleError4(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: AnyHandleIndex}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestIsTPMHandleError5(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVDefineSpace, Code: ErrorHierarchy}, Index: 1}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVDefineSpace, Code: ErrorHierarchy}, Index: 1}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestIsTPMHandleError6(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVRead, Code: ErrorValue}, Index: 2}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestIsTPMHandleError7(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorHandle}, Index: 2}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestIsTPMHandleError8(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 1}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestIsTPMHandleError9(c *C) {
	err := &TPMHandleError{TPMError: &TPMError{Command: CommandNVWrite, Code: ErrorValue}, Index: 2}
	c.Check(err.Is(&TPMError{Command: CommandNVWrite, Code: ErrorValue}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestResourceUnavailableErrorIs1(c *C) {
	err := ResourceUnavailableError{Handle: 0x81000001}
	c.Check(err.Is(ResourceUnavailableError{Handle: 0x81000001}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestResourceUnavailableErrorIs2(c *C) {
	err := ResourceUnavailableError{Handle: 0x80000000}
	c.Check(err.Is(ResourceUnavailableError{Handle: 0x80000000}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestResourceUnavailableErrorIs3(c *C) {
	err := ResourceUnavailableError{Handle: 0x81000001}
	c.Check(err.Is(ResourceUnavailableError{Handle: AnyHandle}), internal_testutil.IsTrue)
}

func (s *errorsSuite) TestResourceUnavailableErrorIs4(c *C) {
	err := ResourceUnavailableError{Handle: 0x81000001}
	c.Check(err.Is(ResourceUnavailableError{Handle: 0x80000000}), internal_testutil.IsFalse)
}

func (s *errorsSuite) TestResourceUnavailableErrorIs5(c *C) {
	err := ResourceUnavailableError{Handle: 0x81000001}
	c.Check(err.Is(errors.New("error")), internal_testutil.IsFalse)
}
