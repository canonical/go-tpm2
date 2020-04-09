// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/canonical/go-tpm2"
)

func TestDecodeResponse(t *testing.T) {
	if err := DecodeResponseCode(CommandClear, Success); err != nil {
		t.Errorf("Expected no error for success")
	}

	err := DecodeResponseCode(CommandClear, ResponseCode(0x00000155))
	if !IsTPMError(err, ErrorSensitive, CommandClear) {
		t.Errorf("Unexpected error: %v", err)
	}

	vendorErrResp := ResponseCode(0xa5a5057e)
	err = DecodeResponseCode(CommandLoad, vendorErrResp)
	if e, ok := err.(*TPMVendorError); !ok || e.Code != vendorErrResp || e.Command != CommandLoad {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandNVWrite, ResponseCode(0x00000923))
	if !IsTPMWarning(err, WarningNVUnavailable, CommandNVWrite) {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000005e7))
	if !IsTPMParameterError(err, ErrorECCPoint, CommandClear, 5) {
		t.Errorf("Unexpected error: %v", err)
	}
	if !IsTPMError(err, ErrorECCPoint, CommandClear) {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandUnseal, ResponseCode(0x000000b9c))
	if !IsTPMSessionError(err, ErrorKey, CommandUnseal, 3) {
		t.Errorf("Unexpected error: %v", err)
	}
	if !IsTPMError(err, ErrorKey, CommandUnseal) {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandStartup, ResponseCode(0x00000496))
	if !IsTPMHandleError(err, ErrorSymmetric, CommandStartup, 4) {
		t.Errorf("Unexpected error: %v", err)
	}
	if !IsTPMError(err, ErrorSymmetric, CommandStartup) {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandSign, ResponseCode(0x00000084))
	if !IsTPMError(err, ErrorValue, CommandSign) {
		t.Errorf("Unexpected error: %v", err)
	}
}
