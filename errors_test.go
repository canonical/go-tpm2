// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"
)

func TestDecodeResponse(t *testing.T) {
	if err := DecodeResponseCode(CommandClear, Success); err != nil {
		t.Errorf("Expected no error for success")
	}

	err := DecodeResponseCode(CommandClear, ResponseCode(0x00000155))
	if e, ok := err.(*TPMError); !ok || e.Code != ErrorSensitive {
		t.Errorf("Unexpected error: %v", err)
	}

	vendorErrResp := ResponseCode(0xa5a5057e)
	err = DecodeResponseCode(CommandClear, vendorErrResp)
	if e, ok := err.(*TPMVendorError); !ok || e.Code != vendorErrResp {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x00000923))
	if e, ok := err.(*TPMWarning); !ok || e.Code != WarningNVUnavailable {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000005e7))
	if e, ok := err.(*TPMParameterError); !ok || e.Code != ErrorECCPoint || e.Index != 5 {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000000b9c))
	if e, ok := err.(*TPMSessionError); !ok || e.Code != ErrorKey || e.Index != 3 {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x00000496))
	if e, ok := err.(*TPMHandleError); !ok || e.Code != ErrorSymmetric || e.Index != 4 {
		t.Errorf("Unexpected error: %v", err)
	}
}
