// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"testing"

	"golang.org/x/xerrors"
)

func TestDecodeResponse(t *testing.T) {
	if err := DecodeResponseCode(CommandClear, Success); err != nil {
		t.Errorf("Expected no error for success")
	}

	err := DecodeResponseCode(CommandClear, ResponseCode(0x00000155))
	if e, ok := err.(*TPMError); !ok || e.Code != ErrorSensitive || e.Command != CommandClear {
		t.Errorf("Unexpected error: %v", err)
	}

	vendorErrResp := ResponseCode(0xa5a5057e)
	err = DecodeResponseCode(CommandLoad, vendorErrResp)
	if e, ok := err.(*TPMVendorError); !ok || e.Code != vendorErrResp || e.Command != CommandLoad {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandNVWrite, ResponseCode(0x00000923))
	if e, ok := err.(*TPMWarning); !ok || e.Code != WarningNVUnavailable || e.Command != CommandNVWrite {
		t.Errorf("Unexpected error: %v", err)
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000005e7))
	if e, ok := err.(*TPMParameterError); !ok || e.Code() != ErrorECCPoint || e.Index != 5 || e.Command() != CommandClear {
		t.Errorf("Unexpected error: %v", err)
	}
	var e *TPMError
	if !xerrors.As(err, &e) || e.Code != ErrorECCPoint || e.Command != CommandClear {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandUnseal, ResponseCode(0x000000b9c))
	if e, ok := err.(*TPMSessionError); !ok || e.Code() != ErrorKey || e.Index != 3 || e.Command() != CommandUnseal {
		t.Errorf("Unexpected error: %v", err)
	}
	if !xerrors.As(err, &e) || e.Code != ErrorKey || e.Command != CommandUnseal {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandStartup, ResponseCode(0x00000496))
	if e, ok := err.(*TPMHandleError); !ok || e.Code() != ErrorSymmetric || e.Index != 4 || e.Command() != CommandStartup {
		t.Errorf("Unexpected error: %v", err)
	}
	if !xerrors.As(err, &e) || e.Code != ErrorSymmetric || e.Command != CommandStartup {
		t.Errorf("Unexpected wrapping")
	}

	err = DecodeResponseCode(CommandSign, ResponseCode(0x00000084))
	if e, ok := err.(*TPMError); !ok || e.Code != ErrorValue || e.Command != CommandSign {
		t.Errorf("Unexpected error: %v", err)
	}
}
