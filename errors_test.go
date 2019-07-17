package tpm2

import (
	"reflect"
	"testing"
)

func TestDecodeResponse(t *testing.T) {
	if err := DecodeResponseCode(CommandClear, Success); err != nil {
		t.Errorf("Expected no error for success")
	}

	err := DecodeResponseCode(CommandClear, ResponseCode(0x00000155))
	switch e := err.(type) {
	case TPMError:
		if e.Code != ErrorSensitive {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, ErrorSensitive)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}

	vendorErrResp := ResponseCode(0xa5a5057e)
	err = DecodeResponseCode(CommandClear, vendorErrResp)
	switch e := err.(type) {
	case TPMVendorError:
		if e.Code != vendorErrResp {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, vendorErrResp)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x00000923))
	switch e := err.(type) {
	case TPMWarning:
		if e.Code != WarningNVUnavailable {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, WarningNVUnavailable)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000005e7))
	switch e := err.(type) {
	case TPMParameterError:
		if e.Code != ErrorECCPoint {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, ErrorECCPoint)
		}
		if e.Index != 5 {
			t.Errorf("Unexpected index %d", e.Index)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x000000b9c))
	switch e := err.(type) {
	case TPMSessionError:
		if e.Code != ErrorKey {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, ErrorKey)
		}
		if e.Index != 3 {
			t.Errorf("Unexpected index %d", e.Index)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}

	err = DecodeResponseCode(CommandClear, ResponseCode(0x00000496))
	switch e := err.(type) {
	case TPMHandleError:
		if e.Code != ErrorSymmetric {
			t.Errorf("Unexpected error code %v (expected %v)", e.Code, ErrorSymmetric)
		}
		if e.Index != 4 {
			t.Errorf("Unexpected index %d", e.Index)
		}
	default:
		t.Errorf("Unexpected error type %s", reflect.TypeOf(err))
	}
}
