// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mssim

import (
	"net"

	"github.com/canonical/go-tpm2/transportutil"
)

type (
	DeviceAddr = deviceAddr
)

func MockNetDial(fn func(string, string) (net.Conn, error)) (restore func()) {
	orig := netDial
	netDial = fn
	return func() {
		netDial = orig
	}
}

func NewMockDevice(tpm, platform *DeviceAddr, retryParams *transportutil.RetryParams) *Device {
	return &Device{
		tpm:         *tpm,
		platform:    *platform,
		retryParams: *retryParams,
	}
}
