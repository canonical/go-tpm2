// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mssim

import (
	"net"
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

func NewMockDevice(tpm, platform *DeviceAddr) *Device {
	return &Device{
		tpm:      tpm,
		platform: platform,
	}
}
