// Copyright 2013 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import efi "github.com/canonical/go-efilib"

var NewAcpiPpi = newAcpiPpi

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}

func MockEFIVars(vars efi.VarsBackend) (restore func()) {
	orig := customEfiVars
	customEfiVars = vars
	return func() {
		customEfiVars = orig
	}
}

func NewMockDirectDevice(path, sysfsPath string, version TPMMajorVersion, devno int) *DirectDevice {
	return &DirectDevice{
		Device: Device{
			path:      path,
			sysfsPath: sysfsPath,
			version:   version},
		devno: devno,
	}
}

func NewMockRMDevice(path, sysfsPath string, version TPMMajorVersion, raw *DirectDevice) *RMDevice {
	return &RMDevice{
		Device: Device{
			path:      path,
			sysfsPath: sysfsPath,
			version:   version,
		},
		raw: raw,
	}
}

func ResetDevices() {
	devices = tpmDevices{}
}
