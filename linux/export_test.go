// Copyright 2013 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

var NewSysfsPpi = newSysfsPpi

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}

func NewMockTPMDeviceRaw(path, sysfsPath string, version TPMMajorVersion, devno int) *TPMDeviceRaw {
	return &TPMDeviceRaw{
		TPMDevice: TPMDevice{
			path:      path,
			sysfsPath: sysfsPath,
			version:   version},
		devno: devno,
	}
}

func NewMockTPMDeviceRM(path, sysfsPath string, version TPMMajorVersion, raw *TPMDeviceRaw) *TPMDeviceRM {
	return &TPMDeviceRM{
		TPMDevice: TPMDevice{
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
