// Copyright 2013 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

func MockSysfsPath(path string) (restore func()) {
	orig := sysfsPath
	sysfsPath = path
	return func() {
		sysfsPath = orig
	}
}

func NewMockTPMDeviceRaw(path, sysfsPath string, version, devno int) *TPMDeviceRaw {
	return &TPMDeviceRaw{
		TPMDevice: TPMDevice{
			path:      path,
			sysfsPath: sysfsPath,
			version:   version},
		devno: devno}
}

func NewMockTPMDeviceRM(path, sysfsPath string, version int, raw *TPMDeviceRaw) *TPMDeviceRM {
	return &TPMDeviceRM{
		TPMDevice: TPMDevice{
			path:      path,
			sysfsPath: sysfsPath,
			version:   version},
		raw: raw}
}
