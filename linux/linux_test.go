// Copyright 2013 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	"os/exec"
	"path/filepath"
	"testing"

	. "github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }

type linuxSuite struct {
	testutil.BaseTest
}

var _ = Suite(&linuxSuite{})

func (s *linuxSuite) unpackTarball(c *C, path string) string {
	dir := c.MkDir()

	cmd := exec.Command("tar", "xaf", path, "-C", dir)
	c.Assert(cmd.Run(), IsNil)

	return dir
}

func (s *linuxSuite) TestListTPMDevicesTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
	})
}

func (s *linuxSuite) TestListTPMDevicesTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
	})
}

func (s *linuxSuite) TestListTPMDevicesNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw(nil))
}

func (s *linuxSuite) TestListTPMDevicesTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), 1, 0),
	})
}

func (s *linuxSuite) TestListTPMDevicesMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
		NewMockTPMDeviceRaw("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm1"), 1, 1),
	})
}

func (s *linuxSuite) TestListTPMDevicesMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), 1, 0),
		NewMockTPMDeviceRaw("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), 2, 1),
	})
}

func (s *linuxSuite) TestListTPMDevicesTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), 2, 0),
		NewMockTPMDeviceRaw("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), 2, 1),
	})
}

func (s *linuxSuite) TestListTPM2DevicesTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
	})
}

func (s *linuxSuite) TestListTPM2DevicesTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
	})
}

func (s *linuxSuite) TestListTPM2DevicesNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw(nil))
}

func (s *linuxSuite) TestListTPM2DevicesTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw(nil))
}

func (s *linuxSuite) TestListTPM2DevicesMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0),
	})
}

func (s *linuxSuite) TestListTPM2DevicesMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), 2, 1),
	})
}

func (s *linuxSuite) TestListTPM2DevicesTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*TPMDeviceRaw{
		NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), 2, 0),
		NewMockTPMDeviceRaw("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), 2, 1),
	})
}

func (s *linuxSuite) TestDefaultTPMDeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPMDeviceTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPMDeviceNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPMDevice()
	c.Check(err, Equals, ErrNoTPMDevices)
}

func (s *linuxSuite) TestDefaultTPMDeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), 1, 0))
}

func (s *linuxSuite) TestDefaultTPMDeviceMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPMDeviceMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), 1, 0))
}

func (s *linuxSuite) TestDefaultTPMDeviceTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPM2DeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPM2DeviceTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPM2DeviceNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrNoTPMDevices)
}

func (s *linuxSuite) TestDefaultTPM2DeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrDefaultNotTPM2Device)
}

func (s *linuxSuite) TestDefaultTPM2DeviceMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestDefaultTPM2DeviceMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrDefaultNotTPM2Device)
}

func (s *linuxSuite) TestDefaultTPM2DeviceTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockTPMDeviceRaw("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), 2, 0))
}

func (s *linuxSuite) TestTPMDeviceMethodsTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)
	c.Check(device.Path(), Equals, "/dev/tpm0")
	c.Check(device.SysfsPath(), Equals, filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"))
	c.Check(device.MajorVersion(), Equals, 2)
}

func (s *linuxSuite) TestTPMDeviceMethodsTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)
	c.Check(device.Path(), Equals, "/dev/tpm0")
	c.Check(device.SysfsPath(), Equals, filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"))
	c.Check(device.MajorVersion(), Equals, 1)
}

func (s *linuxSuite) TestTPMDeviceRawResourceManagedDeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	rm, err := device.ResourceManagedDevice()
	c.Check(err, IsNil)
	c.Check(rm, DeepEquals, NewMockTPMDeviceRM("/dev/tpmrm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpmrm/tpmrm0"), 2, device))
	c.Check(rm.RawDevice(), Equals, device)
}

func (s *linuxSuite) TestTPMDeviceRawResourceManagedDeviceTPM2NoRM(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-no-rm-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	_, err = device.ResourceManagedDevice()
	c.Check(err, Equals, ErrNoResourceManagedDevice)
}

func (s *linuxSuite) TestTPMDeviceRawResourceManagedDeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	_, err = device.ResourceManagedDevice()
	c.Check(err, Equals, ErrNoResourceManagedDevice)
}
