// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux_test

import (
	"bytes"
	"encoding/binary"
	"os/exec"
	"path/filepath"

	. "gopkg.in/check.v1"

	efi "github.com/canonical/go-efilib"
	internal_ppi "github.com/canonical/go-tpm2/internal/ppi"
	internal_ppi_efi "github.com/canonical/go-tpm2/internal/ppi_efi"
	. "github.com/canonical/go-tpm2/linux"
	"github.com/canonical/go-tpm2/ppi"
	"github.com/canonical/go-tpm2/testutil"
)

var efiPpGuid = efi.MakeGUID(0xaeb9c5c1, 0x94f1, 0x4d02, 0xbfd9, [...]uint8{0x46, 0x02, 0xdb, 0x2d, 0x3c, 0x54})

type efiPpConfig struct {
	StructVersion    uint32
	PPICapabilities  uint32
	PPIVersion       [8]byte
	TransitionAction uint32
	UserConfirmation [64]uint8
}

type efiPpVars struct {
	supported bool
	config    *efiPpConfig
}

func (v *efiPpVars) Get(name string, guid efi.GUID) (efi.VariableAttributes, []byte, error) {
	if !v.supported {
		return 0, nil, efi.ErrVarNotExist
	}

	if guid != efiPpGuid {
		return 0, nil, efi.ErrVarNotExist
	}

	switch name {
	case "Tcg2PhysicalPresenceFlags":
		return efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, []byte{0xe2, 0x00, 0x07, 0x00}, nil
	case "Tcg2PhysicalPresenceConfig":
		if v.config == nil {
			return 0, nil, efi.ErrVarNotExist
		}
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, v.config)
		return efi.AttributeNonVolatile | efi.AttributeBootserviceAccess | efi.AttributeRuntimeAccess, buf.Bytes(), nil
	default:
		return 0, nil, efi.ErrVarNotExist
	}
}

func (v *efiPpVars) Set(name string, guid efi.GUID, attrs efi.VariableAttributes, data []byte) error {
	return efi.ErrVarsUnavailable
}

func (v *efiPpVars) List() ([]efi.VariableDescriptor, error) {
	return nil, efi.ErrVarsUnavailable
}

type deviceSuite struct {
	testutil.BaseTest
}

func (s *deviceSuite) SetUpTest(c *C) {
	s.BaseTest.SetUpTest(c)
	ResetDevices()
}

var _ = Suite(&deviceSuite{})

func (s *deviceSuite) newEfiPPI(c *C, customVars efi.VarsBackend) ppi.PPI {
	impl, version, err := internal_ppi_efi.NewBackend(customVars)
	c.Assert(err, IsNil)
	return internal_ppi.New(ppi.EFI, version, impl)
}

func (s *deviceSuite) newAcpiPPI(c *C, path string) ppi.PPI {
	impl, err := NewAcpiPpi(path)
	c.Assert(err, IsNil)
	return internal_ppi.New(ppi.ACPI, impl.Version, impl)
}

func (s *deviceSuite) unpackTarball(c *C, path string) string {
	dir := c.MkDir()

	cmd := exec.Command("tar", "xaf", path, "-C", dir)
	c.Assert(cmd.Run(), IsNil)

	return dir
}

func (s *deviceSuite) TestListTPMDevicesTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
	})
}

func (s *deviceSuite) TestListTPMDevicesTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
	})
}

func (s *deviceSuite) TestListTPMDevicesNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice(nil))
}

func (s *deviceSuite) TestListTPMDevicesTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), TPMVersion1, 0),
	})
}

func (s *deviceSuite) TestListTPMDevicesMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
		NewMockDirectDevice("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm1"), TPMVersion1, 1),
	})
}

func (s *deviceSuite) TestListTPMDevicesMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), TPMVersion1, 0),
		NewMockDirectDevice("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), TPMVersion2, 1),
	})
}

func (s *deviceSuite) TestListTPMDevicesTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPMDevices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), TPMVersion2, 0),
		NewMockDirectDevice("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), TPMVersion2, 1),
	})
}

func (s *deviceSuite) TestListTPM2DevicesTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
	})
}

func (s *deviceSuite) TestListTPM2DevicesTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
	})
}

func (s *deviceSuite) TestListTPM2DevicesNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice(nil))
}

func (s *deviceSuite) TestListTPM2DevicesTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice(nil))
}

func (s *deviceSuite) TestListTPM2DevicesMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0),
	})
}

func (s *deviceSuite) TestListTPM2DevicesMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), TPMVersion2, 1),
	})
}

func (s *deviceSuite) TestListTPM2DevicesTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	devices, err := ListTPM2Devices()
	c.Check(err, IsNil)
	c.Check(devices, DeepEquals, []*DirectDevice{
		NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), TPMVersion2, 0),
		NewMockDirectDevice("/dev/tpm1", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm1"), TPMVersion2, 1),
	})
}

func (s *deviceSuite) TestDefaultTPMDeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPMDeviceTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPMDeviceNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPMDevice()
	c.Check(err, Equals, ErrNoTPMDevices)
}

func (s *deviceSuite) TestDefaultTPMDeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), TPMVersion1, 0))
}

func (s *deviceSuite) TestDefaultTPMDeviceMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPMDeviceMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"), TPMVersion1, 0))
}

func (s *deviceSuite) TestDefaultTPMDeviceTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPM2DeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPM2DeviceTPM2OldKernel(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-old-kernel-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPM2DeviceNoDevices(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/no-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrNoTPMDevices)
}

func (s *deviceSuite) TestDefaultTPM2DeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrDefaultNotTPM2Device)
}

func (s *deviceSuite) TestDefaultTPM2DeviceMixedTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm2-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestDefaultTPM2DeviceMixedTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/mixed-devices-tpm1-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	_, err := DefaultTPM2Device()
	c.Check(err, Equals, ErrDefaultNotTPM2Device)
}

func (s *deviceSuite) TestDefaultTPM2DeviceTPM2Multiple(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/multiple-tpm2-devices-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPM2Device()
	c.Check(err, IsNil)
	c.Check(device, DeepEquals, NewMockDirectDevice("/dev/tpm0", filepath.Join(sysfsPath, "devices/platform/MSFT0101:00/tpm/tpm0"), TPMVersion2, 0))
}

func (s *deviceSuite) TestTPMDeviceMethodsTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)
	c.Check(device.Path(), Equals, "/dev/tpm0")
	c.Check(device.SysfsPath(), Equals, filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0"))
	c.Check(device.MajorVersion(), Equals, TPMVersion2)
}

func (s *deviceSuite) TestTPMDeviceMethodsTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)
	c.Check(device.Path(), Equals, "/dev/tpm0")
	c.Check(device.SysfsPath(), Equals, filepath.Join(sysfsPath, "devices/platform/SMO3324:00/tpm/tpm0"))
	c.Check(device.MajorVersion(), Equals, TPMVersion1)
}

func (s *deviceSuite) TestDirectDeviceResourceManagedDeviceTPM2(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	rm, err := device.ResourceManagedDevice()
	c.Check(err, IsNil)
	c.Check(rm, DeepEquals, NewMockRMDevice("/dev/tpmrm0", filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpmrm/tpmrm0"), TPMVersion2, device))
	c.Check(rm.DirectDevice(), Equals, device)
}

func (s *deviceSuite) TestDirectDeviceResourceManagedDeviceTPM2NoRM(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-no-rm-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	_, err = device.ResourceManagedDevice()
	c.Check(err, Equals, ErrNoResourceManagedDevice)
}

func (s *deviceSuite) TestDirectDeviceResourceManagedDeviceTPM1(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	_, err = device.ResourceManagedDevice()
	c.Check(err, Equals, ErrNoResourceManagedDevice)
}

func (s *deviceSuite) TestDirectDevicePhysicalPresenceInterfaceACPI(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))
	s.AddCleanup(MockEFIVars(new(efiPpVars)))

	expected := s.newAcpiPPI(c, filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0/ppi"))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	pp, err := device.PhysicalPresenceInterface()
	c.Assert(err, IsNil)
	c.Check(pp, DeepEquals, expected)
}

func (s *deviceSuite) TestDirectDevicePhysicalPresenceInterfaceEFI(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	vars := &efiPpVars{
		supported: true,
		config: &efiPpConfig{
			StructVersion:    1,
			PPIVersion:       [8]byte{'1', '.', '4', 0, 0, 0, 0, 0},
			TransitionAction: 2,
		},
	}
	s.AddCleanup(MockEFIVars(vars))

	expected := s.newEfiPPI(c, vars)

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	pp, err := device.PhysicalPresenceInterface()
	c.Assert(err, IsNil)
	c.Check(pp, DeepEquals, expected)
}

func (s *deviceSuite) TestDirectDevicePhysicalPresenceInterfaceACPIPreferredOverIncompleteEFI(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm2-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))
	s.AddCleanup(MockEFIVars(&efiPpVars{supported: true}))

	expected := s.newAcpiPPI(c, filepath.Join(sysfsPath, "devices/platform/STM0125:00/tpm/tpm0/ppi"))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	pp, err := device.PhysicalPresenceInterface()
	c.Assert(err, IsNil)
	c.Check(pp, DeepEquals, expected)
}

func (s *deviceSuite) TestDirectDevicePhysicalPresenceInterfaceIncompleteEFI(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))

	vars := &efiPpVars{supported: true}
	s.AddCleanup(MockEFIVars(vars))

	expected := s.newEfiPPI(c, vars)

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	pp, err := device.PhysicalPresenceInterface()
	c.Assert(err, IsNil)
	c.Check(pp, DeepEquals, expected)
}

func (s *deviceSuite) TestDirectDevicePhysicalPresenceInterfaceNone(c *C) {
	sysfsPath := s.unpackTarball(c, "testdata/tpm1-device-sysfs.tar")
	s.AddCleanup(MockSysfsPath(sysfsPath))
	s.AddCleanup(MockEFIVars(new(efiPpVars)))

	device, err := DefaultTPMDevice()
	c.Assert(err, IsNil)

	_, err = device.PhysicalPresenceInterface()
	c.Assert(err, Equals, ErrNoPhysicalPresenceInterface)
}
