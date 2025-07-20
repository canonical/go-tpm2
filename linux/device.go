// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	efi "github.com/canonical/go-efilib"
	"github.com/canonical/go-tpm2"
	internal_ppi "github.com/canonical/go-tpm2/internal/ppi"
	internal_ppi_efi "github.com/canonical/go-tpm2/internal/ppi_efi"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/ppi"
)

const (
	devPath = "/dev"
)

var (
	// ErrDefaultNotTPM2Device indicates that the default device is not a TPM device.
	ErrDefaultNotTPM2Device = errors.New("the default TPM device is not a TPM2 device")

	// ErrNoPhysicalPresenceInterface indicates that there is no physical presence interface
	// available for a TPM device.
	ErrNoPhysicalPresenceInterface = errors.New("no physical presence interface available")

	// ErrNoResourceManagedDevice indicates that a TPM device has no corresponding resource
	// managed device.
	ErrNoResourceManagedDevice = errors.New("no resource managed TPM device available")

	// ErrNoTPMDevices indicates that there are no TPM devices.
	ErrNoTPMDevices = errors.New("no TPM devices are available")

	sysfsPath = "/sys"

	customEfiVars efi.VarsBackend
)

type nonBlockingTpmFileReader struct {
	file *tpmFile
}

func (r *nonBlockingTpmFileReader) Read(data []byte) (int, error) {
	n, err := r.file.ReadNonBlocking(data)
	if n == 0 && err == nil {
		err = io.EOF
	}
	return n, err
}

type tpmDevices struct {
	once    sync.Once
	devices []*DirectDevice
	err     error
}

var devices tpmDevices

// TctiDevice represents a connection to a Linux TPM character device.
//
// Deprecated: Use Transport
type TctiDevice = Transport

// TPMMajorVersion describes the major version of a TPM device.
type TPMMajorVersion int

const (
	TPMVersion1 TPMMajorVersion = 1
	TPMVersion2 TPMMajorVersion = 2
)

// TPMDevice represents a Linux TPM character device.
//
// Deprecated: use [Device].
type TPMDevice = Device

// Device represents a Linux TPM character device.
type Device struct {
	path      string
	sysfsPath string
	version   TPMMajorVersion

	prsOnce                    sync.Once
	devicePartialReadSupported bool

	mrsOnce               sync.Once
	deviceMaxResponseSize uint32
}

func (d *Device) partialReadSupported(f *os.File) bool {
	d.prsOnce.Do(func() {
		d.devicePartialReadSupported = func() bool {
			if f == nil {
				var err error
				f, err = os.OpenFile(d.path, os.O_RDWR, 0)
				if err != nil {
					return false
				}
				defer f.Close()
			}
			tf := &tpmFile{file: f}

			cmd := tpm2.MustMarshalCommandPacket(
				tpm2.CommandGetCapability, nil, nil,
				mu.MustMarshalToBytes(tpm2.CapabilityTPMProperties, tpm2.PropertyManufacturer, uint32(1)),
			)
			if _, err := tf.Write(cmd); err != nil {
				return false
			}

			var rspHdr tpm2.ResponseHeader
			buf := make([]byte, binary.Size(rspHdr))
			if _, err := io.ReadFull(tf, buf); err != nil {
				return false
			}
			if _, err := mu.UnmarshalFromBytes(buf, &rspHdr); err != nil {
				return false
			}
			if rspHdr.ResponseCode != tpm2.ResponseSuccess {
				return false
			}

			var moreData bool
			var capabilityData *tpm2.CapabilityData
			if _, err := mu.UnmarshalFromReader(&nonBlockingTpmFileReader{tf}, &moreData, &capabilityData); err != nil {
				return false
			}

			return true
		}()
	})

	return d.devicePartialReadSupported
}

type dummyDevice struct {
	d *Device
	f *os.File
}

func (d *dummyDevice) Open() (tpm2.Transport, error) {
	return newTransport(&tpmFile{file: d.f}, false, maxResponseSize), nil
}

func (d *dummyDevice) String() string {
	return d.d.String()
}

func (d *Device) maxResponseSize(f *os.File) uint32 {
	d.mrsOnce.Do(func() {
		d.deviceMaxResponseSize = func() uint32 {
			tpm, err := tpm2.OpenTPMDevice(&dummyDevice{d: d, f: f})
			if err != nil {
				return maxResponseSize
			}

			sz, err := tpm.GetCapabilityTPMProperty(tpm2.PropertyMaxResponseSize)
			if err != nil {
				return maxResponseSize
			}
			return sz
		}()
	})
	return d.deviceMaxResponseSize
}

func (d *Device) openInternal() (*Transport, error) {
	f, err := os.OpenFile(d.path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	partialReadSupported := d.partialReadSupported(f)
	var maxResponseSize uint32
	if !partialReadSupported {
		maxResponseSize = d.maxResponseSize(f)
	}

	return newTransport(&tpmFile{file: f}, partialReadSupported, maxResponseSize), nil
}

// Path returns the path of the character device.
func (d *Device) Path() string {
	return d.path
}

// SysfsPath returns the path of the device in sysfs.
func (d *Device) SysfsPath() string {
	return d.sysfsPath
}

// MajorVersion indicates the TPM version.
func (d *Device) MajorVersion() TPMMajorVersion {
	return d.version
}

// PartialReadSupported indicates whether the TPM character device supports
// partial reads.
func (d *Device) PartialReadSupported() bool {
	return d.partialReadSupported(nil)
}

// Open implements [tpm2.TPMDevice.Open]. The returned transport cannot be used from multiple
// goroutines simultaneously.
func (d *Device) Open() (tpm2.Transport, error) {
	return d.openInternal()
}

// String implements [fmt.Stringer].
func (d *Device) String() string {
	return "linux TPM character device: " + d.path
}

// TPMDeviceRaw represents a raw Linux TPM character device.
//
// Deprecated: use [DirectDevice].
type TPMDeviceRaw = DirectDevice

// RawDevice represents a raw Linux TPM character device.
//
// Deprecated: use [DirectDevice].
type RawDevice = DirectDevice

// DirectDevice represents a direct Linux TPM character device. These devices don't
// use the kernel's resource manager. It is safe to use this from multiple goroutines
// simultaneously.
type DirectDevice struct {
	Device
	devno int

	ppiOnce sync.Once
	ppi     ppi.PPI
	ppiErr  error

	rmOnce sync.Once
	rm     *RMDevice
	rmErr  error
}

// PhysicalPresenceInterface returns the physical presence interface associated
// with this device. This will return the EFI implementation if it's supported, else
// it will return the ACPI implementation that is exposed via sysfs if supported.
// If no implementation is supported, an [ErrNoPhysicalPresenceInterface] error
// will be returned. Calling this function will always return either a pointer to
// the same interface or the same error for the lifetime of a process.
func (d *DirectDevice) PhysicalPresenceInterface() (ppi.PPI, error) {
	d.ppiOnce.Do(func() {
		d.ppi, d.ppiErr = func() (ppi.PPI, error) {
			requestedPpiType, requestedPpiTypeSet := loadForcedPpiType()

			var (
				efiPpi ppi.PPI
				efiErr error = ErrNoPhysicalPresenceInterface
			)
			if !requestedPpiTypeSet || requestedPpiType == ppi.EFI {
				// Try to instantiate the EFI PPI implementation first. Linux only associates
				// the ACPI PPI exposed via sysfs to TPM devices that have a corresponding
				// node in the ACPI device tree. We'll implement the same behaviour for the
				// EFI PPI - it will only be accessible from TPM device instances that have a
				// node in the device tree.
				_, efiErr = os.Stat(filepath.Join(d.sysfsPath, "device", "firmware_node"))
				switch {
				case errors.Is(efiErr, os.ErrNotExist) || errors.Is(efiErr, os.ErrPermission):
					efiErr = ErrNoPhysicalPresenceInterface
				case efiErr != nil:
					efiErr = fmt.Errorf("cannot test whether TPM device is linked to a device tree node: %w", efiErr)
				default:
					var backend internal_ppi_efi.PPIBackend
					var version ppi.Version
					backend, version, efiErr = internal_ppi_efi.NewBackend(customEfiVars)
					switch {
					case errors.Is(efiErr, internal_ppi_efi.ErrUnavailable):
						// EFI PPI is unavailable. Fall through to trying ACPI PPI.
						efiErr = ErrNoPhysicalPresenceInterface
					case efiErr != nil:
						// Instantiating EFI PPI failed with an unexpected error.
						// Do nothing with this error - it will be wrapped below.
						// Fall through to trying ACPI PPI.
					case backend.SupportsConfig():
						// Use the EFI PPI implementation
						return internal_ppi.New(ppi.EFI, version, backend), nil
					default:
						// The EFI PPI implementation doesn't support Tcg2PhysicalPresenceConfig.
						// Save it for now, and only use it if we can't use the ACPI PPI
						// implementation.
						efiPpi = internal_ppi.New(ppi.EFI, version, backend)
					}
				}
			}

			var acpiErr error = ErrNoPhysicalPresenceInterface
			if !requestedPpiTypeSet || requestedPpiType == ppi.ACPI {
				// Try to instantiate the ACPI PPI implementation that's exposed via sysfs.
				var backend *acpiPpiImpl
				backend, acpiErr = newAcpiPpi(filepath.Join(d.sysfsPath, "ppi"))
				switch {
				case errors.Is(acpiErr, os.ErrNotExist) || errors.Is(acpiErr, os.ErrPermission):
					// ACPI PPI is unavailable.
					acpiErr = ErrNoPhysicalPresenceInterface
				case acpiErr != nil:
					// Instantiating ACPI PPI failed with an unexpected error.
					// Do nothing with this error - it will be wrapped below.
				default:
					// Use the ACPI PPI implementation.
					return internal_ppi.New(ppi.ACPI, backend.Version, backend), nil
				}
			}

			if efiPpi != nil {
				// We can't use the ACPI PPI implementation, but we can use the EFI PPI
				// implementation with the caveat that it doesn't support
				// Tcg2PhysicalPresenceConfig, so just return that.
				return efiPpi, nil
			}

			// Instantiating a PPI instance failed, so handle the errors here.
			switch {
			case acpiErr == ErrNoPhysicalPresenceInterface && efiErr == ErrNoPhysicalPresenceInterface:
				// Both PPI implementations are unavailable.
				return nil, ErrNoPhysicalPresenceInterface
			case efiErr == ErrNoPhysicalPresenceInterface:
				// The EFI implementation is unavailable and the ACPI implementation returned an
				// unexpected error. Return the ACPI error.
				return nil, fmt.Errorf("no EFI PPI available and cannot initialize ACPI PPI backend: %w", acpiErr)
			case acpiErr == ErrNoPhysicalPresenceInterface:
				// The ACPI implementation is unavailable and the EFI implementation returned an
				// unexpected error. Return the EFI error.
				return nil, fmt.Errorf("no ACPI PPI available and cannot initialize EFI PPI backend: %w", efiErr)
			default:
				// Both implementations returned an unexpected error. Return both errors.
				// TODO: Use errors.Join when we can depend on go1.20. For now, we'll
				// return both errors without any wrapping.
				return nil, fmt.Errorf("cannot initialize EFI PPI backend: %v\ncannot initialize ACPI PPI backend: %v", efiErr, acpiErr)

			}
		}()
	})

	return d.ppi, d.ppiErr
}

// ResourceManagedDevice returns the corresponding resource managed device if one
// is available. If there isn't one, a [ErrNoResourceManagedDevice] error is returned.
// Calling  this function will always return either a pointer to the same interface or
// the same error for the lifetime of a process.
func (d *DirectDevice) ResourceManagedDevice() (*RMDevice, error) {
	d.rmOnce.Do(func() {
		d.rm, d.rmErr = func() (*RMDevice, error) {
			if d.version != TPMVersion2 {
				// the kernel resource manager is only available for TPM2 devices.
				return nil, ErrNoResourceManagedDevice
			}

			base := fmt.Sprintf("tpmrm%d", d.devno)
			sysfsPath, err := filepath.EvalSymlinks(filepath.Join(d.sysfsPath, "device/tpmrm", base))
			switch {
			case os.IsNotExist(err):
				// the kernel is probably too old
				return nil, ErrNoResourceManagedDevice
			case err != nil:
				return nil, err
			default:
				return &RMDevice{
					Device: Device{
						path:      filepath.Join(devPath, base),
						sysfsPath: sysfsPath,
						version:   d.version},
					raw: d}, nil
			}
		}()
	})
	return d.rm, d.rmErr
}

// TPMDeviceRM represents a Linux TPM character device that makes use of the kernel
// resource manager.
//
// Deprecated: use [RMDevice].
type TPMDeviceRM = RMDevice

// RMDevice represents a Linux TPM character device that makes use of the kernel
// resource manager. It is safe to use this from multiple goroutines simultaneously.
type RMDevice struct {
	Device
	raw *DirectDevice
}

// DirectDevice returns the corresponding raw device.
func (d *RMDevice) DirectDevice() *DirectDevice {
	return d.raw
}

// OpenDevice attempts to open a connection to the Linux TPM character device at
// the specified path. If successful, it returns a new Transport instance which
// can be passed to tpm2.NewTPMContext. Failure to open the TPM character device
// will result in a *os.PathError being returned.
//
// Deprecated: Use [DirectDevice] and [RMDevice].
func OpenDevice(path string) (*Transport, error) {
	device := &Device{path: path}
	tcti, err := device.openInternal()
	if err != nil {
		return nil, err
	}

	s, err := tcti.statter.Stat()
	if err != nil {
		tcti.Close()
		return nil, err
	}

	if s.Mode()&os.ModeDevice == 0 {
		tcti.Close()
		return nil, fmt.Errorf("unsupported file mode %v", s.Mode())
	}

	return tcti, nil
}

func tpmDeviceVersion(path string) (TPMMajorVersion, error) {
	versionPath := filepath.Join(path, "tpm_version_major")

	versionBytes, err := os.ReadFile(versionPath)
	switch {
	case os.IsNotExist(err):
		// Handle older kernels that didn't have this attribute file. There were no other
		// sysfs attributes for TPM2 devices when this was introduced, so detect the
		// presence of a TPM1.2 device by testing that a known attribute file exists.
		// This attribute exists for as far as I can check back in the kernel git tree.
		_, err := os.Stat(filepath.Join(path, "pcrs"))
		switch {
		case os.IsNotExist(err):
			return TPMVersion2, nil
		case err != nil:
			return 0, err
		default:
			return TPMVersion1, nil
		}
	case err != nil:
		return 0, err
	default:
		version, err := strconv.Atoi(strings.TrimSpace(string(versionBytes)))
		if err != nil {
			return 0, err
		}
		switch version {
		case 1, 2:
			return TPMMajorVersion(version), nil
		default:
			return 0, fmt.Errorf("unexpected version %d", version)
		}
	}
}

func probeTpmDevices() (out []*DirectDevice, err error) {
	class := filepath.Join(sysfsPath, "class/tpm")

	f, err := os.Open(class)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	entries, err := f.ReadDir(0)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		var devno int
		if _, err := fmt.Sscanf(entry.Name(), "tpm%d", &devno); err != nil {
			return nil, fmt.Errorf("unexpected name \"%s\": %w", entry.Name(), err)
		}

		sysfsPath, err := filepath.EvalSymlinks(filepath.Join(class, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("cannot resolve path for \"%s\": %w", entry.Name(), err)
		}

		version, err := tpmDeviceVersion(sysfsPath)
		if err != nil {
			return nil, fmt.Errorf("cannot determine version of TPM device at %s: %w", sysfsPath, err)
		}

		out = append(out, &DirectDevice{
			Device: Device{
				path:      filepath.Join(devPath, entry.Name()),
				sysfsPath: sysfsPath,
				version:   version},
			devno: devno,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].devno < out[j].devno
	})
	return out, nil
}

// ListTPMDevices returns a list of all TPM devices. Note that this returns all
// devices, regardless of version. Calling this function always returns the same
// slice or the same error for the lifetime of a process. It is safe to call this
// function from multiple goroutines simultaneously.
func ListTPMDevices() (out []*DirectDevice, err error) {
	devices.once.Do(func() {
		devices.devices, devices.err = probeTpmDevices()
	})
	return devices.devices, devices.err
}

// ListTPMDevices returns a list of all TPM2 devices. Calling this function always
// returns the same slice or the same error for the lifetime of a process. It is
// safe to call this function from multiple goroutines simultaneously.
func ListTPM2Devices() (out []*DirectDevice, err error) {
	candidates, err := ListTPMDevices()
	if err != nil {
		return nil, err
	}
	for _, device := range candidates {
		if device.MajorVersion() != TPMVersion2 {
			continue
		}
		out = append(out, device)
	}

	return out, err
}

// DefaultTPMDevice returns the default TPM device. If there are no devices
// available, then [ErrNoTPMDevices] is returned. Calling this function always
// returns a pointer to the same device or the same error for the lifetime of
// a process. It is safe to call this function from multiple goroutines
// simultaneously.
func DefaultTPMDevice() (*DirectDevice, error) {
	devices, err := ListTPMDevices()
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, ErrNoTPMDevices
	}
	return devices[0], nil
}

// DefaultTPM2Device returns the default TPM2 device. If there are no devices
// available, then [ErrNoTPMDevices] is returned. If the default TPM device is
// not a TPM2 device, then [ErrDefaultNotTPM2Device] is returned. Calling this
// function always returns a pointer to the same device or the same error for the
// lifetime of a process. It is safe to call this function from multiple goroutines
// simultaneously.
func DefaultTPM2Device() (*DirectDevice, error) {
	device, err := DefaultTPMDevice()
	if err != nil {
		return nil, err
	}
	if device.MajorVersion() != TPMVersion2 {
		return nil, ErrDefaultNotTPM2Device
	}
	return device, nil
}
