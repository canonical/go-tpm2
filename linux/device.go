// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/canonical/go-tpm2"
	internal_ppi "github.com/canonical/go-tpm2/internal/ppi"
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

	errClosed = errors.New("use of closed file")

	sysfsPath = "/sys"
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
	devices []*RawDevice
	err     error
}

var devices tpmDevices

// TPMMajorVersion describes the major version of a TPM device.
type TPMMajorVersion int

const (
	TPMVersion1 TPMMajorVersion = 1
	TPMVersion2 TPMMajorVersion = 2
)

// Device represents a Linux TPM character device.
type Device struct {
	path      string
	sysfsPath string
	version   TPMMajorVersion

	prsOnce              sync.Once
	partialReadSupported bool

	mrsOnce sync.Once
	mrs     uint32
}

func (d *Device) checkPartialReadSupport() {
	d.prsOnce.Do(func() {
		d.partialReadSupported = func() bool {
			f, err := os.OpenFile(d.path, os.O_RDWR, 0)
			if err != nil {
				return false
			}

			tf := &tpmFile{file: f}
			defer tf.Close()

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
		d.mrs = func() uint32 {
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
	return d.mrs
}

func (d *Device) openInternal() (*Transport, error) {
	d.checkPartialReadSupport()

	f, err := os.OpenFile(d.path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var mrs uint32
	if !d.partialReadSupported {
		mrs = d.maxResponseSize(f)
	}

	return newTransport(&tpmFile{file: f}, d.partialReadSupported, mrs), nil
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
	d.checkPartialReadSupport()
	return d.partialReadSupported
}

// Open implements [tpm2.TPMDevice.Open].
func (d *Device) Open() (tpm2.Transport, error) {
	return d.openInternal()
}

// String implements [fmt.Stringer].
func (d *Device) String() string {
	return "linux TPM character device: " + d.path
}

// RawDevice represents a raw Linux TPM character device.
type RawDevice struct {
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
// with this device.
func (d *RawDevice) PhysicalPresenceInterface() (ppi.PPI, error) {
	d.ppiOnce.Do(func() {
		d.ppi, d.ppiErr = func() (ppi.PPI, error) {
			backend, err := newSysfsPpi(filepath.Join(d.sysfsPath, "ppi"))
			switch {
			case os.IsNotExist(err):
				return nil, ErrNoPhysicalPresenceInterface
			case err != nil:
				return nil, fmt.Errorf("cannot initialize PPI backend: %w", err)
			}

			return internal_ppi.New(backend.Version, backend), nil
		}()
	})
	return d.ppi, d.ppiErr
}

// ResourceManagedDevice returns the corresponding resource managed device if one
// is available.
func (d *RawDevice) ResourceManagedDevice() (*RMDevice, error) {
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

// RMDevice represents a Linux TPM character device that makes use of the kernel
// resource manager.
type RMDevice struct {
	Device
	raw *RawDevice
}

// RawDevice returns the corresponding raw device.
func (d *RMDevice) RawDevice() *RawDevice {
	return d.raw
}

// OpenDevice attempts to open a connection to the Linux TPM character device at
// the specified path. If successful, it returns a new Transport instance which
// can be passed to tpm2.NewTPMContext. Failure to open the TPM character device
// will result in a *os.PathError being returned.
//
// Deprecated: Use [RawDevice] and [RMDevice].
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

	versionBytes, err := ioutil.ReadFile(versionPath)
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

func probeTpmDevices() (out []*RawDevice, err error) {
	class := filepath.Join(sysfsPath, "class/tpm")

	f, err := os.Open(class)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	entries, err := f.Readdir(0)
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

		out = append(out, &RawDevice{
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

// ListTPMDevices returns a list of all TPM devices. Note that this returns
// all devices, regardless of version.
func ListTPMDevices() (out []*RawDevice, err error) {
	devices.once.Do(func() {
		devices.devices, devices.err = probeTpmDevices()
	})
	return devices.devices, devices.err
}

// ListTPMDevices returns a list of all TPM2 devices.
func ListTPM2Devices() (out []*RawDevice, err error) {
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
// available, then [ErrNoTPMDevices] is returned.
func DefaultTPMDevice() (*RawDevice, error) {
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
// not a TPM2 device, then [ErrDefaultNotTPM2Device] is returned.
func DefaultTPM2Device() (*RawDevice, error) {
	device, err := DefaultTPMDevice()
	if err != nil {
		return nil, err
	}
	if device.MajorVersion() != TPMVersion2 {
		return nil, ErrDefaultNotTPM2Device
	}
	return device, nil
}
