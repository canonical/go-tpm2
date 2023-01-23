// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package linux provides an interface for communicating with TPMs using a Linux TPM character device
*/
package linux

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/canonical/go-tpm2"
)

const (
	maxCommandSize int = 4096

	devPath = "/dev"
)

var (
	// ErrDefaultNotTPM2Device indicates that the default device is not a TPM device.
	ErrDefaultNotTPM2Device = errors.New("the default TPM device is not a TPM2 device")

	// ErrNoResourceManagedDevice indicates that a TPM device has no corresponding resource
	// managed device.
	ErrNoResourceManagedDevice = errors.New("no resource managed TPM device available")

	// ErrNoTPMDevices indicates that there are no TPM devices.
	ErrNoTPMDevices = errors.New("no TPM devices are available")

	sysfsPath = "/sys"
)

// TctiDevice represents a connection to a Linux TPM character device.
//
// Deprecated: Use Tcti
type TctiDevice = Tcti

// TPMDevice represents a Linux TPM character device.
type TPMDevice struct {
	path      string
	sysfsPath string
	version   int
}

func (d *TPMDevice) openInternal() (*Tcti, error) {
	f, err := os.OpenFile(d.path, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	return &Tcti{f: f}, nil
}

// Path returns the path of the character device.
func (d *TPMDevice) Path() string {
	return d.path
}

// SysfsPath returns the path of the device in sysfs.
func (d *TPMDevice) SysfsPath() string {
	return d.sysfsPath
}

// MajorVersion indicates the TPM version, either 1 or 2.
func (d *TPMDevice) MajorVersion() int {
	return d.version
}

// Open implements [tpm2.TPMDevice.Open].
func (d *TPMDevice) Open() (tpm2.TCTI, error) {
	return d.openInternal()
}

// String implements [fmt.Stringer].
func (d *TPMDevice) String() string {
	return "linux TPM character device: " + d.path
}

// TPMDeviceRaw represents a raw Linux TPM character device.
type TPMDeviceRaw struct {
	TPMDevice
	devno int
}

// ResourceManagedDevice returns the corresponding resource managed device if one
// is available.
func (d *TPMDeviceRaw) ResourceManagedDevice() (*TPMDeviceRM, error) {
	if d.version != 2 {
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
		return &TPMDeviceRM{
			TPMDevice: TPMDevice{
				path:      filepath.Join(devPath, base),
				sysfsPath: sysfsPath,
				version:   d.version},
			raw: d}, nil
	}
}

// TPMDeviceRM represents a Linux TPM character device that makes use of the kernel
// resource manager.
type TPMDeviceRM struct {
	TPMDevice
	raw *TPMDeviceRaw
}

// RawDevice returns the corresponding raw device.
func (d *TPMDeviceRM) RawDevice() *TPMDeviceRaw {
	return d.raw
}

// Tcti represents a connection to a Linux TPM character device.
type Tcti struct {
	f   *os.File
	buf *bytes.Reader
}

func (d *Tcti) readMoreData() error {
	fds := []unix.PollFd{unix.PollFd{Fd: int32(d.f.Fd()), Events: unix.POLLIN}}
	_, err := unix.Ppoll(fds, nil, nil)
	if err != nil {
		return fmt.Errorf("polling device failed: %w", err)
	}

	if fds[0].Events != fds[0].Revents {
		return fmt.Errorf("invalid poll events returned: %d", fds[0].Revents)
	}

	buf := make([]byte, maxCommandSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return fmt.Errorf("reading from device failed: %w", err)
	}

	d.buf = bytes.NewReader(buf[:n])
	return nil
}

// Read implmements [tpm2.TCTI].
func (d *Tcti) Read(data []byte) (int, error) {
	if d.buf == nil {
		if err := d.readMoreData(); err != nil {
			return 0, err
		}
	}

	n, err := d.buf.Read(data)
	if err == io.EOF {
		d.buf = nil
	}
	return n, err
}

// Write implmements [tpm2.TCTI].
func (d *Tcti) Write(data []byte) (int, error) {
	return d.f.Write(data)
}

// Close implements [tpm2.TCTI].
func (d *Tcti) Close() error {
	return d.f.Close()
}

// MakeSticky implements [tpm2.TCTI].
func (d *Tcti) MakeSticky(handle tpm2.Handle, sticky bool) error {
	return errors.New("not implemented")
}

// OpenDevice attempts to open a connection to the Linux TPM character device at
// the specified path. If successful, it returns a new TctiDevice instance which
// can be passed to tpm2.NewTPMContext. Failure to open the TPM character device
// will result in a *os.PathError being returned.
//
// Deprecated: Use [TPMDeviceRaw] and [TPMDeviceRM].
func OpenDevice(path string) (*Tcti, error) {
	device := &TPMDevice{path: path}
	tcti, err := device.openInternal()
	if err != nil {
		return nil, err
	}

	s, err := tcti.f.Stat()
	if err != nil {
		return nil, err
	}

	if s.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("unsupported file mode %v", s.Mode())
	}

	return tcti, nil
}

func tpmDeviceVersion(path string) (int, error) {
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
			return 2, nil
		case err != nil:
			return 0, err
		default:
			return 1, nil
		}
	case err != nil:
		return 0, err
	default:
		version, err := strconv.Atoi(strings.TrimSpace(string(versionBytes)))
		if err != nil {
			return 0, err
		}
		if version < 1 || version > 2 {
			return 0, fmt.Errorf("unexpected version %d", version)
		}
		return version, nil
	}
}

// ListTPMDevices returns a list of all TPM devices. Note that this returns
// all devices, regardless of version.
func ListTPMDevices() (out []*TPMDeviceRaw, err error) {
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

		out = append(out, &TPMDeviceRaw{
			TPMDevice: TPMDevice{
				path:      filepath.Join(devPath, entry.Name()),
				sysfsPath: sysfsPath,
				version:   version},
			devno: devno})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].devno < out[j].devno
	})
	return out, nil
}

// ListTPMDevices returns a list of all TPM2 devices.
func ListTPM2Devices() (out []*TPMDeviceRaw, err error) {
	candidates, err := ListTPMDevices()
	if err != nil {
		return nil, err
	}
	for _, device := range candidates {
		if device.MajorVersion() != 2 {
			continue
		}
		out = append(out, device)
	}

	return out, err
}

// DefaultTPMDevice returns the default TPM device. If there are no devices
// available, then [ErrNoTPMDevices] is returned.
func DefaultTPMDevice() (*TPMDeviceRaw, error) {
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
func DefaultTPM2Device() (*TPMDeviceRaw, error) {
	device, err := DefaultTPMDevice()
	if err != nil {
		return nil, err
	}
	if device.MajorVersion() != 2 {
		return nil, ErrDefaultNotTPM2Device
	}
	return device, nil
}
