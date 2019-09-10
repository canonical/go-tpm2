// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

const (
	maxCommandSize int = 4096
)

// TctiDeviceLinux represents a connection to a Linux TPM character device.
type TctiDeviceLinux struct {
	f   *os.File
	buf *bytes.Reader
}

func (d *TctiDeviceLinux) readMoreData() error {
	fds := []unix.PollFd{unix.PollFd{Fd: int32(d.f.Fd()), Events: unix.POLLIN}}
	_, err := unix.Ppoll(fds, nil, nil)
	if err != nil {
		return fmt.Errorf("polling device failed: %v", err)
	}

	if fds[0].Events != fds[0].Revents {
		return fmt.Errorf("invalid poll events returned: %d", fds[0].Revents)
	}

	buf := make([]byte, maxCommandSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return fmt.Errorf("reading from device failed: %v", err)
	}

	d.buf = bytes.NewReader(buf[:n])
	return nil
}

func (d *TctiDeviceLinux) Read(data []byte) (int, error) {
	if d.buf == nil || d.buf.Len() == 0 {
		if err := d.readMoreData(); err != nil {
			return 0, err
		}
	}

	return d.buf.Read(data)
}

func (d *TctiDeviceLinux) Write(data []byte) (int, error) {
	return d.f.Write(data)
}

func (d *TctiDeviceLinux) Close() error {
	return d.f.Close()
}

// OpenTPMDevice attempts to open a connection to the Linux TPM character device at the specified path. If
// successful, it returns a new TctiDeviceLinux instance which can be passed to NewTPMContext.
func OpenTPMDevice(path string) (*TctiDeviceLinux, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("cannot open linux TPM device: %v", err)
	}

	s, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("cannot stat linux TPM device: %v", err)
	}

	if s.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("unsupported file mode %v", s.Mode())
	}

	return &TctiDeviceLinux{f: f}, nil
}
