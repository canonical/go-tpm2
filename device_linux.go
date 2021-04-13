// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
	"golang.org/x/xerrors"
)

const (
	maxCommandSize int = 4096
)

// tctiDeviceLinux represents a connection to a Linux TPM character device.
type TctiDeviceLinux struct {
	f   *os.File
	buf *bytes.Reader
}

func (d *TctiDeviceLinux) readMoreData() error {
	fds := []unix.PollFd{unix.PollFd{Fd: int32(d.f.Fd()), Events: unix.POLLIN}}
	_, err := unix.Ppoll(fds, nil, nil)
	if err != nil {
		return xerrors.Errorf("polling device failed: %w", err)
	}

	if fds[0].Events != fds[0].Revents {
		return fmt.Errorf("invalid poll events returned: %d", fds[0].Revents)
	}

	buf := make([]byte, maxCommandSize)
	n, err := d.f.Read(buf)
	if err != nil {
		return xerrors.Errorf("reading from device failed: %w", err)
	}

	d.buf = bytes.NewReader(buf[:n])
	return nil
}

func (d *TctiDeviceLinux) Read(data []byte) (int, error) {
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

func (d *TctiDeviceLinux) Write(data []byte) (int, error) {
	return d.f.Write(data)
}

func (d *TctiDeviceLinux) Close() error {
	return d.f.Close()
}

func (d *TctiDeviceLinux) SetLocality(locality uint8) error {
	return errors.New("not implemented")
}

func (d *TctiDeviceLinux) MakeSticky(handle Handle, sticky bool) error {
	return errors.New("not implemented")
}

// OpenTPMDevice attempts to open a connection to the Linux TPM character device at the specified path. If successful, it returns a
// new TctiDeviceLinux instance which can be passed to NewTPMContext. Failure to open the TPM character device will result in a
// wrapped *os.PathError being returned
func OpenTPMDevice(path string) (*TctiDeviceLinux, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return nil, xerrors.Errorf("cannot open linux TPM device: %w", err)
	}

	s, err := f.Stat()
	if err != nil {
		return nil, xerrors.Errorf("cannot stat linux TPM device: %w", err)
	}

	if s.Mode()&os.ModeDevice == 0 {
		return nil, fmt.Errorf("unsupported file mode %v", s.Mode())
	}

	return &TctiDeviceLinux{f: f}, nil
}
