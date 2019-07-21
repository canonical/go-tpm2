package tpm2

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

type tctiDeviceLinux struct {
	f *os.File
}

func (d *tctiDeviceLinux) Read(data []byte) (int, error) {
	fds := []unix.PollFd{unix.PollFd{Fd: int32(d.f.Fd()), Events: unix.POLLIN}}
	_, err := unix.Ppoll(fds, nil, nil)
	if err != nil {
		return 0, fmt.Errorf("poll failed: %v", err)
	}

	if fds[0].Events != fds[0].Revents {
		return 0, fmt.Errorf("invalid poll events returned: %d", fds[0].Revents)
	}

	return d.f.Read(data)
}

func (d *tctiDeviceLinux) Write(data []byte) (int, error) {
	return d.f.Write(data)
}

func (d *tctiDeviceLinux) Close() error {
	return d.f.Close()
}

func OpenTPMDevice(path string) (io.ReadWriteCloser, error) {
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

	return &tctiDeviceLinux{f: f}, nil
}
