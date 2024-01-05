// Copyright 2019-2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"io"
	"os"
	"syscall"
)

// The TPM character device's read and poll implementations are a bit funky, in a way that
// doesn't play nicely with go's netpoller. The read() implementation can return 0 instead of
// -EWOULDBLOCK when there is no response ready to read. This is a problem because go's
// internal/poll will attempt to read before waiting, which means that the os.File.Read()
// implementation just returns io.EOF when it should park the routine and poll the device
// descriptor instead.
//
// To work around this, we use raw read and write system calls via the syscall.RawConn
// implementation provided by os.File. The read and write callbacks provided to these return
// a boolean which indicates whether the operation should complete, or whether the operation
// should block and poll the descriptor to become ready.
//
// In the read case, we immediately block and poll the device, before performing the read whenever
// the device becomes ready in the future. Skipping the initial read and polling immediately works
// around another issue with the way that the driver works. The read() implementation can block
// until the current command completes, even in non-blocking mode, if we call it whilst the
// kernel's TPM async worker is dispatching the command. This is because both reading and command
// dispatching take a lock on the command/response buffer.
//
// This still doesn't really work properly though, as the poll() implementation can also block
// for the same reason (the poll implementation also locks the command/response buffer). As the
// poll() implementation blocks before the system call would normally suspend the current task
// in the VFS layer, this means that polling can potentially ignore any specified timeout if it
// is called whilst a TPM command is being dispatched.
//
// We never block and poll the device in the write case. Although the write() implementation
// will return -EBUSY if there is a response waiting to be read from the device, it's not
// possible to poll the device to wait for it to become ready for writing because there is
// nothing in the read() implementation that will wake a sleeping task when the device becomes
// ready for writing.

func ignoringEINTR(fn func() (int, error)) (int, error) {
	for {
		n, err := fn()
		if err != syscall.EINTR {
			return n, err
		}
	}
}

type tpmFile struct {
	file *os.File
}

func (f *tpmFile) wrapErr(op string, err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if err == errClosed {
		err = os.ErrClosed
	}
	return &os.PathError{
		Op:   op,
		Path: f.file.Name(),
		Err:  err}
}

func (f *tpmFile) Read(data []byte) (n int, err error) {
	conn, err := f.file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var readErr error
	polled := false
	if err := conn.Read(func(fd uintptr) bool {
		if !polled {
			// always poll before reading - see the comments above.
			polled = true
			return false
		}
		n, readErr = ignoringEINTR(func() (int, error) {
			return syscall.Read(int(fd), data)
		})
		return true
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, f.wrapErr("read", errClosed)
	}
	if n == 0 && readErr == nil {
		readErr = io.EOF
	}
	return n, f.wrapErr("read", readErr)
}

func (f *tpmFile) Write(data []byte) (n int, err error) {
	conn, err := f.file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var writeErr error
	if err := conn.Write(func(fd uintptr) bool {
		n, writeErr = ignoringEINTR(func() (int, error) {
			return syscall.Write(int(fd), data)
		})
		return true
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, f.wrapErr("write", errClosed)
	}
	if n < len(data) && writeErr == nil {
		writeErr = io.ErrShortWrite
	}
	return n, f.wrapErr("write", writeErr)
}

func (f *tpmFile) Close() error {
	return f.file.Close()
}

func (f *tpmFile) Stat() (os.FileInfo, error) {
	return f.file.Stat()
}
