// Copyright 2019-2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/canonical/go-tpm2/transportutil"
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
// In the read case, we perform a read and then block and poll the device if this read returned
// no errors and zero bytes, before performing another read whenever the device becomes ready in
// the future.
//
// Note that the read() system call can block until the current command completes, even in
// non-blocking mode, if we call it whilst the kernel's TPM async worker is dispatching the
// command. This is because both reading and command dispatching take a lock on the
// command/response buffer. Ideally we would work around this by polling before reading, but
// this doesn't work properly because go's netpoller uses epoll with edge-triggered polling,
// so polling before reading can result in the routine becoming permanently blocked.
//
// Polling can also block for the same reason (the poll implementation for the TPM character
// device also locks the command/response buffer). As the poll implementation blocks before the
// system call would normally suspend the current task in the VFS layer, this means that polling
// can potentially ignore any specified timeout if it is called whilst a TPM command is being
// dispatched.
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
	return &os.PathError{
		Op:   op,
		Path: f.file.Name(),
		Err:  err}
}

func (f *tpmFile) ReadNonBlocking(data []byte) (n int, err error) {
	conn, err := f.file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var readErr error
	if err := conn.Read(func(fd uintptr) bool {
		n, readErr = ignoringEINTR(func() (int, error) {
			return syscall.Read(int(fd), data)
		})
		return true
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, f.wrapErr("read", transportutil.ErrClosed)
	}
	return n, f.wrapErr("read", readErr)
}

func (f *tpmFile) Read(data []byte) (n int, err error) {
	conn, err := f.file.SyscallConn()
	if err != nil {
		return 0, err
	}

	var readErr error
	if err := conn.Read(func(fd uintptr) bool {
		n, readErr = ignoringEINTR(func() (int, error) {
			return syscall.Read(int(fd), data)
		})
		return n > 0
	}); err != nil {
		// The only error that can be returned from this is poll.ErrFileClosing
		// which is private
		return 0, f.wrapErr("read", transportutil.ErrClosed)
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
		return 0, f.wrapErr("write", transportutil.ErrClosed)
	}
	switch {
	case errors.Is(writeErr, syscall.Errno(syscall.EBUSY)):
		writeErr = transportutil.ErrBusy
	case n < len(data) && writeErr == nil:
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
