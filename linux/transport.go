// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"bytes"
	"io"
	"syscall"
)

const (
	maxCommandSize int = 4096
)

// Tcti represents a connection to a Linux TPM character device.
//
// Deprecated: Use [Transport].
type Tcti = Transport

// Transport represents a connection to a Linux TPM character device.
type Transport struct {
	file *tpmFile
	rsp  *bytes.Reader
}

func (d *Transport) readNextResponse() error {
	buf := make([]byte, maxCommandSize)
	n, err := d.file.Read(buf)
	if err != nil {
		return err
	}

	d.rsp = bytes.NewReader(buf[:n])
	return nil
}

// Read implmements [tpm2.Transport].
func (d *Transport) Read(data []byte) (int, error) {
	// TODO: Support for partial reads on newer kernels
	if d.rsp == nil {
		if err := d.readNextResponse(); err != nil {
			return 0, err
		}
	}

	n, err := d.rsp.Read(data)
	if err == io.EOF {
		d.rsp = nil
	}
	return n, err
}

// Write implmements [tpm2.Transport].
func (d *Transport) Write(data []byte) (int, error) {
	if d.rsp != nil {
		// Don't start a new command before the previous response has been fully read.
		// This doesn't catch the case where we haven't fetched the previous response
		// from the device, but the subsequent write will fail with -EBUSY
		return 0, d.file.wrapErr("write", syscall.EBUSY)
	}

	return d.file.Write(data)
}

// Close implements [tpm2.Transport.Close].
func (d *Transport) Close() error {
	return d.file.Close()
}
