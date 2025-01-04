// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"errors"
	"io"
	"os"
	"syscall"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/transportutil"
)

const (
	maxCommandSize  = 4096
	maxResponseSize = 4096
)

type fileStatter interface {
	Stat() (os.FileInfo, error)
}

// Tcti represents a connection to a Linux TPM character device.
//
// Deprecated: Use [Transport].
type Tcti = Transport

// Transport represents a connection to a Linux TPM character device. It is not intended to be
// used from multiple goroutines simultaneously.
type Transport struct {
	r       transportutil.ResponseBuffer
	w       io.Writer
	closer  io.Closer
	statter fileStatter
}

func newTransport(file *tpmFile, partialReadSupported bool, maxResponseSize uint32) *Transport {
	var r transportutil.ResponseBuffer = file
	if !partialReadSupported {
		r = transportutil.BufferResponses(r, maxResponseSize)
	}
	return &Transport{
		r:       r,
		w:       transportutil.BufferCommands(file, maxCommandSize),
		closer:  file,
		statter: file,
	}
}

// Read implmements [tpm2.Transport].
func (d *Transport) Read(data []byte) (int, error) {
	return d.r.Read(data)
}

// Write implmements [tpm2.Transport].
func (d *Transport) Write(data []byte) (int, error) {
	if d.r.Len() > 0 {
		return 0, tpm2.ErrTransportBusy
	}
	n, err := d.w.Write(data)
	switch {
	case errors.Is(err, syscall.Errno(syscall.EBUSY)):
		return 0, tpm2.ErrTransportBusy
	case err != nil:
		return 0, err
	default:
		return n, nil
	}
}

// Close implements [tpm2.Transport.Close].
func (d *Transport) Close() error {
	if err := d.closer.Close(); err != nil {
		if errors.Is(err, os.ErrClosed) {
			return tpm2.ErrTransportClosed
		}
		return err
	}
	return nil
}
