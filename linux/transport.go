// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package linux

import (
	"io"
	"os"

	"github.com/canonical/go-tpm2/internal/transportutil"
)

const (
	maxCommandSize  = 4096
	maxResponseSize = 4096
)

type fileStatter interface {
	Stat() (os.FileInfo, error)
}

// transport represents a connection to a Linux TPM character device.
type transport struct {
	r       io.Reader
	w       io.Writer
	closer  io.Closer
	statter fileStatter
}

func newTransport(file *tpmFile, partialReadSupported bool, maxResponseSize uint32) *transport {
	var r io.Reader = file
	if !partialReadSupported {
		r = transportutil.BufferResponses(r, maxResponseSize)
	}
	return &transport{
		r:       r,
		w:       transportutil.BufferCommands(file, maxCommandSize),
		closer:  file,
		statter: file,
	}
}

// Read implmements [tpm2.transport].
func (d *transport) Read(data []byte) (int, error) {
	return d.r.Read(data)
}

// Write implmements [tpm2.transport].
func (d *transport) Write(data []byte) (int, error) {
	return d.w.Write(data)
}

// Close implements [tpm2.transport.Close].
func (d *transport) Close() error {
	return d.closer.Close()
}
