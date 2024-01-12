// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"io"
	"time"
)

// InfiniteTimeout can be used to configure an infinite timeout.
const InfiniteTimeout = -1 * time.Millisecond

// ErrTimeoutNotSupported indicates that a [Transport] implementation does not support
// configuring the command timeout.
var ErrTimeoutNotSupported = errors.New("configurable command timeouts are not supported")

// Transport represents a communication channel to a TPM implementation.
type Transport interface {
	// Read is used to receive a response to a previously transmitted command.
	Read(p []byte) (int, error)

	// Write is used to transmit a serialized command to the TPM implementation.
	Write(p []byte) (int, error)

	// Close closes the transport.
	Close() error
}

type transportWriter struct {
	w io.Writer
}

func (w *transportWriter) Write(data []byte) (int, error) {
	n, err := w.w.Write(data)
	if err != nil {
		return n, &TransportError{"write", err}
	}
	return n, nil
}

func wrapTransportWriteErrors(w io.Writer) io.Writer {
	return &transportWriter{w: w}
}

type transportReader struct {
	r io.Reader
}

func (r *transportReader) Read(data []byte) (int, error) {
	n, err := r.r.Read(data)
	if err != nil {
		return n, &TransportError{"read", err}
	}
	return n, nil
}

func wrapTransportReadErrors(r io.Reader) io.Reader {
	return &transportReader{r: r}
}
