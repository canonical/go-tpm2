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

var (
	// ErrTimeoutNotSupported indicates that a [Transport] implementation does not support
	// configuring the command timeout.
	ErrTimeoutNotSupported = errors.New("configurable command timeouts are not supported")

	// ErrTransportBusy should be returned from calls to Write if a previously
	// submitted command has not finished or not all of its bytes have
	// been read back yet.
	ErrTransportBusy = errors.New("transport is busy")

	// ErrTransportClosed indicates that a transport is closed.
	ErrTransportClosed = errors.New("transport already closed")
)

// TCTI represents a communication channel to a TPM implementation.
//
// Deprecated: use [Transport] instead.
type TCTI = Transport

// Transport represents a communication channel to a TPM implementation.
//
// Implementations of the [io.Reader] and [io.Writer] parts of this can expect that they
// will be called from the same goroutine and that they won't be used from multiple
// goroutines.
//
// Implementations should handle the [io.Closer] part being called from any goroutine,
// even when a Read or Write is in progress on another goroutine.
type Transport interface {
	// Read is used to receive a response to a previously transmitted command.
	// Implementations should support a response being read using multiple calls
	// to Read (partial reads). The transportutil.BufferResponses API can assist
	// for transports that don't support this. Implementations that support
	// partial reads should not return parts of more than one command in a single
	// call.
	//
	// Implementations should only use io.EOF to indicate that no more bytes will
	// ever be read from this transport. Callers should be able to identify the end
	// of a response based on the ResponseHeader itself and the number of bytes read.
	Read(p []byte) (int, error)

	// Write is used to transmit a serialized command to the TPM implementation.
	// Implementations should support a command being sent across multiple calls
	// to Write, and should be able to identify the end of a command based on the
	// CommandHeader itself. The transportutil.BufferCommands API can assist for
	// transports that don't support this.
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
