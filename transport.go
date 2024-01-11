// Copyright 2020 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"errors"
	"time"
)

// InfiniteTimeout can be used to configure an infinite timeout.
const InfiniteTimeout = -1 * time.Millisecond

// ErrTimeoutNotSupported indicates that a [Transport] implementation does not support
// configuring the command timeout.
var ErrTimeoutNotSupported = errors.New("configurable command timeouts are not supported")

// Transport represents a communication channel to a TPM implementation.
type Transport interface {
	// Read is used to receive a response to a previously transmitted command. The implementation
	// must support partial reading of a response, and must return io.EOF when there are no more
	// bytes of a response left to read.
	//
	// Reads can block and should consider the previously configured timeout. Once a response
	// has been received from the device and when part of the response is read from this interface,
	// subsequent reads to obtain the rest of the response should not block.
	Read(p []byte) (int, error)

	// Write is used to transmit a serialized command to the TPM implementation. Commands are
	// written in a single write. Writes should be non blocking.
	Write(p []byte) (int, error)

	Close() error
}
