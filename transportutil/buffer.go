package transportutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
)

type commandBuffer struct {
	w              io.Writer
	maxCommandSize uint32
	buf            []byte
}

type CommandBuffer interface {
	io.Writer

	// Len is the number of bytes currently in the command buffer.
	Len() int
}

// BufferCommands buffers writes written to the returned CommandBuffer and
// writes complete commnd packets to the supplied io.Writer in a single
// write. The maxCommandSize argument defines the maximum size of a
// command. If the commandSize field of a command header indicates the
// command packet size will be larger than maxCommandSize, an error will
// be returned.
//
// If the supplied io.Writer returns an error on submission of a command
// packet, the entire packet is discarded.
//
// The returned CommandBuffer only supports TPM command packets. It will fail if
// any other type of packet is sent through it (eg, packets that have been
// encapsulated for a specific transport), because it depends on being able
// to decode the command header.
func BufferCommands(w io.Writer, maxCommandSize uint32) CommandBuffer {
	return &commandBuffer{w: w, maxCommandSize: maxCommandSize}
}

func (b *commandBuffer) Write(data []byte) (n int, err error) {
	n = len(data)                 // The size of the buffer passed to us.
	buf := append(b.buf, data...) // Append the supplied buffer to what we have from previous writes and and store the slice in a temporary variable

	// Try to decode a command header from all of the data we have already.
	var hdr tpm2.CommandHeader
	_, err = mu.UnmarshalFromBytes(buf, &hdr)
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		// We don't have enough bytes for a command header yet. Store the temporary
		// buffer that we have for the next write.
		b.buf = buf
		return n, nil
	case err != nil:
		// This is an unexpected error.
		return 0, fmt.Errorf("cannot decode command header: %w", err)
	case hdr.CommandSize > b.maxCommandSize:
		// The decoded command header has an invalid command size.
		return 0, fmt.Errorf("invalid command size (%d bytes)", hdr.CommandSize)
	}

	// We have a command header. Save the temporary buffer slice which contains
	// the current write appended to all previous writes.
	b.buf = buf

	if len(b.buf) < int(hdr.CommandSize) {
		// We don't have enough bytes for a complete command yet, so return
		// now and wait for more writes.
		return n, nil
	}

	// We have enough bytes. Clear the buffer unconditionally on return,
	// including any error paths where they are encountered.
	defer func() { b.buf = nil }()

	// Send the command to the originally supplied io.Writer in a
	// single call.
	cmd := b.buf[:int(hdr.CommandSize)]
	remaining := len(b.buf[int(hdr.CommandSize):])
	if _, err := b.w.Write(cmd); err != nil {
		return n, err
	}

	if remaining > 0 {
		// The caller supplied too many bytes for the command. Discard
		// the excess bytes, adjust n accordingly and return an
		// appropriate error.
		return n - remaining, io.ErrShortWrite
	}

	// Command sending completed successfully.
	return n, nil
}

func (b *commandBuffer) Len() int {
	return len(b.buf)
}

type responseBuffer struct {
	r               io.Reader
	maxResponseSize uint32
	rsp             *bytes.Reader
}

type ResponseBuffer interface {
	io.Reader

	// Len is the remaining number of bytes to read.
	Len() int
}

// BufferResponses reads complete response packets from the supplied reader
// in a single read and makes them available to the returned ResponseBuffer for
// partial reading. The maxResponseSize argument defines the size of the read on
// the supplied reader.
//
// The supplied reader will be passed a buffer of size maxResponseSize. It must
// return a complete response packet when ready - it must not block waiting to
// fill the supplied buffer.
func BufferResponses(r io.Reader, maxResponseSize uint32) ResponseBuffer {
	return &responseBuffer{r: r, maxResponseSize: maxResponseSize}
}

func (b *responseBuffer) readNextResponse() error {
	buf := make([]byte, b.maxResponseSize)
	n, err := b.r.Read(buf)
	if err != nil {
		return err
	}

	b.rsp = bytes.NewReader(buf[:n])
	return nil
}

func (b *responseBuffer) Read(data []byte) (n int, err error) {
	if b.rsp == nil {
		if err := b.readNextResponse(); err != nil {
			return 0, err
		}
	}

	n, err = b.rsp.Read(data)
	if b.rsp.Len() == 0 {
		// We've read all of the bytes from this response.
		b.rsp = nil // Make the next call wait for another response.

		if err == io.EOF {
			// It's possible we could get a io.EOF from the bytes.Reader here, but
			// tpm2.Transport.Read should never return this unless it will never
			// return any more bytes (eg, after it's closed). In this case, clear
			// the error.
			err = nil
		}
	}
	return n, err
}

func (b *responseBuffer) Len() int {
	if b.rsp == nil {
		return 0
	}
	return b.rsp.Len()
}
