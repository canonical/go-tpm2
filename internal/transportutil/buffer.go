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

// BufferCommands buffers command packets written to the returned writer and
// writes complete packets to the supplied writer in a single write. The
// maxCommandSize argument defines the maximum size of a command.
func BufferCommands(w io.Writer, maxCommandSize uint32) io.Writer {
	return &commandBuffer{w: w, maxCommandSize: maxCommandSize}
}

func (b *commandBuffer) Write(data []byte) (n int, err error) {
	n = len(data)
	buf := append(b.buf, data...)

	// Try to decode a command header
	var hdr tpm2.CommandHeader
	_, err = mu.UnmarshalFromBytes(buf, &hdr)
	switch {
	case errors.Is(err, io.ErrUnexpectedEOF):
		// We don't have a command header yet, so queue the write
		b.buf = buf
		return n, nil
	case err != nil:
		return 0, fmt.Errorf("cannot decode command header: %w", err)
	case hdr.CommandSize > b.maxCommandSize:
		return 0, fmt.Errorf("invalid command size (%d bytes)", hdr.CommandSize)
	}

	// We have a command header, so queue the write
	b.buf = buf

	if len(b.buf) < int(hdr.CommandSize) {
		// Not enough bytes yet
		return n, nil
	}

	// We have enough bytes. Clear the buffer on return
	defer func() { b.buf = nil }()

	// Send the command
	cmd := b.buf[:int(hdr.CommandSize)]
	remaining := len(b.buf[int(hdr.CommandSize):])
	if _, err := b.w.Write(cmd); err != nil {
		return n, err
	}

	if remaining > 0 {
		// Discard excess bytes and return an appropriate error
		return n - remaining, io.ErrShortWrite
	}

	return n, nil
}

type responseBuffer struct {
	r               io.Reader
	maxResponseSize uint32
	rsp             io.Reader
}

// BufferResponses reads complete response packets from the supplied reader
// in a single read and makes them available to the returned reader for partial
// reading. The maxResponseSize argument defines the size of the read on the
// supplied reader.
func BufferResponses(r io.Reader, maxResponseSize uint32) io.Reader {
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
	for {
		if b.rsp == nil {
			if err := b.readNextResponse(); err != nil {
				return 0, err
			}
		}

		n, err = b.rsp.Read(data)
		if err == io.EOF {
			b.rsp = nil
			err = nil
			if n == 0 {
				continue
			}
		}
		return n, err
	}
}
