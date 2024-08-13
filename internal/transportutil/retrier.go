package transportutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"gopkg.in/tomb.v2"
)

var ErrClosed = errors.New("transport already closed")

type RetryParams struct {
	// MaxRetries is the maximum number of times a command is retried.
	MaxRetries uint

	// InitialBackoff is the amount of time to wait before submitting the
	// first retry.
	InitialBackoff time.Duration

	// BackoffRate determines how much more time to wait before submitting
	// each subsequent retry. Eg, if InitialBackoff is 20ms and this field
	// is 2, the first retry will be attempted after a delay of 20ms, then
	// the next retry after 40ms, then 80ms etc.
	BackoffRate uint
}

type retrierTransport struct {
	tomb *tomb.Tomb

	w io.WriteCloser // write channel from public io.Writer to transport routine

	r    io.ReadCloser // read channel to public io.Reader from transport routine
	rLen <-chan int64  // next response length, used to demarcate responses, sent from transport routine to public io.Reader
	rErr <-chan error  // read errors, sent from transport routine to io.Reader
	lr   io.Reader     // current response, limited by the last value read from rLen, accessed from public io.Reader

	closeErr <-chan error // close errors to public io.Closer from transport routine
}

// NewRetrierTransport returns a new transport that resubmits commands on certain
// errors, which is necessary for transports that don't already do this.
func NewRetrierTransport(transport tpm2.Transport, params RetryParams) tpm2.Transport {
	t := new(retrierTransport)

	// Construct the write channel
	wr, ww := io.Pipe()
	t.w = ww
	// wr is read by the transport routine

	// Construct the read channel
	rr, rw := io.Pipe()
	t.r = rr
	// rw is written to from the transport routine
	rLen := make(chan int64) // Used by the transport routine to tell the public io.Reader how big the next response is
	t.rLen = rLen
	rErr := make(chan error) // Used by the transport routine to signal a transport error to the public io.Reader.
	t.rErr = rErr

	// Construct the close channel
	closeErr := make(chan error) // Used by the transport routine to signal close errors to the public io.Closer.
	t.closeErr = closeErr

	tmb := new(tomb.Tomb)
	t.tomb = tmb

	// Run the transport routine
	tmb.Go(func() error {
		loop := newRetrierTransportLoop(&params, transport, tmb, wr, rw, rLen, rErr)
		err := loop.run()

		// Ensure the public calling routine gets unblocked.
		wr.Close()                    // Unblocks public io.Writer
		rw.Close()                    // Unblocks public io.Reader reads from io.LimitedReader
		close(rLen)                   // Unblocks public io.Reader waits for next response or io.Closer
		close(rErr)                   // Unblocks public io.Reader waits for next transport error or io.Closer
		closeErr <- transport.Close() // Close the underlying transport, unblocking public io.Closer with the actual error
		close(closeErr)               // Last ditch attempt to unblock public io.Closer, causing it to return ErrClosed
		return err
	})
	return t
}

type retrierTransportLoop struct {
	params    RetryParams
	transport tpm2.Transport

	tomb *tomb.Tomb

	r io.Reader

	w    io.Writer
	wLen chan<- int64
	wErr chan<- error
}

func newRetrierTransportLoop(params *RetryParams, transport tpm2.Transport, tomb *tomb.Tomb, r io.Reader, w io.Writer, wLen chan<- int64, wErr chan<- error) *retrierTransportLoop {
	return &retrierTransportLoop{
		params:    *params,
		transport: transport,
		tomb:      tomb,
		r:         r,
		w:         w,
		wLen:      wLen,
		wErr:      wErr,
	}
}

func (l *retrierTransportLoop) runCommand(commandCode tpm2.CommandCode, data []byte) ([]byte, error) {
	retryDelay := l.params.InitialBackoff

	for retries := l.params.MaxRetries; ; retries-- {
		if !l.tomb.Alive() {
			return nil, ErrClosed
		}

		// Send the command.
		if _, err := l.transport.Write(data); err != nil {
			return nil, fmt.Errorf("cannot send command: %w", err)
		}

		if !l.tomb.Alive() {
			return nil, ErrClosed
		}

		rsp := new(bytes.Buffer)
		tr := io.TeeReader(l.transport, rsp)

		// Wait for the response header
		var hdr tpm2.ResponseHeader
		if _, err := mu.UnmarshalFromReader(tr, &hdr); err != nil {
			return nil, fmt.Errorf("cannot unmarshal response header: %w", err)
		}

		// Read the rest of the response
		if _, err := io.CopyN(io.Discard, tr, int64(hdr.ResponseSize)-int64(binary.Size(hdr))); err != nil {
			return nil, err
		}

		err := tpm2.DecodeResponseCode(commandCode, hdr.ResponseCode)
		if retries > 0 && (tpm2.IsTPMWarning(err, tpm2.WarningYielded, commandCode) ||
			tpm2.IsTPMWarning(err, tpm2.WarningTesting, commandCode) ||
			tpm2.IsTPMWarning(err, tpm2.WarningRetry, commandCode)) {
			time.Sleep(retryDelay)
			retryDelay *= time.Duration(l.params.BackoffRate)
			continue
		}

		return rsp.Bytes(), nil
	}
}

func (l *retrierTransportLoop) run() (err error) {
	for {
		cmd := new(bytes.Buffer)
		tr := io.TeeReader(l.r, cmd)

		// Wait for the next command header
		var hdr tpm2.CommandHeader
		_, err := mu.UnmarshalFromReader(tr, &hdr)
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF):
			// We were closed
			return nil
		case err != nil:
			// Unexpected error
			return err
		}

		// Read the rest of the command
		_, err = io.CopyN(io.Discard, tr, int64(hdr.CommandSize)-int64(binary.Size(hdr)))
		switch {
		case err == io.EOF:
			// We were closed
			return nil
		case err != nil:
			// Unexpected error
			return err
		}

		rsp, err := l.runCommand(hdr.CommandCode, cmd.Bytes())
		switch {
		case err != nil:
			// Command dispatch failed, send an error to the reader
			l.wErr <- err
		default:
			// Command was executed, send the response to the reader
			l.wLen <- int64(len(rsp))
			_, err := io.Copy(l.w, bytes.NewReader(rsp))
			switch {
			case errors.Is(err, io.ErrClosedPipe):
				return nil
			case err != nil:
				// Unexpected error
				return err
			}
		}
	}
}

func (t *retrierTransport) Read(data []byte) (int, error) {
	for {
		if t.lr == nil {
			// Wait for the next response, or an error.
			select {
			case n, ok := <-t.rLen:
				if !ok {
					return 0, ErrClosed
				}
				t.lr = io.LimitReader(t.r, n)
			case err, ok := <-t.rErr:
				if !ok {
					return 0, ErrClosed
				}
				return 0, err
			}
		}

		n, err := t.lr.Read(data)
		if err == io.EOF {
			// This response is finished.
			t.lr = nil
			err = nil
			if n == 0 {
				continue
			}
		}
		return n, err
	}
}

func (t *retrierTransport) Write(data []byte) (n int, err error) {
	n, err = t.w.Write(data)
	if errors.Is(err, io.ErrClosedPipe) {
		err = ErrClosed
	}
	return n, err
}

func (t *retrierTransport) Close() error {
	// Close pipes to unblock I/O on the transport side.
	t.w.Close() // Unblocks transport routine waits on reads
	t.r.Close() // Unblocks transport routine waits on writes

	// Mark dying so the retry loop exits.
	t.tomb.Kill(nil)

	var closeErr error
	var wasOpen bool

	// Wait for everything on the transport routine to die
Loop:
	for {
		select {
		case <-t.rErr:
			// Response error channel is closed
		case <-t.rLen:
			// Response length channel is closed
		case closeErr, wasOpen = <-t.closeErr:
			// Close channel receives a close response from the underlying
			// transport routine if it wasn't already closed
			if !wasOpen {
				// It was already closed
				closeErr = ErrClosed
			}
			// This is the last thing we were waiting for.
			break Loop
		}
	}

	// Wait for all goroutines to terminate
	if err := t.tomb.Wait(); err != nil {
		return err
	}

	// We're done!
	return closeErr
}
