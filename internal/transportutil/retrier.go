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
	transport tpm2.Transport
	params    RetryParams

	tomb tomb.Tomb

	w io.WriteCloser // write channel

	r    io.ReadCloser // read channel
	rLen <-chan int64  // next response length, used to demarcate responses.
	rErr <-chan error  // read errors.
	lr   io.Reader     // current response reader, limited by the last value read from rLen.

	closeErr <-chan error
}

// NewRetrierTransport returns a new transport that resubmits commands on certain
// errors, which is necessary for transports that don't already do this.
func NewRetrierTransport(transport tpm2.Transport, params RetryParams) tpm2.Transport {
	t := &retrierTransport{
		transport: transport,
		params:    params,
	}

	// Construct the write channel
	wr, ww := io.Pipe()
	t.w = ww

	// Construct the read channel
	rr, rw := io.Pipe()
	t.r = rr
	rLen := make(chan int64)
	t.rLen = rLen
	rErr := make(chan error)
	t.rErr = rErr

	// Construct the close channel
	closeErr := make(chan error)
	t.closeErr = closeErr

	// Run the transport routine
	t.tomb.Go(func() error {
		err := t.run(wr, rw, rLen, rErr)
		// Ensure the calling routine gets unblocked.
		wr.Close()
		rw.Close()
		close(rLen)
		close(rErr)
		closeErr <- transport.Close()
		close(closeErr)
		return err
	})
	return t
}

func (t *retrierTransport) runCommand(commandCode tpm2.CommandCode, data []byte) ([]byte, error) {
	retryDelay := t.params.InitialBackoff

	for retries := t.params.MaxRetries; ; retries-- {
		if !t.tomb.Alive() {
			return nil, errors.New("transport is closing")
		}

		// Send the command.
		if _, err := t.transport.Write(data); err != nil {
			return nil, fmt.Errorf("cannot send command: %w", err)
		}

		if !t.tomb.Alive() {
			return nil, errors.New("transport is closing")
		}

		rsp := new(bytes.Buffer)
		tr := io.TeeReader(t.transport, rsp)

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
		if retries > 0 && (tpm2.IsTPMWarning(err, tpm2.WarningYielded, commandCode) || tpm2.IsTPMWarning(err, tpm2.WarningTesting, commandCode) || tpm2.IsTPMWarning(err, tpm2.WarningRetry, commandCode)) {
			time.Sleep(retryDelay)
			retryDelay *= time.Duration(t.params.BackoffRate)
			continue
		}

		return rsp.Bytes(), nil
	}
}

func (t *retrierTransport) run(r io.Reader, w io.Writer, wLen chan<- int64, wErr chan<- error) (err error) {
	for {
		cmd := new(bytes.Buffer)
		tr := io.TeeReader(r, cmd)

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

		rsp, err := t.runCommand(hdr.CommandCode, cmd.Bytes())
		switch {
		case err != nil:
			// Command dispatch failed, send an error to the reader
			wErr <- err
		default:
			// Command was executed, send the response to the reader
			wLen <- int64(len(rsp))
			_, err := io.Copy(w, bytes.NewReader(rsp))
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
			case n := <-t.rLen:
				t.lr = io.LimitReader(t.r, n)
			case err := <-t.rErr:
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
	return t.w.Write(data)
}

func (t *retrierTransport) Close() error {
	// Close the pipes and transport to unblock the transport routine.
	t.w.Close()
	t.r.Close()

	t.tomb.Kill(nil)

	var closeErr error
	var wasOpen bool

	// Wait for everything to die.
Loop:
	for {
		select {
		case <-t.rErr:
		case <-t.rLen:
		case closeErr, wasOpen = <-t.closeErr:
			if !wasOpen {
				closeErr = errors.New("transport already closed")
			}
			break Loop
		}
	}
	if err := t.tomb.Wait(); err != nil {
		return err
	}

	return closeErr
}
