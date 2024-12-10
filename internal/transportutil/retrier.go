package transportutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"gopkg.in/tomb.v2"
)

var ErrClosed = errors.New("transport already closed")

type RetryParams struct {
	// MaxRetries is the maximum number of times a command is retried.
	// A command is always dispatched once. Setting this to zero disables
	// retries.
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

// retrierLoop handles re-dispatching of commands that should be retried.
type retrierLoop struct {
	params    RetryParams    // supplied retrier parameters
	transport tpm2.Transport // supplied underlying transport, accessed only from retrier routine

	tomb *tomb.Tomb // tracker for goroutines (shared with retrierTransport)

	r         io.Reader               // command channel from public io.Writer
	w         io.Writer               // response channel to io.Reader
	rspResult transportResultSendChan // response channel results to public io.Reader
}

func newRetrierLoop(params *RetryParams, transport tpm2.Transport, tomb *tomb.Tomb, r io.Reader, w io.Writer, rspResult transportResultSendChan) *retrierLoop {
	return &retrierLoop{
		params:    *params,
		transport: transport,
		tomb:      tomb,
		r:         r,
		w:         w,
		rspResult: rspResult,
	}
}

func (l *retrierLoop) runCommand(commandCode tpm2.CommandCode, data []byte) ([]byte, error) {
	retryDelay := l.params.InitialBackoff // set the retry delay to the initial backoff time.

	for retries := l.params.MaxRetries; ; retries-- {
		// Loop for the maximum specified number of retries
		if !l.tomb.Alive() {
			// A close has been requested, so exit early.
			return nil, tomb.ErrDying
		}

		// Send the full command to the underlying transport.
		if _, err := l.transport.Write(data); err != nil {
			return nil, fmt.Errorf("cannot send command: %w", err)
		}

		if !l.tomb.Alive() {
			// A close has been requested, so exit early rather than
			// waiting for a response.
			return nil, tomb.ErrDying
		}

		rsp := new(bytes.Buffer)
		tr := io.TeeReader(l.transport, rsp)

		// Wait for the response header from the underlying transport.
		var hdr tpm2.ResponseHeader
		if _, err := mu.UnmarshalFromReader(tr, &hdr); err != nil {
			return nil, fmt.Errorf("cannot unmarshal response header: %w", err)
		}

		if !l.tomb.Alive() {
			// A close has been requested, so exit early rather than
			// waiting for the rest of the response.
			return nil, tomb.ErrDying
		}

		// Does the response indicate that the command should be retried? Note that
		// in any case where the response code is 0, the TPM response is just the response
		// header, so there are no more bytes to read.
		err := tpm2.DecodeResponseCode(commandCode, hdr.ResponseCode)
		if retries > 0 && (tpm2.IsTPMWarning(err, tpm2.WarningYielded, commandCode) ||
			tpm2.IsTPMWarning(err, tpm2.WarningTesting, commandCode) ||
			tpm2.IsTPMWarning(err, tpm2.WarningRetry, commandCode)) {

			// Yes, we have retries left and should retry. Sleep for the current retry delay
			select {
			case <-time.After(retryDelay):
				// Scale the next retry delay by the specified backoff rate.
				retryDelay *= time.Duration(l.params.BackoffRate)
			case <-l.tomb.Dying():
				// A close has been requested, so abort the timeout and exit early.
				return nil, tomb.ErrDying
			}

			// Retry!
			continue
		}

		// No need to retry the command. Wait for and read the rest of the response from the
		// underlying transport.
		if _, err := io.CopyN(io.Discard, tr, int64(hdr.ResponseSize)-int64(binary.Size(hdr))); err != nil {
			return nil, err
		}

		// Return the whole response.
		return rsp.Bytes(), nil
	}
}

func (l *retrierLoop) run() (err error) {
	for {
		cmd := new(bytes.Buffer)
		tr := io.TeeReader(l.r, cmd)

		// Wait for the next command header from the public io.Writer
		var hdr tpm2.CommandHeader
		_, err := mu.UnmarshalFromReader(tr, &hdr)
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF:
			// The write end was closed from the public io.Closer, treat
			// this as a normal termination.
			return nil
		case err != nil:
			// Unexpected error
			return err
		}

		if !l.tomb.Alive() {
			// A close has been requested, so exit early rather than
			// waiting for the rest of the response.
			return tomb.ErrDying
		}

		// Wait for and read the rest of the command from the public io.Writer
		_, err = io.CopyN(io.Discard, tr, int64(hdr.CommandSize)-int64(binary.Size(hdr)))
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF:
			// this as a normal termination.
			return nil
		case err != nil:
			// Unexpected error
			return err
		}

		// Don't check tomb status here as it's checked at the start of each loop in runCommand.

		// Run this command
		rsp, err := l.runCommand(hdr.CommandCode, cmd.Bytes())
		switch {
		case err == tomb.ErrDying:
			// We're closing down, so just propagate this error.
			return err
		case err != nil:
			// Command dispatch failed in some way - we don't distinguish between transport errors related to
			// the command or the response due to the retry logic - we treat errors as being related to the
			// response, so send the error to the public io.Reader.
			select {
			case l.rspResult <- transportResult{n: 0, err: err}: // This is a blocking write.
			case <-l.tomb.Dying():
				// A close has been requested, so unblock and exit early with the command error.
				return err
			}
		default:
			// Command was dispatched to the underlying transport successfully and we already have a full
			// response. Send information about the results of the read from the transport to the public
			// io.Reader to unblock it.
			select {
			case l.rspResult <- transportResult{n: len(rsp), err: nil}: // This is a blocking write.
			case <-l.tomb.Dying():
				// A close has been requested, so unblock and exit early.
				return tomb.ErrDying
			}

			if !l.tomb.Alive() {
				// A close has been requested, so exit early rather than copying
				// the rest of the response back to the public io.Reader.
				return tomb.ErrDying
			}

			// Copy the whole resonse to the public io.Reader, which uses the received transportResult
			// to create a temporary io.LimitedReader.
			_, err = io.Copy(l.w, bytes.NewReader(rsp))
			switch {
			case errors.Is(err, io.ErrClosedPipe):
				// The read end was closed from the public io.Closer, treat
				// this as a normal termination.
				return nil
			case err != nil:
				// Unexpected error
				return err
			}
		}
	}
}

// retrierTransport is an implementation to tpm2.Transport and is the public
// facing part of this interface.
type retrierTransport struct {
	tomb *tomb.Tomb // tracker for goroutines

	wc        io.WriteCloser          // command channel to retry routine.
	rc        io.ReadCloser           // response channel from retry routine.
	rspResult transportResultRecvChan // response channel results

	transportCloserOnce sync.Once // ensures we only close the underlying transport once.
	transportCloser     io.Closer // the closer implementation for the underlying transport.

	current io.Reader // current response packet.
}

// NewRetrierTransport returns a new transport that resubmits commands on certain
// errors, which is necessary for transports that don't already do this. This
// functionality isn't implemented in the public [tpm2.TPMContext] API because some
// transports already support automatic command resubmission - the linux character
// device being one of them.
//
// The returned transport expects to only see TPM command and response packets. It will
// fail if any other type of packet is sent through it (eg, packets that have been
// encapsulated for a specific transport).
//
// The supplied transport must implement partial read support for the [io.Reader] side,
// as described in the documentation for [tpm2.Transport]. The [io.Writer] part will
// only ever receive commands in a single write call.
//
// The [io.Reader] part of the returned transport supports partial reads. The [io.Writer]
// part of the returned transport supports a command being split across multiple writes,
// as described in the documentation for [tpm2.Transport].
func NewRetrierTransport(transport tpm2.Transport, params RetryParams) tpm2.Transport {
	// Construct the write channel
	wr, ww := io.Pipe()
	// wr is read by the retry routine
	// ww is written to from the public io.Writer.

	// Construct the read channel
	rr, rw := io.Pipe()
	// rr is read by the public io.Reader
	// rw is written to from the retry routine

	// Construct a channel to send the result of the Read from the underlying
	// transport to the public io.Reader
	rspResult := make(transportResultChan)

	tmb := new(tomb.Tomb)

	// Run the retry routine
	tmb.Go(func() error {
		loop := newRetrierLoop(&params, transport, tmb, wr, rw, rspResult)
		err := loop.run()

		// We might exit for reasons other than a call via the public
		// io.Closer interface, so try to handle that by unblocking
		// any calls into the public interface.
		wr.Close() // Unblocks public io.Writer.
		rw.Close() // Unblocks public io.Reader.

		return err
	})

	return &retrierTransport{
		tomb:            tmb,
		wc:              ww,
		rc:              rr,
		rspResult:       rspResult,
		transportCloser: transport,
	}
}

func (t *retrierTransport) Read(data []byte) (int, error) {
	for {
		if t.current == nil {
			var rspLen int
			// Wait for the next response packet, or an error.
			select {
			case rspResult := <-t.rspResult:
				if rspResult.err != nil {
					// An error was received. The retry loop doesn't mix errors
					// with n > 0, so just return the error.
					return 0, rspResult.err
				}
				rspLen = rspResult.n
			case <-t.tomb.Dying():
				// A close has been requested, so just return io.EOF.
				return 0, io.EOF
			}

			// Create a limited reader for the response
			t.current = io.LimitReader(t.rc, int64(rspLen))
		}

		n, err := t.current.Read(data)
		if err == io.EOF {
			// This response is finished.
			t.current = nil
			err = nil
			if n == 0 {
				// If we read nothing, then the last read consumed
				// all of the bytes associated with the current response.
				// In this case, loop again and wait for the next response
				// from the retry loop.
				continue
			}
		}
		return n, err
	}
}

func (t *retrierTransport) Write(data []byte) (n int, err error) {
	n, err = t.wc.Write(data)
	if errors.Is(err, io.ErrClosedPipe) {
		// Closed either via the io.Closer interface or because the retry loop terminated.
		err = ErrClosed
	}
	return n, err
}

func (t *retrierTransport) Close() error {
	// Mark dying so the retry loop terminates when it reaches an
	// appropriate point
	t.tomb.Kill(nil)

	// Close pipes to unblock I/O between us and the retry loop side.
	t.wc.Close() // Unblocks reads in the retry loop.
	t.rc.Close() // Unblocks writes in the retry loop.

	// Close the underlying transport. This may unblock parts of the
	// retry loop that are blocked on interactions with it. We only
	// do this once. If it's already closed, we respond with ErrClosed.
	var closeErr error = ErrClosed
	t.transportCloserOnce.Do(func() {
		closeErr = t.transportCloser.Close()
	})

	// Wait for all goroutines to terminate
	if err := t.tomb.Wait(); err != nil {
		return err
	}

	// We're done!
	return closeErr
}
