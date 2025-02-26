package transportutil

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"gopkg.in/tomb.v2"
)

// RetryParams contains parameters for [NewRetrierTransport].
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

// retrierLoop handles re-dispatching of commands that should be retried. It
// is accessed from a dedicated retry goroutine.
type retrierLoop struct {
	params    RetryParams    // supplied retrier parameters
	transport tpm2.Transport // supplied underlying transport, accessed only from retrier routine

	tomb *tomb.Tomb // tracker for goroutines (shared with retrierTransport)

	r *io.PipeReader // command channel from public io.Writer

	w         *io.PipeWriter          // response channel to public io.Reader
	rspResult transportResultSendChan // response channel results to public io.Reader
}

func newRetrierLoop(params *RetryParams, transport tpm2.Transport, tomb *tomb.Tomb, r *io.PipeReader, w *io.PipeWriter, rspResult transportResultSendChan) *retrierLoop {
	return &retrierLoop{
		params:    *params,
		transport: transport,
		tomb:      tomb,
		r:         r,
		w:         w,
		rspResult: rspResult,
	}
}

func (l *retrierLoop) runCommand(commandCode tpm2.CommandCode, cmd []byte) ([]byte, error) {
	retryDelay := l.params.InitialBackoff // set the retry delay to the initial backoff time.

	for tries := l.params.MaxRetries + 1; l.tomb.Alive() && tries > 0; tries-- {
		// Loop for the maximum specified number of tries or until
		// the tomb enters a dying state.

		// Send the full command to the underlying transport. This can be unblocked by
		// closing the transport from the public io.Closer, in which case the tomb will
		// be in a dying state and we want to terminate cleanly. If this fails, we'll not
		// try again.
		if _, err := l.transport.Write(cmd); err != nil {
			if !l.tomb.Alive() {
				return nil, tomb.ErrDying
			}
			return nil, fmt.Errorf("cannot send command to transport: %w", err)
		}

		// Create a buffer to hold the entire response packet.
		rsp := new(bytes.Buffer)
		tr := io.TeeReader(l.transport, rsp)

		// Wait for the response header from the underlying transport. This can be
		// unblocked by closing the transport from the public io.Closer, in which
		// case the tomb will be in a dying state and we want to terminate cleanly.
		// If this fails, we'll not try again because without a decoded header, we
		// don't know how many more bytes are remaining and we need the response buffer
		// to be empty before we can send a new command.
		var hdr tpm2.ResponseHeader
		if _, err := mu.UnmarshalFromReader(tr, &hdr); err != nil {
			if !l.tomb.Alive() {
				return nil, tomb.ErrDying
			}
			return nil, fmt.Errorf("cannot unmarshal response header from transport: %w", err)
		}
		if int64(hdr.ResponseSize) < int64(binary.Size(hdr)) {
			return nil, errors.New("response header received from transport has invalid commandSize: size smaller than header")
		}

		// Does the response indicate that the command should be retried? Note that
		// in any case where the response code is not 0, the TPM response is just the
		// response header, so there are no more bytes for us to read.
		err := tpm2.DecodeResponseCode(commandCode, hdr.ResponseCode)
		if tries > 1 && (tpm2.IsTPMWarning(err, tpm2.WarningYielded, commandCode) ||
			(tpm2.IsTPMWarning(err, tpm2.WarningTesting, commandCode) && commandCode != tpm2.CommandSelfTest) ||
			tpm2.IsTPMWarning(err, tpm2.WarningRetry, commandCode)) {

			// Yes, we have retries left and should retry. Sleep for the current retry delay
			select {
			case <-time.NewTimer(retryDelay).C:
				// Scale the next retry delay by the specified backoff rate.
				retryDelay *= time.Duration(l.params.BackoffRate)
			case <-l.tomb.Dying():
			}

			// Retry!
			continue
		}

		// There's no need to retry the command, or we have no more retry attempts left. Wait
		// for and read the rest of the response from the underlying transport. This can be
		// unblocked by closing the transport from the public io.Closer, in which case the tomb
		// will be in a dying state and we want to terminate cleanly.
		if _, err := io.CopyN(io.Discard, tr, int64(hdr.ResponseSize)-int64(binary.Size(hdr))); err != nil {
			if !l.tomb.Alive() {
				return nil, tomb.ErrDying
			}
			return nil, fmt.Errorf("cannot receive remainder of response from transport: %w", err)
		}

		// Return the whole response.
		return rsp.Bytes(), nil
	}

	return nil, tomb.ErrDying
}

func (l *retrierLoop) run() (err error) {
	defer func() {
		// If the retry loop returned a tomb.ErrDying error, then it is
		// likely because of a call to the public io.Closer interface which
		// put the tomb into a dying state. If it's not already dying, we'll
		// generate a panic by returning this error from this function.
		// Test for that now. Also make sure that nil errors are only returned
		// when the tomb is already in a dying state. We want to make sure that
		// when this function returns, the tomb is always put into a dying state
		// if it wasn't previously.
		if l.tomb.Alive() && (err == nil || err == tomb.ErrDying) {
			// This will put the tomb into a dying state.
			err = errors.New("internal error: retry loop terminated with unexpected error")
		}

		// We might exit for reasons other than a call via the public io.Closer
		// interface, so try to handle this case by unblocking any current calls
		// into the public io.Reader or io.Writer interface by closing the pipes
		// that connects the public API to this routine. We close them with the
		// error returned from the retry loop, unless that error is tomb.ErrDying,
		// and then we close them with nil instead.
		closeErr := err
		if err == tomb.ErrDying {
			closeErr = nil
		}

		// Unblock public io.Writer
		l.r.CloseWithError(closeErr)

		// Unblock public io.Reader
		if closeErr != nil {
			// Only send a transportResult if we have a non-nil error.
			// We're going to close the channel anyway.
			select {
			case l.rspResult <- transportResult{err: closeErr}:
			default:
			}
		}
		close(l.rspResult)
		l.w.CloseWithError(closeErr)
	}()

	for l.tomb.Alive() {
		cmd := new(bytes.Buffer)
		tr := io.TeeReader(l.r, cmd)

		// Wait for the next command header from the public io.Writer
		var hdr tpm2.CommandHeader
		_, err := mu.UnmarshalFromReader(tr, &hdr)
		switch {
		case errors.Is(err, io.ErrUnexpectedEOF) || err == io.EOF:
			// The write end was closed, most likely via a call into the public io.Closer,
			// in which case the tomb will be in a dying state. Treat this as a normal
			// termination, returning an appropriate error. We expect the public io.Writer
			// side to handle returning an appropriate error (ErrClosed) - we don't do that
			// here because we want the tomb to die with success. Note that mu.UnmarshalFrom*
			// functions never return io.EOF yet, but may do in the future.
			return tomb.ErrDying
		case err != nil:
			// Unexpected error
			return fmt.Errorf("cannot decode command header provided to public io.Writer interface: %w", err)
		}
		if int64(hdr.CommandSize) < int64(binary.Size(hdr)) {
			return errors.New("command header provided to public io.Writer has invalid commandSize: size smaller than header")
		}

		// Wait for and read the rest of the command supplied to the public io.Writer
		_, err = io.CopyN(io.Discard, tr, int64(hdr.CommandSize)-int64(binary.Size(hdr)))
		switch {
		case err == io.EOF:
			// The write end was closed, most likely via a call into the public io.Closer,
			// in which case the tomb will be in a dying state. Treat this as a normal
			// termination, returning an appropriate error. We expect the public io.Writer
			// side to handle returning an appropriate error (ErrClosed) - we don't do that
			// here because we want the tomb to die with success.
			return tomb.ErrDying
		case err != nil:
			// Unexpected error
			return fmt.Errorf("cannot obtain remainder of command packet provided to public io.Writer interface: %w", err)
		}

		// We have a full command packet - run it!
		rsp, err := l.runCommand(hdr.CommandCode, cmd.Bytes())
		if err != nil {
			// Command dispatch failed in some way. We don't distinguish between send (from io.Writer)
			// and receive (to io.Reader) errors because writing to the underlying transport to send
			// a command packet happens inside of the retry loop and might happen several times. The
			// public io.Writer interface doesn't block on this, so errors as a result of this are
			// picked up by the public io.Reader interface when waiting for a response.
			return err
		}
		// Command was dispatched to the underlying transport successfully and we already have a full
		// response. Send information about the results of the read from the transport to the public
		// io.Reader to unblock it. Note that this will block until the next call into the public
		// io.Reader, or a call into the public io.Closer.
		select {
		case l.rspResult <- transportResult{n: len(rsp)}:
		case <-l.tomb.Dying():
			// A close has been requested, so unblock and return straight away
			return tomb.ErrDying
		}

		// Copy the whole resonse to the public io.Reader, which uses the received transportResult
		// to create a temporary io.LimitedReader. This will block until there is a caller into the
		// public io.Reader to consume the bytes, or a call into the public io.Closer.
		_, err = io.Copy(l.w, bytes.NewReader(rsp))
		switch {
		case err == io.ErrClosedPipe:
			// The read end was closed, most likely via a call into the public io.Closer, in which
			// case the tomb will be in a dying state. Treat this as a normal termination, returning
			// an approproate error. We expect the public io.Reader size to handle returning an
			// appropriate error (io.EOF) - we don't do that here because we want the tomb to die
			// with success.
			return tomb.ErrDying
		case err != nil:
			// Unexpected error
			return fmt.Errorf("cannot send response bytes to public io.Reader: %w", err)
		}
	}
	return tomb.ErrDying
}

// retrierTransport is an implementation to tpm2.Transport and is the public
// facing part of this interface.
type retrierTransport struct {
	tomb *tomb.Tomb // tracker for goroutines

	w *io.PipeWriter // command channel to retry routine.

	r         *io.PipeReader          // response channel from retry routine.
	rspResult transportResultRecvChan // response channel results received from retry routine.

	transportCloserOnce sync.Once // ensures we only close the underlying transport once.
	transportCloser     io.Closer // the closer implementation for the underlying transport.

	current *io.LimitedReader // current response packet
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
// only ever receive commands in a single write call due to the nature in which the
// retry loop works.
//
// The [io.Reader] part of the returned transport supports partial reads. The [io.Writer]
// part of the returned transport supports a command being split across multiple writes,
// as described in the documentation for [tpm2.Transport].
//
// The supplied params is used to customize the transport (see documentation for [RetryParams].
//
// Note that the return values of the [io.Writer] implementation of the returned transport
// don't reflect what was written to the supplied transport. The returned number of bytes
// are those written to a pipe that connects the public API to the retry routine. The returned
// error may reflect errors that occur as a result of processing the supplied bytes on the
// retry routine. As commands are written to the supplied transport in a loop in the case
// where a command has to be retried, any errors that occur when writing to the supplied
// transport may be returned to the [io.Reader] implementation of the returned transport
// instead.
//
// The returned transport should be closed eventually with its [Close] method. This not
// only closes the supplied transport, but also shuts down the retry loop routine that
// was communicating with it.
func NewRetrierTransport(transport tpm2.Transport, params RetryParams) tpm2.Transport {
	if params.MaxRetries == math.MaxUint {
		params.MaxRetries -= 1 // Avoid an overflow in retrierLoop.runCommand/
	}

	// Construct the command channel
	wr, ww := io.Pipe()
	// wr is read by the retry routine
	// ww is written to from the public io.Writer.

	// Construct the response channel
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
		return loop.run()
	})

	return &retrierTransport{
		tomb:            tmb,
		w:               ww,
		r:               rr,
		rspResult:       rspResult,
		transportCloser: transport,
	}
}

func (t *retrierTransport) Read(data []byte) (int, error) {
	if t.current == nil {
		// We have no more data to return. Wait for the next response packet, or an error.
		select {
		case rsp, ok := <-t.rspResult:
			// We have some sort of response
			switch {
			case !ok:
				// The channel is closed.
				return 0, io.EOF
			case rsp.err != nil:
				// We'll get an error if the retry loop exits with an error - just return
				// it unmodified.
				return 0, rsp.err
			default:
				// We have a response, so create a limited reader for it.
				t.current = &io.LimitedReader{R: t.r, N: int64(rsp.n)}
			}
		case <-t.tomb.Dying():
			// A close has been requested, so just return io.EOF.
			return 0, io.EOF
		}
	}

	// We have a response to read.

	n, err := t.current.Read(data)
	if t.current.N == 0 {
		// We've read all of the bytes from this response.
		t.current = nil // Make the next call wait for another response.

		// It's possible that io.LimitedReader could return io.EOF with the call that empties
		// it, but tpm2.Transport should never return io.EOF unless it will never return any
		// more bytes. Clear the error in this case.
		if err == io.EOF {
			err = nil
		}
	}

	// We still have more bytes in this response.

	switch {
	case err == io.EOF:
		// The pipe was closed either from the read side via the io.Closer interface or
		// because the retry loop terminated and closed the write side - we generally
		// shouldn't hit this case though because the retry loop will return an error,
		// which will be passed to io.PipeWriter.CloseWithError. We'll pick that error
		// up in the following branch, unless it is io.EOF.
		return n, io.EOF
	case err != nil:
		// Unexpected error
		return n, fmt.Errorf("cannot obtain all requested response bytes from retry loop: %w", err)
	}

	return n, nil
}

func (t *retrierTransport) Write(data []byte) (int, error) {
	// n in this case isn't the number of bytes submitted to the underlying
	// transport - it's the number of bytes we've written into the pipe
	// that connects us to the retry loop. What is actually submitted to
	// the underlying transport isn't available to this function, and we
	// don't wait for it. In the case where a command is retried, the command
	// may be written to the underlying transport multiple times.
	n, err := t.w.Write(data)
	switch {
	case err == io.ErrClosedPipe:
		// Pipe closed via the public io.Closer interface. The retry loop side
		// will receive a io.EOF of io.ErrUnexpectedEOF and terminate cleanly.
		return n, ErrClosed
	case err != nil:
		// An error occurred on the retry loop side which caused it to terminate
		// and call io.PipeReader.CloseWithError on the command pipe.
		return n, fmt.Errorf("cannot send command data to retry loop: %w", err)
	}

	return n, nil
}

func (t *retrierTransport) Close() error {
	// Mark tomb as dying to unblock channel senders/receivers and so the
	// retry loop terminates.
	t.tomb.Kill(nil)

	// Close pipes to unblock I/O between us and the retry loop side.
	t.w.Close() // Unblocks reads in the retry loop.
	t.r.Close() // Unblocks writes in the retry loop.

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
