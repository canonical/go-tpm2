package transportutil

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/canonical/go-tpm2"
	"gopkg.in/tomb.v2"
)

// ErrNotLocked is returned from methods of LockableTransport if the transport
// instance doesn't hold the lock on the underlying downstream transport.
var ErrNotLocked = errors.New("cannot use transport without it being locked")

// LockableTransport extends the [tpm2.Transport] interface with the [sync.Locker]
// interface, and permits multiple transports operating in multiple goroutines
// to interact with a single underlying downstream transport, which is only ever
// accessed from a single, dedicated goroutine, and which can only be accessed by
// the instance of LockableTransport which holds an exclusive lock.
//
// The [Close] method of this has the same effect as calling
// [MultiplexedTransportManager.Close] and can be accessed on any goroutine and
// on any instance of LockableTransport associated with the same [MultiplexedTransportManager].
//
// LockableTransport is agnostic to the bytes that are transeferred trrough it -
// they could be valid TPM commands / responses or something else such as TPM
// commands / responses encapsulated in some other protocol.
type LockableTransport interface {
	tpm2.Transport
	sync.Locker
}

type lockableTransportImpl struct {
	manager *multiplexedTransportManagerImpl // the manager of the downstream transport that this transport fowards requests to.
}

func (t *lockableTransportImpl) Read(data []byte) (int, error) {
	if !t.beginOp() {
		return 0, ErrNotLocked
	}
	defer t.endOp()

	// Send the size of the supplied buffer. We don't want to read any
	// more bytes than this.
	select {
	case t.manager.expectedBytes <- len(data):
	case <-t.manager.tmb.Dying():
		return 0, io.EOF
	}

	// Wait for the result from the transport
	var n int
	var err error
	select {
	case rspResult := <-t.manager.rspResult:
		n = rspResult.n
		err = rspResult.err
	case <-t.manager.tmb.Dying():
		// A close has been requested, so unblock and return straight away
		return 0, io.EOF
	}

	if n > len(data) {
		// n should be equal to or less than the length of the supplied buffer
		return 0, errors.New("internal error: unexpected number of bytes returned from transport routine")
	}

	// Read the response from the main transport routine
	tmpData := make([]byte, n)                  // Make a temporary buffer to hold the bytes we're about to read from the transport routine
	nPipe, errPipe := t.manager.r.Read(tmpData) // Read from the transport routine
	n = copy(data, tmpData[:nPipe])             // Copy the read number of bytes from the temporary buffer into the supplied buffer
	switch {
	case err != nil: // This is an error from the underlying transport.
		return n, err
	case errPipe == io.EOF:
		// This is an error from the pipe between us and the transport routine,
		// because it has been closed.
		return n, io.EOF
	case errPipe != nil:
		// This is an unexpected error from the pipe between us and the transport routine.
		// If the transport routine returned an unexpected error, it will likely appear
		// here because the pipe gets closed with the error.
		return n, fmt.Errorf("cannot read response bytes from transport routine: %w", errPipe)
	}

	return n, nil
}

func (t *lockableTransportImpl) Write(data []byte) (int, error) {
	if !t.beginOp() {
		return 0, ErrNotLocked
	}
	defer t.endOp()

	// Send the length of data we've got to the transport routine
	select {
	case t.manager.readyBytes <- len(data):
	case <-t.manager.tmb.Dying():
		// A close has been requested, so unblock and return straight away
		return 0, ErrClosed
	}

	// Write the command to the main transport routine
	_, err := t.manager.w.Write(data)
	switch {
	case errors.Is(err, io.ErrClosedPipe):
		// This is an error from the pipe between us and the transport routine,
		// because it has been closed.
		return 0, ErrClosed
	case err != nil:
		// This is an unexpected error from the pipe between us and the transport routine.
		// If the transport routine returned an unexpected error, it will likely appear
		// here because the pipe gets closed with the error.
		return 0, fmt.Errorf("cannot write command bytes to transport routine: %w", err)
	}

	// Wait for the result from the transport
	select {
	case cmdResult := <-t.manager.cmdResult:
		return cmdResult.n, cmdResult.err
	case <-t.manager.tmb.Dying():
	}

	return 0, ErrClosed
}

func (t *lockableTransportImpl) Close() error {
	// Close can be called on any routine, so it's proxied straight through.
	return t.manager.Close()
}

func (t *lockableTransportImpl) beginOp() bool {
	locking := &t.manager.locking

	locking.cond.L.Lock()
	defer locking.cond.L.Unlock()

	if locking.holder != t {
		// We aren't the lock holder
		return false
	}

	// There shouldn't already be an op in progress
	if locking.holderOpInProgress {
		panic("internal error: operation already in progress")
	}

	// Set the flag indicating that an operation is in progress. This
	// prevents Unlock working without a panic.
	locking.holderOpInProgress = true
	return true
}

func (t *lockableTransportImpl) endOp() {
	locking := &t.manager.locking

	locking.cond.L.Lock()
	defer locking.cond.L.Unlock()

	if locking.holder != t {
		panic("internal error: cannot end operation: we aren't the lock holder")
	}
	if !locking.holderOpInProgress {
		panic("internal error: cannot end operation: operation not in progress")
	}

	// Clear the flag indicating that an operation is in progress. This
	// permits Unlock to be called.
	locking.holderOpInProgress = false
}

// Lock implements [sync.Locker.Lock].
func (t *lockableTransportImpl) Lock() {
	locking := &t.manager.locking

	locking.cond.L.Lock()
	defer locking.cond.L.Unlock()

	// Wait until there is no holder.
	for locking.holder != nil {
		locking.cond.Wait()
	}

	// There is no lock holder and we have the mutex.

	// Make sure the last holder didn't release the lock without clearing the
	// flag that indicates an operation is in progress.
	if locking.holderOpInProgress {
		panic("internal error: previous lock released whilst operation in progress")
	}

	// We are the new lock holder on the downstream transport.
	locking.holder = t
}

// Unlock implements [sync.Locker.Unlock].
func (t *lockableTransportImpl) Unlock() {
	locking := &t.manager.locking

	locking.cond.L.Lock()
	defer locking.cond.L.Unlock()

	// Make sure we're the current lock holder
	if locking.holder != t {
		panic("cannot release the lock - it isn't held by this transport")
	}
	// Make sure there isn't an operation in progress (there shouldn't really be,
	// as the methods of this instance should generally be called from the same
	// goroutine, perhaps with the exception of Close).
	if locking.holderOpInProgress {
		panic("cannot release the lock whilst an operation is in progress")
	}

	// Clear the current lock holder and signal any waiters.
	locking.holder = nil
	locking.cond.Signal()
}

// transportLoop handles communication directly with the io.Reader and io.Writer
// parts of the supplied downstream transport.
type transportLoop struct {
	transport io.ReadWriter // The Read/Write part of the underlying transport
	tmb       *tomb.Tomb    // For managing all goroutines created by this API

	readyBytes <-chan int              // To receive the amount of bytes written to the public io.Writer
	r          *io.PipeReader          // To receive command bytes written to the public io.Writer
	cmdResult  transportResultSendChan // To return the result of the Write to the underlying transport to the public io.Writer

	expectedBytes <-chan int              // To receieve the amount of bytes the public io.Reader is called with
	w             *io.PipeWriter          // To send response bytes which will be read by the public io.Reader
	rspResult     transportResultSendChan // To return the result of the Read from the underlying transport to the public io.Reader
}

func newTransportLoop(transport io.ReadWriter, tmb *tomb.Tomb, readyBytes <-chan int, r *io.PipeReader, cmdResult transportResultSendChan, expectedBytes <-chan int, w *io.PipeWriter, rspResult transportResultSendChan) *transportLoop {
	return &transportLoop{
		transport:     transport,
		tmb:           tmb,
		readyBytes:    readyBytes,
		r:             r,
		cmdResult:     cmdResult,
		expectedBytes: expectedBytes,
		w:             w,
		rspResult:     rspResult,
	}
}

func (l *transportLoop) run() (err error) {
	defer func() {
		// If the transport loop returned a tomb.ErrDying error, then it is
		// likely because of a call to the public io.Closer interface which
		// put the tomb into a dying state. If it's not already dying, we'll
		// generate a panic by returning this error from this function.
		// Test for that now. Also make sure that nil errors are only returned
		// when the tomb is already in a dying state. We want to make sure that
		// when this function returns, the tomb is always put into a dying state
		// if it wasn't previously.
		if l.tmb.Alive() && (err == nil || err == tomb.ErrDying) {
			// This will put the tomb into a dying state.
			err = errors.New("internal error: transport loop terminated with unexpected error")
		}

		// We might exit for reasons other than a call via the public io.Closer
		// interface, so try to handle that by unblocking any calls into a public
		// interface by closing the pipes that connects the public API to this
		// routine. We close them with the error returned from the transport loop,
		// unless that error is tomb.ErrDying, and then we close them with nil
		// instead.
		closeErr := err
		if closeErr == tomb.ErrDying {
			closeErr = nil
		}

		// Unblock public io.Writer
		l.r.CloseWithError(closeErr)
		if closeErr != nil {
			// Only send a transportResult if we have a non-nil error.
			// We're going to close the channel anyway.
			select {
			case l.cmdResult <- transportResult{err: closeErr}:
			default:
			}
		}
		close(l.cmdResult)

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

	for l.tmb.Alive() {
		select {
		case ready := <-l.readyBytes:
			// Someone has called Write via a public io.Writer with ready number of bytes.
			// Copy these bytes into a local buffer.
			buf := new(bytes.Buffer)
			_, err := io.CopyN(buf, l.r, int64(ready))
			switch {
			case err == io.EOF:
				// The write end was closed by a public io.Closer, so treat this
				// as a normal termination. We expect the tomb to be in a dying
				// state at this point.
				return tomb.ErrDying
			case err != nil:
				// Unexpected error.
				return fmt.Errorf("cannot read command bytes from public io.Writer: %w", err)
			}

			// Write the received bytes to the underlying transport. This can be
			// interrupted by any public io.Closer.
			n, err := l.transport.Write(buf.Bytes())
			switch {
			case !l.tmb.Alive():
				err = ErrClosed
			case err != nil:
				err = fmt.Errorf("cannot write command bytes to transport: %w", err)
			default:
			}

			// Send the Write result to the public io.Writer
			select {
			case l.cmdResult <- transportResult{n: n, err: err}:
			case <-l.tmb.Dying():
				return tomb.ErrDying
			}
		case expected := <-l.expectedBytes:
			// Someone has called Read via a public io.Reader with a buffer that
			// as the expected number of bytes.
			data := make([]byte, expected)

			// Read the expected number of bytes from the underlying transport. This
			// can be interrupted by any public io.Closer.
			n, err := l.transport.Read(data)
			switch {
			case !l.tmb.Alive():
				err = io.EOF
			case err != nil:
				err = fmt.Errorf("cannot read response bytes from transport: %w", err)
			}

			// Send the Read result to the public io.Reader.
			select {
			case l.rspResult <- transportResult{n: n, err: err}: // This is a blocking write
			case <-l.tmb.Dying():
				return tomb.ErrDying
			}

			// Copy the read bytes to the public io.Reader.
			_, err = io.CopyN(l.w, bytes.NewReader(data), int64(n))
			switch {
			case errors.Is(err, io.ErrClosedPipe):
				// The read end was closed by the public io.Closer, so treat this
				// as a normal termination. We expect the tomb to be in a dying
				// state at this point.
				return tomb.ErrDying
			case err != nil:
				// Unexpected error.
				return fmt.Errorf("cannot copy response bytes to public io.Reader: %w", err)
			}
		case <-l.tmb.Dying():
		}
	}
	return tomb.ErrDying
}

// MultiplexedTransportManager permits multiple [LockableTransport] implementations
// to interact with a single underlying downstream transport, which runs in its own
// dedicated goroutine. Each [LockableTransport] can operate from an arbitrary
// goroutine (noting the restrictions for Read and Write in the documentation for
// [tpm2.Transport], and access to the main downstream transport is serialized via
// an exclusive locking mechanism.
//
// This is useful in scenarios where some access to a transport has to happen on a
// goroutine seaprate from the public API (ie, NewRetrierTransport, which communicates
// with the transport from within a retry loop that runs on its own goroutine), but
// where you still want the public API to be able to communicate directly with the
// underlying transport. In this case, there are 2 [LockableTransport] implementations
// - one accessed directly from the public API, and one accessed from the retry loop,
// with accesses to both being proxied to the same transport in the same goroutine, and
// with access being serialized using a lock.
type MultiplexedTransportManager interface {
	// NewTransport creates a new transport that proxies communications to the
	// main downstream transport inside a lock. This can be called on any
	// goroutine, although note that the returned transport should only be
	// used from the calling goroutine (note the restrictions in the documentation
	// for tpm2.Transport.
	NewTransport() LockableTransport

	// Close closes the main downstream transport and ends its goroutines. Calling
	// Close on any LockableTransport created by the implementation of this should
	// have the same effect.
	Close() error
}

type multiplexedTransportManagerLockData struct {
	// The fields in this struct are protected by the lock associated with the condition variable.
	cond               *sync.Cond
	holder             *lockableTransportImpl // The public transport currently permitted to access the underlying transport (the lock holder)
	holderOpInProgress bool                   // Whether the lock holder is in a read or write operation
}

type multiplexedTransportManagerImpl struct {
	tmb *tomb.Tomb // To manager goroutines created by this API

	// Locking data. Only one public transport can hold the lock at a time.
	locking multiplexedTransportManagerLockData

	// Communications used by the public transport with hold of the lock to
	// communicate with the main downstream transport on its own routine.
	readyBytes chan<- int              // Tell the transport routine how many bytes are in the command Write
	w          *io.PipeWriter          // Command channnel
	cmdResult  transportResultRecvChan // Receive the result of the Write to the main underlying transport

	expectedBytes chan<- int              // Tell the transport routine how many bytes were passed to the response Read
	r             *io.PipeReader          // Response channel
	rspResult     transportResultRecvChan // Receive the result of the Read from the main underlying transport

	// io.Closer helpers.
	transportCloserOnce sync.Once // ensures we only close the underlying transport once.
	transportCloser     io.Closer // the closer implementation for the underlying transport.
}

// NewMultiplexedTransportManager returns a new MultiplexedTransportManager to permit the supplied
// transport to be accessed from multiple goroutines, with an exclusive locking mechanism to
// serialize access to the suplied transport. The supplied transport is only ever accessed directly
// from its own dedicate goroutine, and is accessed indirectly via [LockableTransport] instances
// that can be accessed from arbitrary goroutines, with the requests being forwarded to the supplied
// transport using a mix of go channels and in-process pipes.
//
// When done with the returned manager, one must call its Close method to shut down any created
// goroutines. This can either be done directly, or indirectly via one of its associated
// [LockableTransport] instances.
func NewMultiplexedTransportManager(transport tpm2.Transport) MultiplexedTransportManager {
	// Construct the command channel
	readyBytes := make(chan int)
	wr, ww := io.Pipe()
	// wr is read by the transport routine
	// ww is written to from the public io.Writer.
	cmdResult := make(transportResultChan)

	// Construct the response channel
	expectedBytes := make(chan int)
	rr, rw := io.Pipe()
	// rr is read by the public io.Reader
	// rw is written to from the transport routine
	rspResult := make(transportResultChan)

	tmb := new(tomb.Tomb)

	// Spin up the transport routine
	tmb.Go(func() error {
		loop := newTransportLoop(transport, tmb, readyBytes, wr, cmdResult, expectedBytes, rw, rspResult)
		return loop.run()
	})

	var mu sync.Mutex

	return &multiplexedTransportManagerImpl{
		tmb: tmb,
		locking: multiplexedTransportManagerLockData{
			cond: sync.NewCond(&mu),
		},
		readyBytes:      readyBytes,
		w:               ww,
		cmdResult:       cmdResult,
		expectedBytes:   expectedBytes,
		r:               rr,
		rspResult:       rspResult,
		transportCloser: transport,
	}
}

func (t *multiplexedTransportManagerImpl) NewTransport() LockableTransport {
	return &lockableTransportImpl{manager: t}
}

func (t *multiplexedTransportManagerImpl) Close() error {
	// Make all routines die when they reach an appropriate point
	t.tmb.Kill(nil)

	// Close pipes to unblock the transport routine
	t.w.Close()
	t.r.Close()

	// Close the underlying transport
	var closeErr error = ErrClosed
	t.transportCloserOnce.Do(func() {
		closeErr = t.transportCloser.Close()
	})

	// Wait for all goroutines to terminate
	if err := t.tmb.Wait(); err != nil {
		return err
	}

	// We're done!
	return closeErr
}
