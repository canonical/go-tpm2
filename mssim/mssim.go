// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package mssim provides an interface for communicating with a TPM simulator
*/
package mssim

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/mu"
	"github.com/canonical/go-tpm2/transportutil"
)

// SimulatorFlags provides information about TPM simulator features.
type SimulatorFlags uint32

const (
	// SimulatorFlagPlatformAvailable indicates that the platform hierarchy
	// is available, and hardware platform functionality (eg, _TPM_Hash_Start)
	// is also available.
	SimulatorFlagPlatformAvailable SimulatorFlags = 1 << iota

	// SimulatorFlagUsesTbs indicates that a resource manager is used. In
	// this case, handles for transient objects and sessions returned to the
	// caller are virtualized.
	SimulatorFlagUsesTbs

	// SimulatorFlagInRawMode indicates that no resource virtualization is
	// performed.
	SimulatorFlagInRawMode

	// SimulatorFlagSupportsPP indicates that the simulator supports asserting
	// physical presence.
	SimulatorFlagSupportsPP

	// SimulatorFlagsNoPowerCtl indicates that the simulator does not support
	// power control commands.
	SimulatorFlagsNoPowertCtl

	// SimulatorFlagsNoLocalityCtl indicates that the simulator does not support
	// controlling the command locality.
	SimulatorFlagsNoLocalityCtl

	// SimulatorFlagsNoNvCtl indicates that the simulator does not support any
	// NV control commands.
	SimulatorFlagsNoNvCtl
)

// PlatformCommandError corresponds to an error code in response to a platform command
// executed on a TPM simulator.
//
// Deprecated: This never returned.
type PlatformCommandError struct {
	commandCode uint32
	Code        uint32
}

func (e *PlatformCommandError) Error() string {
	return fmt.Sprintf("received error code %d in response to platform command %d", e.Code, e.commandCode)
}

// ErrUnsupportedOperation is returned from a method of Transport if the
// operation isn't supported by the attached simulator.
var ErrUnsupportedOperation = errors.New("the simulator does not support this operation")

// Tcti represents a connection to a TPM simulator that implements the Microsoft TPM2
// simulator interface.
//
// Deprecated: Use [Transport].
type Tcti = Transport

// Transport represents a connection to a TPM simulator that implements the Microsoft TPM2
// simulator interface. It should not be used from multiple goroutines simultaneously.
type Transport struct {
	flags      SimulatorFlags
	simVersion uint32

	retrier  tpm2.Transport     // For handling TPM commands on the TPM channel
	tpm      *tpmTransport      // For handling control commands on the TPM channel
	platform *platformTransport // For handling control commands on the platform channel

	locality uint32 // uint32 so we can use atomic primitives. This is the integer locality rather than the TPMA_LOCALITY representation

	hashSequence *HashSequence // the current hash sequence
}

// Read implements [tpm2.Transport.Read]. It reads from the TPM channel.
func (t *Transport) Read(data []byte) (int, error) {
	return t.retrier.Read(data)
}

// Write implements [tpm2.Transport.Write]. It writes to the TPM channel and only supports
// TPM commands.
func (t *Transport) Write(data []byte) (int, error) {
	return t.retrier.Write(data)
}

// Close implements [tpm2.Transport.Close]. Close can be called from any
// goroutine and will unblock a goroutine that is currently waiting in
// [Read] or [Write].
func (t *Transport) Close() (err error) {
	// TODO: Make use of errors.Join here when we can use at least go 1.20
	if e := t.platform.sendCommand(cmdSessionEnd); e != nil {
		err = fmt.Errorf("cannot send session end command on platform channel: %w", e)
	}
	if _, e := t.tpm.sendCommand(cmdSessionEnd, false); e != nil {
		err = fmt.Errorf("cannot send session end command on TPM channel: %w", e)
	}

	// We need to close both the TPM and platform channels here. We don't
	// touch the tpm member because calling Close() on the retrier closes
	// the main underlying TPM channel that is shared by both. We close the
	// main TPM channel via the retrier because it has to do some work to
	// shut down some goroutines.

	if e := t.platform.close(); e != nil {
		if errors.Is(err, net.ErrClosed) {
			e = transportutil.ErrClosed
		}
		err = fmt.Errorf("cannot close platform channel: %w", e)
	}
	if e := t.retrier.Close(); e != nil {
		if errors.Is(err, net.ErrClosed) {
			e = transportutil.ErrClosed
		}
		err = fmt.Errorf("cannot close TPM channel: %w", e)
	}
	return err
}

// SimulatorVersion returns the version number reported by the simulator.
func (t *Transport) SimulatorVersion() uint32 {
	return t.simVersion
}

// SimulatorFlags indicates the flags reported by the simulator.
func (t *Transport) SimulatorFlags() SimulatorFlags {
	return t.flags
}

// HashStart begins a hash sequence with the _TPM_Hash_Start command on the TPM
// connection. If a sequence is already in progress, a _TPM_Hash_End will be sent
// for that sequence first. Whether this happens before or after TPM2_Startup
// determines whether it is a H-CRTM sequence or a DRTM sequence.
func (t *Transport) HashStart() (*HashSequence, error) {
	if t.flags&SimulatorFlagPlatformAvailable == 0 {
		return nil, ErrUnsupportedOperation
	}

	if t.hashSequence != nil {
		if err := t.hashSequence.End(); err != nil {
			return nil, fmt.Errorf("cannot end current hash sequence: %w", err)
		}
	}

	var u32 uint32
	if err := t.tpm.runCommand(cmdHashStart, 0, &u32); err != nil {
		return nil, err
	}

	out := &HashSequence{transport: t}
	t.hashSequence = out
	return out, nil
}

// Stop submits a stop command on both the TPM command and platform
// channels, which initiates a shutdown of the TPM simulator.
func (t *Transport) Stop() (err error) {
	// TODO: Make use of errors.Join here when we can use at least go 1.20
	if e := t.platform.sendCommand(cmdStop); e != nil {
		err = e
	}
	if _, e := t.tpm.sendCommand(cmdStop, false); e != nil {
		err = e
	}
	return err
}

// PowerOff puts the simulator into a power off state. It has no effect if the simulator
// is already in a power off state.
func (t *Transport) PowerOff() error {
	if t.flags&SimulatorFlagsNoPowertCtl > 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdPowerOff, 0, &u32)
}

// PowerOn puts the simulator into a power on state. It has no effect if the simulator
// is already in a power off state. If the simulator was in a power off state, it results
// in the execution of _TPM_Init().
func (t *Transport) PowerOn() error {
	if t.flags&SimulatorFlagsNoPowertCtl > 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdPowerOn, 0, &u32)
}

// Reset initiates a reset of the TPM simulator and results in the execution
// of _TPM_Init().
func (t *Transport) Reset() error {
	var u32 uint32
	return t.platform.runCommand(cmdReset, 0, &u32)
}

func (t *Transport) Restart() error {
	var u32 uint32
	return t.platform.runCommand(cmdRestart, 0, &u32)
}

// PhysicalPresenceOn enables the indication of physical presence.
func (t *Transport) PhysicalPresenceOn() error {
	if t.flags&SimulatorFlagSupportsPP == 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdPhysPresOn, 0, &u32)
}

// PhysicalPresenceOfff disables the indication of physical presence.
func (t *Transport) PhysicalPresenceOff() error {
	if t.flags&SimulatorFlagSupportsPP == 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdPhysPresOff, 0, &u32)
}

// CancelOn enables the cancellation of the limited number of commands that
// can be canceled.
func (t *Transport) CancelOn() error {
	var u32 uint32
	return t.platform.runCommand(cmdCancelOn, 0, &u32)
}

// CancelOff disables the cancellation of the limited number of commands that
// can be canceled.
func (t *Transport) CancelOff() error {
	var u32 uint32
	return t.platform.runCommand(cmdCancelOff, 0, &u32)
}

// NVOn makes NV memory available.
func (t *Transport) NVOn() error {
	if t.flags&SimulatorFlagsNoNvCtl > 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdNVOn, 0, &u32)
}

// NVOff makes NV memory unavailable.
func (t *Transport) NVOff() error {
	if t.flags&SimulatorFlagsNoNvCtl > 0 {
		return ErrUnsupportedOperation
	}

	var u32 uint32
	return t.platform.runCommand(cmdNVOff, 0, &u32)
}

// TestFailureMode is used to force the TPM into failure mode during tests.
func (t *Transport) TestFailureMode() error {
	var u32 uint32
	return t.platform.runCommand(cmdTestFailureMode, 0, &u32)
}

// Locality returns the current locality that commands sent on this transport
// will be executed at.
func (t *Transport) Locality() uint8 {
	return uint8(atomic.LoadUint32(&t.locality))
}

// SetLocality sets the locality for subsequent commands. The supplied value is
// the numeric locality rather than the TPMA_LOCALITY representation. Localities
// between 5 and 31 are invalid and the behaviour of the simulator is not defined
// in this case.
func (t *Transport) SetLocality(locality uint8) error {
	if t.flags&SimulatorFlagsNoLocalityCtl > 0 {
		return ErrUnsupportedOperation
	}
	// We use atomics here because the locality value is accessed from the
	// dedicated goroutine that NewRetrierTransport creates to access the transport
	// supplied to it (in this case, an instance of tpmMainTransport).
	atomic.SwapUint32(&t.locality, uint32(locality))
	return nil
}

// TPMRemoteAddr returns the remote address of the TPM channel.
func (t *Transport) TPMRemoteAddr() net.Addr {
	return t.tpm.remoteAddr
}

// TPMLocalAddr returns the local address of the TPM channel.
func (t *Transport) TPMLocalAddr() net.Addr {
	return t.tpm.localAddr
}

// PlatformRemoteAddr returns the remote address of the platform channel.
func (t *Transport) PlatformRemoteAddr() net.Addr {
	return t.platform.conn.RemoteAddr()
}

// PlatformLocalAddr returns the local address of the platform channel.
func (t *Transport) PlatformLocalAddr() net.Addr {
	return t.platform.conn.LocalAddr()
}

// HashSequence corresponds to a H-CRTM or DRTM sequence.
type HashSequence struct {
	transport *Transport
}

// Write writes the supplied bytes to this hash sequence with the _TPM_Hash_Data command.
func (s *HashSequence) Write(data []byte) error {
	if s.transport == nil {
		return errors.New("hash sequence ended")
	}

	var u32 uint32
	return s.transport.tpm.runCommand(cmdHashData, 2, uint32(len(data)), mu.Raw(data), &u32)
}

// End terminates this hash sequence with _TPM_Hash_End. On success,
// it will no longer be possible to use this sequence.
func (s *HashSequence) End() error {
	if s.transport == nil {
		return errors.New("hash sequence ended")
	}

	var u32 uint32
	if err := s.transport.tpm.runCommand(cmdHashEnd, 0, &u32); err != nil {
		return err
	}
	s.transport.hashSequence = nil
	s.transport = nil
	return nil
}

// platformTransport provides a way to send control commands to and receive responses
// from the platform channel
type platformTransport struct {
	// mu protects access to conn. The documentation for tpm2.Transport says
	// Close implementations should handle being called from any goroutine.
	// The platform transport uses a mutex for this because its connection
	// can't have 2 consecutive writers.
	mu sync.Mutex

	conn net.Conn // The underlying connection.
}

func newPlatformTransport(conn net.Conn) *platformTransport {
	return &platformTransport{conn: conn}
}

func (t *platformTransport) sendCommandLocked(cmd uint32, args ...interface{}) error {
	args = append([]interface{}{cmd}, args...)
	_, err := mu.MarshalToWriter(t.conn, args...)
	return err
}

// sendCommand sends a command with the specified ID and its arguments to the
// simulator via the platform channel.
func (t *platformTransport) sendCommand(cmd uint32, args ...interface{}) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.sendCommandLocked(cmd, args...)
}

// runCommand performs a sendCommand/recvResponse sequence to/from the TPM
// simulator via the platform channel. The nargs argument specifes how many
// of the variable sized args are command arguments. The rest of the arguments
// are response arguments.
func (t *platformTransport) runCommand(cmd uint32, nargs int, args ...interface{}) error {
	if nargs > len(args) {
		panic("insufficient command arguments")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if err := t.sendCommandLocked(cmd, args[:nargs]...); err != nil {
		return err
	}
	_, err := mu.UnmarshalFromReader(t.conn, args[nargs:]...)
	return err
}

func (t *platformTransport) close() error {
	return t.conn.Close()
}

// tpmTransport represents a frontent to the underlying main downstream TPM transport, for
// use by a single goroutine. It doesn't implement [io.Reader] or [io.Writer] interfaces,
// but provides specialized APIs for sending control commands and receiving responses, keeping
// the transport locked throughout a transaction.
//
// Only one of these at a time can hold the exlusive lock provided by [transportutil.LockableTransport],
// in order to communicate with the underlying main downstream transport.
type tpmTransport struct {
	transport         transportutil.LockableTransport
	remoteAddr        net.Addr
	localAddr         net.Addr
	expectingResponse bool // Whether more calls to recvTransport or Read are expected for the current transaction
}

func newTpmTransport(transport transportutil.LockableTransport, remoteAddr, localAddr net.Addr) *tpmTransport {
	return &tpmTransport{
		transport:  transport,
		remoteAddr: remoteAddr,
		localAddr:  localAddr,
	}
}

// sendCommand sends a command with the specified ID and its arguments to the
// simulator via the TPM channel. This acquires the lock for the transport, preventing
// other users of the underlying downstream transport from using it. If expectResponse
// is true, the transport lock is not released when this function exits, as it expects
// one or more calls to recvResponse.
//
// The transport lock is released if this function returns an error.
func (t *tpmTransport) sendCommand(cmd uint32, expectResponse bool, args ...interface{}) (n int, err error) {
	t.transport.Lock()
	t.expectingResponse = expectResponse
	defer func() {
		if err != nil {
			// If an error occurred, we aren't expecting a call to recvResponse
			t.expectingResponse = false
		}
		if t.expectingResponse {
			// If we're expecting a call to recvResponse, defer releasing the lock
			return
		}
		t.transport.Unlock()
	}()

	args = append([]interface{}{cmd}, args...)
	return mu.MarshalToWriter(t.transport, args...)
}

// recvFrom receives a response for a previously sent command from the
// simulator via the TPM channel. If a response is not being waited for
// an error will be returned. If the last argument is true, the lock for
// this transport will be released, endkng the current transaction and
// permitting other users of the main downstream TPM channel to use it.
//
// The transport lock is released if this function returns an error.
func (t *tpmTransport) recvResponse(last bool, args ...interface{}) (int, error) {
	if !t.expectingResponse {
		return 0, errors.New("not waiting for a response")
	}

	defer func() {
		// Only drop the lock when we are expecting no more calls for this transaction.
		if !last {
			return
		}
		t.transport.Unlock()
		t.expectingResponse = false
	}()

	return mu.UnmarshalFromReader(t.transport, args...)
}

func (t *tpmTransport) runCommand(cmd uint32, nargs int, args ...interface{}) error {
	if nargs > len(args) {
		panic("insufficient command arguments")
	}
	if _, err := t.sendCommand(cmd, true, args[:nargs]...); err != nil {
		return err
	}
	_, err := t.recvResponse(true, args[nargs:]...)
	return err
}

// tpmMainTransport is an extension to tpmTransport for handling actual TPM commands.
// It is used by transportutil.NewRetrierTransport which interacts with it in a retry
// loop which runs in its own dedicated goroutine.
//
// It automatically encapsulates commands to and decapsulates responses from the
// TPM simulator wire format.
type tpmMainTransport struct {
	tpmTransport
	locality *uint32 // Locality of commands submitted to the simulator, in numeric form rather than TPMA_LOCALITY

	lr *io.LimitedReader // a io.LimitedReader for the current response
}

func newTpmMainTransport(transport transportutil.LockableTransport, locality *uint32, remoteAddr, localAddr net.Addr) *tpmMainTransport {
	t := newTpmTransport(transport, remoteAddr, localAddr)
	return &tpmMainTransport{
		tpmTransport: *t,
		locality:     locality,
	}
}

func (t *tpmMainTransport) Read(data []byte) (int, error) {
	if t.lr == nil {
		// We're beginning a new response. The first 4 bytes are
		// the size of the command packet
		var size uint32
		if _, err := t.recvResponse(false, &size); err != nil {
			return 0, err
		}

		// Make a limited reader to read the response directly from
		// the transport.
		t.lr = &io.LimitedReader{R: t.transport, N: int64(size)}
	}

	n, err := t.lr.Read(data)
	if t.lr.N == 0 {
		// We've read the last bytes, so grab the last part of the response
		t.lr = nil
		if err == io.EOF {
			err = nil
		}
		var u32 uint32
		if _, err := t.recvResponse(true, &u32); err != nil {
			return n, err
		}
	}
	return n, err
}

func (t *tpmMainTransport) Write(data []byte) (int, error) {
	if t.expectingResponse {
		return 0, transportutil.ErrBusy
	}

	// We're called from the command retrier, which guarantees that commands
	// are written in a single command, so there's no need for an additional
	// stage of buffering here - just send what we have.
	n, err := t.sendCommand(cmdTPMSendCommand, true, uint8(atomic.LoadUint32(t.locality)&0xff), uint32(len(data)), mu.RawBytes(data))
	n -= (n - len(data))
	if n < 0 {
		n = 0
	}
	if n < len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

func (t *tpmMainTransport) Close() error {
	return t.transport.Close()
}

// OpenConnection attempts to open a connection to a TPM simulator on the
// specified host and port. The port argument corresponds to the TPM
// command server. The simulator will also provide a platform server on
// port+1. If host is an empty string, it defaults to "localhost".
//
// If successful, it returns a new Transport instance which can be passed to
// tpm2.NewTPMContext.
//
// Deprecated: Use [NewDevice], [NewLocalDevice] or [DefaultDevice].
func OpenConnection(host string, port uint) (*Transport, error) {
	device := NewDevice(WithHost(host), WithPort(port))
	return device.openInternal()
}
