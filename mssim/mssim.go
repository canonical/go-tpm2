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
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/internal/transportutil"
	"github.com/canonical/go-tpm2/mu"
)

const (
	cmdPowerOn        uint32 = 1
	cmdTPMSendCommand uint32 = 8
	cmdNVOn           uint32 = 11
	cmdReset          uint32 = 17
	cmdSessionEnd     uint32 = 20
	cmdStop           uint32 = 21
)

const (
	DefaultPort uint = 2321

	maxCommandSize = 4096
)

var (
	DefaultDevice *Device = &Device{port: DefaultPort}
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

// Device describes a TPM simulator device.
type Device struct {
	host string
	port uint
}

// Host is the host that the TPM simulator is running on.
func (d *Device) Host() string {
	if d.host == "" {
		return "localhost"
	}
	return d.host
}

// Port is the port number of the TPM simulator's command channel.
// Its platform channel runs on the next port number.
func (d *Device) Port() uint {
	return d.port
}

func (d *Device) openInternal() (transport *Transport, err error) {
	tpmAddress := net.JoinHostPort(d.Host(), strconv.FormatUint(uint64(d.Port()), 10))
	platformAddress := net.JoinHostPort(d.Host(), strconv.FormatUint(uint64(d.Port())+1, 10))

	// Open up the TPM and platform sockets
	tpm, err := net.Dial("tcp", tpmAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to TPM socket: %w", err)
	}

	platform, err := net.Dial("tcp", platformAddress)
	if err != nil {
		tpm.Close()
		return nil, fmt.Errorf("cannot connect to platform socket: %w", err)
	}

	defer func() {
		if err == nil {
			return
		}
		switch {
		case transport != nil: // Once we have a Transport, close it on error
			transport.Close()
		default: // Before we have a Transport, close each TCP socket individually on error
			platform.Close()
			tpm.Close()
		}
	}()

	tmp := new(Transport)

	// Build a threadsafe way to proxy calls to/from the TPM socket. We communicate
	// with the TPM socket from:
	// - The dedicated retry loop goroutine in the command retrier, for TPM commands.
	// - The transport public API on the current goroutine, for control commands.
	// The supplied TPM connection will be accessed on a dedicated internal goroutine.
	mux := transportutil.NewMultiplexedTransportManager(tpm)

	// Make a retrier for the main public tpm2.Transport API to communicate TPM
	// commands with. The retrier communicates with the supplied transport on a
	// dedicated goroutine.
	tmp.retrier = transportutil.NewRetrierTransport(
		newTpmMainTransport(mux.NewTransport(), &tmp.locality),
		transportutil.RetryParams{
			MaxRetries:     4,
			InitialBackoff: 20 * time.Millisecond,
			BackoffRate:    2,
		})

	// Early exits from this point should see retrier.Close() being called to
	// shut down the goroutines it starts.

	// Build another transport for control commands for the TPM socket, used
	// on the current goroutine
	tmp.tpm = newTpmTransport(mux.NewTransport())

	// Build a transport for hanlding control commands on the platform socket.
	tmp.platform = newPlatformTransport(platform)

	transport = tmp

	// Ensure the simulator is powered on and NV is available.
	var u32 uint32
	if err := transport.platform.runCommand(cmdPowerOn, 0, &u32); err != nil {
		return nil, fmt.Errorf("cannot complete power on command on platform channel: %w", err)
	}
	if err := transport.platform.runCommand(cmdNVOn, 0, &u32); err != nil {
		return nil, fmt.Errorf("cannot complete NV on command on plarform channel: %w", err)
	}

	return transport, nil
}

// Open implements [tpm2.TPMDevice.Open].
//
// The returned transport will automatically retry commands that fail with TPM_RC_RETRY or
// TPM_RC_YIELDED. It will also retry commands that fail with TPM_RC_TESTING if the command
// wasn't TPM_CC_SELF_TEST.
//
// The returned transport should not be used from more than one goroutine simultaneously.
//
// Before returning an open transport, this package will send some platform commands to
// make sure that the simulator TPM device is on and NV storage is available. If this is
// already the case, then these commands are no-ops. It does not call TPM2_Startup.
func (d *Device) Open() (tpm2.Transport, error) {
	return d.openInternal()
}

// String implements [fmt.Stringer].
func (d *Device) String() string {
	return fmt.Sprintf("mssim device, host=\"%s\", port=%d", d.Host(), d.Port())
}

// Tcti represents a connection to a TPM simulator that implements the Microsoft TPM2
// simulator interface.
//
// Deprecated: Use [Transport].
type Tcti = Transport

// Transport represents a connection to a TPM simulator that implements the Microsoft TPM2
// simulator interface. It should not be used from multiple goroutines simultaneously.
type Transport struct {
	retrier  tpm2.Transport     // For handling TPM commands on the TPM channel
	tpm      *tpmTransport      // For handling control commands on the TPM channel
	platform *platformTransport // For handling control commands on the platform channel

	locality uint32 // uint32 so we can use atomic primitives. This is the integer locality rather than the TPMA_LOCALITY representation
}

// Read implements [tpm2.Transport.Read].
func (t *Transport) Read(data []byte) (int, error) {
	return t.retrier.Read(data)
}

// Write implements [tpm2.Transport.Write].
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
		err = fmt.Errorf("cannot close platform channel: %w", e)
	}
	if e := t.retrier.Close(); e != nil {
		err = fmt.Errorf("cannot close TPM channel: %w", e)
	}
	return err
}

// Reset submits the reset command on the platform connection, which
// initiates a reset of the TPM simulator and results in the execution
// of _TPM_Init().
func (t *Transport) Reset() error {
	var u32 uint32
	return t.platform.runCommand(cmdReset, 0, &u32)
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

// SetLocality sets the locality for subsequent commands. The supplied value is
// the numeric locality rather than the TPMA_LOCALITY representation. It returns the
// currently set locality. Localities between 5 and 31 are invalid and thebehaviour
// of the simulator is not defined in this case.
func (t *Transport) SetLocality(locality uint8) uint8 {
	return uint8(atomic.SwapUint32(&t.locality, uint32(locality)))
}

// platformTransport provides a way to send control commands to and receive responses
// from the platform channel
type platformTransport struct {
	// mu protects access to conn. The documentation for tpm2.Transport says
	// Close implementations should handle being called from any goroutine.
	// The platform transport uses a mutex for this because its connection
	// can't have 2 consecutive writers.
	mu sync.Mutex

	conn net.Conn
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
	expectingResponse bool // Whether more calls to recvTransport or Read are expected for the current transaction
}

func newTpmTransport(transport transportutil.LockableTransport) *tpmTransport {
	return &tpmTransport{transport: transport}
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

// commandSender is an implementation of io.Writer that encapsulates a complete TPM
// command into the simulator wire format and sends them via tpmMainTransport.sendCommand.
type commandSender struct {
	transport *tpmMainTransport
}

func (s *commandSender) Write(data []byte) (int, error) {
	n, err := s.transport.sendCommand(cmdTPMSendCommand, true, uint8(atomic.LoadUint32(s.transport.locality)&0xff), uint32(len(data)), mu.RawBytes(data))
	n -= (n - len(data))
	if n < 0 {
		n = 0
	}
	if n < len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
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

	w io.Writer // For buffering commands

	lr *io.LimitedReader // a io.LimitedReader for the current response
}

func newTpmMainTransport(transport transportutil.LockableTransport, locality *uint32) *tpmMainTransport {
	t := newTpmTransport(transport)
	out := &tpmMainTransport{
		tpmTransport: *t,
		locality:     locality,
	}
	out.w = transportutil.BufferCommands(&commandSender{transport: out}, maxCommandSize)
	return out
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
	return t.w.Write(data) // Buffer the commands
}

func (t *tpmMainTransport) Close() error {
	return t.transport.Close()
}

// NewLocalDevice returns a new device structure for the specified port on the
// local machine. It is safe to use from multiple goroutines simultaneously.
func NewLocalDevice(port uint) *Device {
	return &Device{port: port}
}

// NewDevice returns a new device structure for the specified host and port. It
// is safe to use from multiple goroutines simultaneously.
func NewDevice(host string, port uint) *Device {
	return &Device{host: host, port: port}
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
	device := NewDevice(host, port)
	return device.openInternal()
}
