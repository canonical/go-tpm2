// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

/*
Package mssim provides an interface for communicating with a TPM simulator
*/
package mssim

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
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

func (d *Device) openInternal() (*Transport, error) {
	tpmAddress := net.JoinHostPort(d.Host(), strconv.FormatUint(uint64(d.Port()), 10))
	platformAddress := net.JoinHostPort(d.Host(), strconv.FormatUint(uint64(d.Port())+1, 10))

	internal := &internalTransport{
		locality: 3,
	}

	tpm, err := net.Dial("tcp", tpmAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to TPM socket: %w", err)
	}
	internal.tpm = tpm

	platform, err := net.Dial("tcp", platformAddress)
	if err != nil {
		internal.tpm.Close()
		return nil, fmt.Errorf("cannot connect to platform socket: %w", err)
	}
	internal.platform = platform

	if err := internal.runPlatformCommand(cmdPowerOn); err != nil {
		return nil, fmt.Errorf("cannot complete power on command: %w", err)
	}
	if err := internal.runPlatformCommand(cmdNVOn); err != nil {
		return nil, fmt.Errorf("cannot complete NV on command: %w", err)
	}

	internal.w = transportutil.BufferCommands(&commandSender{transport: internal}, maxCommandSize)

	return &Transport{
		retrier: transportutil.NewRetrierTransport(internal, transportutil.RetryParams{
			MaxRetries:     4,
			InitialBackoff: 20 * time.Millisecond,
			BackoffRate:    2,
		}),
		internal: internal,
	}, nil
}

// Open implements [tpm2.TPMDevice.Open].
//
// The returned transport will automatically retry commands that fail with TPM_RC_RETRY or
// TPM_RC_YIELDED. It will also retry commands that fail with TPM_RC_TESTING if the command
// wasn't TPM_CC_SELF_TEST.
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
// simulator interface.
type Transport struct {
	retrier  tpm2.Transport
	internal *internalTransport
}

// Read implements [tpm2.Transport.Read].
func (t *Transport) Read(data []byte) (int, error) {
	return t.retrier.Read(data)
}

// Write implements [tpm2.Transport.Write].
func (t *Transport) Write(data []byte) (int, error) {
	return t.retrier.Write(data)
}

// Close implements [tpm2.Transport.Close].
func (t *Transport) Close() (err error) {
	return t.retrier.Close()
}

// Reset submits the reset command on the platform connection, which
// initiates a reset of the TPM simulator and results in the execution
// of _TPM_Init().
func (t *Transport) Reset() error {
	return t.internal.runPlatformCommand(cmdReset)
}

// Stop submits a stop command on both the TPM command and platform
// channels, which initiates a shutdown of the TPM simulator.
func (t *Transport) Stop() (out error) {
	if err := t.internal.sendPlatformCommand(cmdStop); err != nil {
		return fmt.Errorf("cannot send platform command: %w", err)
	}
	if _, err := t.internal.sendTpmCommand(cmdStop); err != nil {
		return fmt.Errorf("cannot send TPM command: %w", err)
	}
	return nil
}

// SetLocality sets the locality for subsequent commands. The supplied value is
// the numeric locality rather than the TPMA_LOCALITY representation. It returns the
// currently set locality. Localities between 5 and 31 are invalid and the behaviour
// of the simulator is not defined in this case.
func (t *Transport) SetLocality(locality uint8) uint8 {
	prev := t.internal.locality
	t.internal.locality = locality
	return prev
}

type commandSender struct {
	transport *internalTransport
}

func (s *commandSender) Write(data []byte) (int, error) {
	n, err := s.transport.sendTpmCommand(cmdTPMSendCommand, s.transport.locality, uint32(len(data)), mu.RawBytes(data))
	n -= (n - len(data))
	if n < 0 {
		n = 0
	}
	if n < len(data) && err == nil {
		err = io.ErrShortWrite
	}
	return n, err
}

type internalTransport struct {
	tpm      net.Conn
	platform net.Conn

	timeout  time.Duration
	locality uint8 // Locality of commands submitted to the simulator on this interface

	w io.Writer
	r io.Reader

	tpmSenderMu sync.Mutex
}

func (t *internalTransport) Read(data []byte) (int, error) {
	for {
		if t.r == nil {
			var size uint32
			if err := binary.Read(t.tpm, binary.BigEndian, &size); err != nil {
				return 0, err
			}

			t.r = io.LimitReader(t.tpm, int64(size))
		}

		n, err := t.r.Read(data)
		if err == io.EOF {
			t.r = nil
			err = nil

			var trash uint32
			if err := binary.Read(t.tpm, binary.BigEndian, &trash); err != nil {
				return 0, err
			}

			if n == 0 {
				continue
			}
		}
		return n, err
	}
}

func (t *internalTransport) Write(data []byte) (int, error) {
	return t.w.Write(data)
}

func (t *internalTransport) Close() (err error) {
	if e := t.sendPlatformCommand(cmdSessionEnd); e != nil {
		err = fmt.Errorf("cannot send session end command on platform channel: %w", e)
	}
	if _, e := t.sendTpmCommand(cmdSessionEnd); e != nil {
		err = fmt.Errorf("cannot send session end command on TPM channel: %w", e)
	}
	if e := t.platform.Close(); e != nil {
		err = fmt.Errorf("cannot close platform channel: %w", e)
	}
	if e := t.tpm.Close(); e != nil {
		err = fmt.Errorf("cannot close TPM command channel: %w", e)
	}
	return err
}

func (t *internalTransport) sendTpmCommand(cmd uint32, args ...interface{}) (int, error) {
	t.tpmSenderMu.Lock()
	defer t.tpmSenderMu.Unlock()

	args = append([]interface{}{cmd}, args...)
	n, err := mu.MarshalToWriter(t.tpm, args...)
	if err != nil {
		return n, fmt.Errorf("cannot send command: %w", err)
	}
	return n, nil
}

func (t *internalTransport) sendPlatformCommand(cmd uint32, args ...interface{}) error {
	args = append([]interface{}{cmd}, args...)
	if _, err := mu.MarshalToWriter(t.platform, args...); err != nil {
		return fmt.Errorf("cannot send command: %w", err)
	}
	return nil
}

func (t *internalTransport) runPlatformCommand(cmd uint32, args ...interface{}) error {
	if err := t.sendPlatformCommand(cmd, args...); err != nil {
		return fmt.Errorf("cannot send command: %w", err)
	}

	var trash uint32
	if _, err := mu.UnmarshalFromReader(t.platform, &trash); err != nil {
		return fmt.Errorf("cannot read response to command: %w", err)
	}

	return nil
}

// NewLocalDevice returns a new device structure for the specified port on the
// local machine.
func NewLocalDevice(port uint) *Device {
	return &Device{port: port}
}

// NewDevice returns a new device structure for the specified host and port.
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
