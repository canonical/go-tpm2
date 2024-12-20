// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
package mssim

import (
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/transportutil"
)

const (
	DefaultPort uint = 2321
)

func defaultDevice() *Device {
	return NewLocalDevice(DefaultPort)
}

var (
	DefaultDevice *Device = defaultDevice()
)

type deviceAddr struct {
	host string
	port uint
}

func (a deviceAddr) Network() string {
	return "tcp"
}

func (a deviceAddr) String() string {
	return net.JoinHostPort(a.host, strconv.FormatUint(uint64(a.port), 10))
}

// Device describes a TPM simulator device.
type Device struct {
	tpm      *deviceAddr
	platform *deviceAddr
}

// NewLocalDevice returns a new device structure for the specified port on the
// local machine. It is safe to use from multiple goroutines simultaneously. Note
// that this assumes the supplied port is for the TPM channel, and that the platform
// channel is on the subsequent port.
func NewLocalDevice(port uint) *Device {
	return NewDevice("localhost", port)
}

// NewDevice returns a new device structure for the specified host and port. It
// is safe to use from multiple goroutines simultaneously. Note that this assumes
// the supplied port is for the TPM channel, and that the platform channel is on
// the subsequent port.
func NewDevice(host string, port uint) *Device {
	return &Device{
		tpm: &deviceAddr{
			host: host,
			port: port,
		},
		platform: &deviceAddr{
			host: host,
			port: port + 1,
		},
	}
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

// TPMAddr returns the address of the TPM channel for this device.
func (d *Device) TPMAddr() net.Addr {
	return d.tpm
}

// PlatformAddr returns the address of the platform channel for this device.
func (d *Device) PlatformAddr() net.Addr {
	return d.platform
}

// Host is the host that the TPM simulator is running on.
//
// Deprecated: Use [Device.TPMAddr] or [Device.PlatformAddr] instead.
func (d *Device) Host() string {
	if d.tpm.host == "" {
		return "localhost"
	}
	return d.tpm.host
}

// Port is the port number of the TPM simulator's command channel.
// Its platform channel runs on the next port number.
//
// Deprecated: Use [Device.TPMAddr] or [Device.PlatformAddr] instead.
func (d *Device) Port() uint {
	return d.tpm.port
}

func (d *Device) openInternal() (transport *Transport, err error) {
	// Open up the TPM and platform sockets
	tpm, err := net.Dial(d.tpm.Network(), d.tpm.String())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to TPM socket: %w", err)
	}

	platform, err := net.Dial(d.platform.Network(), d.platform.String())
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
