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
	// DefaultPort is the default IP port that the TPM channel of
	// the simulator runs on. The platform port is normally this + 1,
	// but can be customized by WithPlatformPort.
	DefaultPort uint16 = 2321
)

var (
	// DefaultDevice is configured for the simulator, running locally
	// with the default port of 2321 for the TPM channel and 2322 for
	// the platform channel.
	DefaultDevice *Device = NewDevice()

	netDial = net.Dial
)

type deviceAddr struct {
	Host string
	Port uint16
}

func (a deviceAddr) Network() string {
	return "tcp"
}

func (a deviceAddr) String() string {
	return net.JoinHostPort(a.Host, strconv.FormatUint(uint64(a.Port), 10))
}

// DeviceOption is an option passed to any function that creates
// a new [Device] instance.
type DeviceOption func(*Device)

// Device describes a TPM simulator device.
type Device struct {
	tpm         deviceAddr
	platform    deviceAddr
	retryParams transportutil.RetryParams
}

// NewDevice returns a new device structure. By default, the host is localhost,
// the TPM channel port set to [DefaultPort], and it assumes that the platform
// channel port is [DefaultPort] + 1. The default retry parameters have
// MaxRetries set to 4, InitialBackoff set to 20ms and the BackoffRate set to 2.
//
// It can be customized by any of the [DeviceOption]s.
//
// The returned device is safe to use from multiple goroutines simultaneously.
func NewDevice(opts ...DeviceOption) *Device {
	dev := &Device{
		tpm: deviceAddr{
			Host: "localhost",
			Port: DefaultPort,
		},
		platform: deviceAddr{
			Host: "localhost",
			Port: DefaultPort + 1,
		},
		retryParams: transportutil.RetryParams{
			MaxRetries:     4,
			InitialBackoff: 20 * time.Millisecond,
			BackoffRate:    2,
		},
	}
	for _, opt := range opts {
		opt(dev)
	}
	return dev
}

// WithHost is used to customize the host address on which the simulator's
// TCP ports can be accessed. The default is localhost.
func WithHost(host string) DeviceOption {
	return func(d *Device) {
		d.tpm.Host = host
		d.platform.Host = host
	}
}

// WithPort is used to customize the TCP ports on which the TPM and platform
// channels for the simulator are accessed. It sets the platform channel port
// to the TPM channel port + 1.
func WithPort(port uint16) DeviceOption {
	return func(d *Device) {
		d.tpm.Port = port
		d.platform.Port = port + 1
	}
}

// WithTPMPort is used to customize the TCP port on which the TPM channel
// for the simulator is accessed. It doesn't modify the port for the platform
// channel.
func WithTPMPort(port uint16) DeviceOption {
	return func(d *Device) {
		d.tpm.Port = port
	}
}

// WithPlatformPort is used to customize the TCP port on which the platform
// chanel for the simulator is accessed. It doesn't modify the port for the
// TPM channel
func WithPlatformPort(port uint16) DeviceOption {
	return func(d *Device) {
		d.platform.Port = port
	}
}

// WithRetryParams is used to customize the retry parameters for a device.
func WithRetryParams(maxRetries uint, initialBackoff time.Duration, backoffRate uint) DeviceOption {
	return func(d *Device) {
		d.retryParams = transportutil.RetryParams{
			MaxRetries:     maxRetries,
			InitialBackoff: initialBackoff,
			BackoffRate:    backoffRate,
		}
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

// RetryParams returns the command retry parameters for this device.
func (d *Device) RetryParams() transportutil.RetryParams {
	return d.retryParams
}

// Host is the host that the TPM simulator is running on.
//
// Deprecated: Use [Device.TPMAddr] or [Device.PlatformAddr] instead.
func (d *Device) Host() string {
	return d.tpm.Host
}

// Port is the port number of the TPM simulator's command channel.
// Its platform channel runs on the next port number.
//
// Deprecated: Use [Device.TPMAddr] or [Device.PlatformAddr] instead.
func (d *Device) Port() uint {
	return uint(d.tpm.Port)
}

func (d *Device) openInternal() (transport *Transport, err error) {
	// Open up the TPM and platform sockets
	tpm, err := netDial(d.tpm.Network(), d.tpm.String())
	if err != nil {
		return nil, fmt.Errorf("cannot connect to TPM socket: %w", err)
	}

	platform, err := netDial(d.platform.Network(), d.platform.String())
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
		newTpmMainTransport(mux.NewTransport(), &tmp.locality, tpm.RemoteAddr(), tpm.LocalAddr()), d.retryParams)

	// Early exits from this point should see retrier.Close() being called to
	// shut down the goroutines it starts.

	// Build another transport for control commands for the TPM socket, used
	// on the current goroutine
	tmp.tpm = newTpmTransport(mux.NewTransport(), tpm.RemoteAddr(), tpm.LocalAddr())

	// Build a transport for hanlding control commands on the platform socket.
	tmp.platform = newPlatformTransport(platform)

	transport = tmp

	// Obtain information from the simulator
	var u32 uint32
	if err := transport.tpm.runCommand(cmdRemoteHandshake, 1, uint32(1), &transport.simVersion, &transport.flags, &u32); err != nil {
		return nil, fmt.Errorf("cannot complete handshake with simulator: %w", err)
	}

	// Ensure the simulator is powered on and NV is available.
	if transport.flags&SimulatorFlagsNoPowertCtl == 0 {
		if err := transport.PowerOn(); err != nil {
			return nil, fmt.Errorf("cannot complete power on command on platform channel: %w", err)
		}
	}
	if transport.flags&SimulatorFlagsNoNvCtl == 0 {
		if err := transport.NVOn(); err != nil {
			return nil, fmt.Errorf("cannot complete NV on command on plarform channel: %w", err)
		}
	}

	return transport, nil
}
