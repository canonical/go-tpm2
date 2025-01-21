// Copyright 2019-2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package mssim_test

import (
	"time"

	. "github.com/canonical/go-tpm2/mssim"
	"github.com/canonical/go-tpm2/transportutil"
	. "gopkg.in/check.v1"
)

type deviceSuite struct{}

var _ = Suite(&deviceSuite{})

var (
	defaultRetryParams = transportutil.RetryParams{
		MaxRetries:     4,
		InitialBackoff: 20 * time.Millisecond,
		BackoffRate:    2,
	}
)

func (s *deviceSuite) TestNewDevice(c *C) {
	dev := NewDevice()
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 2321}, &DeviceAddr{Host: "localhost", Port: 2322}, &defaultRetryParams)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentHost(c *C) {
	dev := NewDevice(WithHost("192.18.1.50"))
	expectedDev := NewMockDevice(&DeviceAddr{Host: "192.18.1.50", Port: 2321}, &DeviceAddr{Host: "192.18.1.50", Port: 2322}, &defaultRetryParams)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentPort(c *C) {
	dev := NewDevice(WithPort(4444))
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 4444}, &DeviceAddr{Host: "localhost", Port: 4445}, &defaultRetryParams)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentTPMPort(c *C) {
	dev := NewDevice(WithTPMPort(4444))
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 4444}, &DeviceAddr{Host: "localhost", Port: 2322}, &defaultRetryParams)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentPlatformPort(c *C) {
	dev := NewDevice(WithPlatformPort(4444))
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 2321}, &DeviceAddr{Host: "localhost", Port: 4444}, &defaultRetryParams)
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceWithDifferentRetryParams(c *C) {
	dev := NewDevice(WithRetryParams(10, 10*time.Millisecond, 3))
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 2321}, &DeviceAddr{Host: "localhost", Port: 2322}, &transportutil.RetryParams{
		MaxRetries:     10,
		InitialBackoff: 10 * time.Millisecond,
		BackoffRate:    3,
	})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestInfoMethods(c *C) {
	dev := NewDevice()
	c.Check(dev.TPMAddr(), DeepEquals, DeviceAddr{Host: "localhost", Port: 2321})
	c.Check(dev.PlatformAddr(), DeepEquals, DeviceAddr{Host: "localhost", Port: 2322})
	c.Check(dev.RetryParams(), DeepEquals, defaultRetryParams)
}
