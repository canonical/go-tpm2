// Copyright 2019-2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
package mssim_test

import (
	. "github.com/canonical/go-tpm2/mssim"
	. "gopkg.in/check.v1"
)

type deviceSuite struct{}

var _ = Suite(&deviceSuite{})

func (s *deviceSuite) TestNewDevice(c *C) {
	dev := NewDevice("localhost", 2321)
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 2321}, &DeviceAddr{Host: "localhost", Port: 2322})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentHost(c *C) {
	dev := NewDevice("192.18.1.50", 2321)
	expectedDev := NewMockDevice(&DeviceAddr{Host: "192.18.1.50", Port: 2321}, &DeviceAddr{Host: "192.18.1.50", Port: 2322})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewDeviceDifferentPort(c *C) {
	dev := NewDevice("localhost", 4444)
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 4444}, &DeviceAddr{Host: "localhost", Port: 4445})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewLocalDevice(c *C) {
	dev := NewLocalDevice(2321)
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 2321}, &DeviceAddr{Host: "localhost", Port: 2322})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestNewLocalDeviceDifferentPort(c *C) {
	dev := NewLocalDevice(4444)
	expectedDev := NewMockDevice(&DeviceAddr{Host: "localhost", Port: 4444}, &DeviceAddr{Host: "localhost", Port: 4445})
	c.Check(dev, DeepEquals, expectedDev)
}

func (s *deviceSuite) TestTPMAndPlatformAddr(c *C) {
	dev := NewLocalDevice(2321)
	c.Check(dev.TPMAddr(), DeepEquals, &DeviceAddr{Host: "localhost", Port: 2321})
	c.Check(dev.PlatformAddr(), DeepEquals, &DeviceAddr{Host: "localhost", Port: 2322})
}
