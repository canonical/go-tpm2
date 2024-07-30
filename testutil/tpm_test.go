// Copyright 2024 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package testutil_test

import (
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	. "github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

type tpmSuite struct {
	TPMTest
}

var _ = Suite(&tpmSuite{})

func (s *tpmSuite) TestNewTransportBackedDeviceClosable(c *C) {
	device := NewTransportBackedDevice(s.Transport, true)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)

	transport, err := device.Open()
	c.Assert(err, IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 1)

	var tmpl TransportWrapper
	c.Check(transport, Implements, &tmpl)
	c.Check(transport.(TransportWrapper).Unwrap(), Equals, s.Transport)

	c.Check(transport.Close(), IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)
	c.Check(transport.Close(), ErrorMatches, `transport already closed`)

	tpm := s.TPM
	s.TPM = nil
	c.Check(tpm.Close(), internal_testutil.IsOneOf(ErrorMatches), []string{
		`.*use of closed network connection$`,
		`.*file already closed$`,
		`.*transport already closed$`})
}

func (s *tpmSuite) TestNewTransportBackedDeviceNotClosable(c *C) {
	device := NewTransportBackedDevice(s.Transport, false)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)

	transport, err := device.Open()
	c.Assert(err, IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 1)

	var tmpl TransportWrapper
	c.Check(transport, Implements, &tmpl)
	c.Check(transport.(TransportWrapper).Unwrap(), Equals, s.Transport)

	c.Check(transport.Close(), IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)
	c.Check(transport.Close(), ErrorMatches, `transport already closed`)

	// The test fixture will fail if the underlying transport was closed
	// unexpectedly
}

func (s *tpmSuite) TestNewTransportBackedDeviceMultipleOpen(c *C) {
	device := NewTransportBackedDevice(s.Transport, false)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)

	transport1, err := device.Open()
	c.Assert(err, IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 1)

	transport2, err := device.Open()
	c.Assert(err, IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 2)

	c.Check(transport1.Close(), IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 1)
	c.Check(transport2.Close(), IsNil)
	c.Check(device.NumberOpen(), internal_testutil.IntEqual, 0)

	// The test fixture will fail if the underlying transport was closed
	// unexpectedly
}
