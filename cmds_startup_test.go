// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	. "github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/testutil"

	. "gopkg.in/check.v1"
)

type startupSuite struct {
	testutil.TPMSimulatorTest
}

var _ = Suite(&startupSuite{})

func (s *startupSuite) runStartupTest(c *C, shutdownType, startupType StartupType) (*TimeInfo, *TimeInfo) {
	timeBefore, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	c.Check(s.TPM.Shutdown(shutdownType), IsNil)
	c.Check(s.TCTI.(*TctiMssim).Reset(), IsNil)
	c.Check(s.TPM.Startup(startupType), IsNil)

	time, err := s.TPM.ReadClock()
	c.Assert(err, IsNil)

	return timeBefore, time
}

func (s *startupSuite) TestResume(c *C) {
	time1, time2 := s.runStartupTest(c, StartupState, StartupState)
	c.Check(time2.ClockInfo.ResetCount, Equals, time1.ClockInfo.ResetCount)
	c.Check(time2.ClockInfo.RestartCount, Equals, time1.ClockInfo.RestartCount+1)
}

func (s *startupSuite) TestRestart(c *C) {
	time1, time2 := s.runStartupTest(c, StartupState, StartupClear)
	c.Check(time2.ClockInfo.ResetCount, Equals, time1.ClockInfo.ResetCount)
	c.Check(time2.ClockInfo.RestartCount, Equals, time1.ClockInfo.RestartCount+1)
}

func (s *startupSuite) TestReset(c *C) {
	time1, time2 := s.runStartupTest(c, StartupClear, StartupClear)
	c.Check(time2.ClockInfo.ResetCount, Equals, time1.ClockInfo.ResetCount+1)
	c.Check(time2.ClockInfo.RestartCount, Equals, uint32(0))
}
