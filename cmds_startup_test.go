// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"testing"

	. "github.com/chrisccoulson/go-tpm2"
)

func TestStartup(t *testing.T) {
	tpm, tcti := openTPMSimulatorForTesting(t)
	defer closeTPM(t, tpm)

	run := func(t *testing.T, shutdownType, startupType StartupType) (*TimeInfo, *TimeInfo) {
		timeBefore, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}

		if err := tpm.Shutdown(shutdownType); err != nil {
			t.Errorf("Shutdown failed: %v", err)
		}
		if err := tcti.Reset(); err != nil {
			t.Errorf("Reset failed: %v", err)
		}
		if err := tpm.Startup(startupType); err != nil {
			t.Errorf("Startup failed: %v", err)
		}

		time, err := tpm.ReadClock()
		if err != nil {
			t.Fatalf("ReadClock failed: %v", err)
		}

		return timeBefore, time
	}

	t.Run("Resume", func(t *testing.T) {
		time1, time2 := run(t, StartupState, StartupState)
		if time2.ClockInfo.ResetCount != time1.ClockInfo.ResetCount {
			t.Errorf("Unexpected resetCount")
		}
		if time2.ClockInfo.RestartCount != time1.ClockInfo.RestartCount+1 {
			t.Errorf("Unexpected restartCount")
		}
	})

	t.Run("Restart", func(t *testing.T) {
		time1, time2 := run(t, StartupState, StartupClear)
		if time2.ClockInfo.ResetCount != time1.ClockInfo.ResetCount {
			t.Errorf("Unexpected resetCount")
		}
		if time2.ClockInfo.RestartCount != time1.ClockInfo.RestartCount+1 {
			t.Errorf("Unexpected restartCount")
		}
	})

	t.Run("Reset", func(t *testing.T) {
		time1, time2 := run(t, StartupClear, StartupClear)
		if time2.ClockInfo.ResetCount != time1.ClockInfo.ResetCount+1 {
			t.Errorf("Unexpected resetCount")
		}
		if time2.ClockInfo.RestartCount != 0 {
			t.Errorf("Unexpected restartCount")
		}
	})
}
