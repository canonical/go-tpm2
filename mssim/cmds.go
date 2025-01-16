// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
package mssim

const (
	cmdPowerOn         uint32 = 1
	cmdPowerOff        uint32 = 2
	cmdPhysPresOn      uint32 = 3
	cmdPhysPresOff     uint32 = 4
	cmdHashStart       uint32 = 5
	cmdHashData        uint32 = 6
	cmdHashEnd         uint32 = 7
	cmdTPMSendCommand  uint32 = 8
	cmdCancelOn        uint32 = 9
	cmdCancelOff       uint32 = 10
	cmdNVOn            uint32 = 11
	cmdNVOff           uint32 = 12
	cmdRemoteHandshake uint32 = 15
	cmdReset           uint32 = 17
	cmdRestart         uint32 = 18
	cmdSessionEnd      uint32 = 20
	cmdStop            uint32 = 21
	cmdTestFailureMode uint32 = 30
)
