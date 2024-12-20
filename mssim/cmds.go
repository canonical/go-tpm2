// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.
package mssim

const (
	cmdPowerOn         uint32 = 1
	cmdPowerOff        uint32 = 2
	cmdHashStart       uint32 = 5
	cmdHashData        uint32 = 6
	cmdHashEnd         uint32 = 7
	cmdTPMSendCommand  uint32 = 8
	cmdNVOn            uint32 = 11
	cmdRemoteHandshake uint32 = 15
	cmdReset           uint32 = 17
	cmdSessionEnd      uint32 = 20
	cmdStop            uint32 = 21
)
