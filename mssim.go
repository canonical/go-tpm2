// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

const (
	cmdPowerOn        uint32 = 1
	cmdTPMSendCommand uint32 = 8
	cmdNVOn           uint32 = 11
	cmdReset          uint32 = 17
	cmdSessionEnd     uint32 = 20
)

// TctiMssim represents a connection to a TPM simulator that implements the Microsoft TPM2 simulator interface.
type TctiMssim struct {
	Locality uint8 // Locality of commands submitted to the simulator on this interface

	tpm      net.Conn
	platform net.Conn

	buf *bytes.Reader
}

func (t *TctiMssim) readMoreData() error {
	var size uint32
	if err := binary.Read(t.tpm, binary.BigEndian, &size); err != nil {
		return fmt.Errorf("cannot read response size: %v", err)
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(t.tpm, buf); err != nil {
		return fmt.Errorf("cannot read response: %v", err)
	}

	t.buf = bytes.NewReader(buf)

	var trash uint32
	if err := binary.Read(t.tpm, binary.BigEndian, &trash); err != nil {
		return fmt.Errorf("cannot read zero bytes after response: %v", err)
	}
	return nil
}

func (t *TctiMssim) Read(data []byte) (int, error) {
	if t.buf == nil || t.buf.Len() == 0 {
		if err := t.readMoreData(); err != nil {
			return 0, err
		}
	}
	return t.buf.Read(data)
}

func (t *TctiMssim) Write(data []byte) (int, error) {
	buf, err := MarshalToBytes(cmdTPMSendCommand, t.Locality, uint32(len(data)), RawBytes(data))
	if err != nil {
		return 0, fmt.Errorf("cannot marshal command: %v", err)
	}

	return t.tpm.Write(buf)
}

func (t *TctiMssim) Close() (out error) {
	if err := binary.Write(t.platform, binary.BigEndian, cmdSessionEnd); err != nil {
		out = err
	}
	if err := binary.Write(t.tpm, binary.BigEndian, cmdSessionEnd); err != nil {
		out = err
	}
	t.platform.Close()
	t.tpm.Close()
	return
}

func (t *TctiMssim) platformCommand(cmd uint32) error {
	if err := binary.Write(t.platform, binary.BigEndian, cmd); err != nil {
		return fmt.Errorf("cannot marshal platform command: %v", err)
	}

	var resp uint32
	if err := binary.Read(t.platform, binary.BigEndian, &resp); err != nil {
		return fmt.Errorf("cannot read response to platform command: %v", err)
	}
	if resp != 0 {
		return fmt.Errorf("received error code %d in response to platform command %d", resp, cmd)
	}

	return nil
}

// Reset submits the reset command on the platform connection, which initiates a reset of the TPM simulator and results in the
// execution of _TPM_Init().
func (t *TctiMssim) Reset() error {
	return t.platformCommand(cmdReset)
}

// OpenMssim attempts to open a connection to a TPM simulator on the specified host. tpmPort is the port on which the TPM command
// server is listening. platformPort is the port on which the platform server is listening. If host is an empty string, it defaults
// to "localhost".
//
// If successful, it returns a new TctiMssim instance which can be passed to NewTPMContext.
func OpenMssim(host string, tpmPort, platformPort uint) (*TctiMssim, error) {
	if host == "" {
		host = "localhost"
	}

	tpmAddress := fmt.Sprintf("%s:%d", host, tpmPort)
	platformAddress := fmt.Sprintf("%s:%d", host, platformPort)

	tcti := new(TctiMssim)
	tcti.Locality = 3

	tpm, err := net.Dial("tcp", tpmAddress)
	if err != nil {
		return nil, fmt.Errorf("cannot connect to TPM socket: %v", err)
	}
	tcti.tpm = tpm

	platform, err := net.Dial("tcp", platformAddress)
	if err != nil {
		tcti.tpm.Close()
		return nil, fmt.Errorf("cannot connect to platform socket: %v", err)
	}
	tcti.platform = platform

	if err := tcti.platformCommand(cmdPowerOn); err != nil {
		return nil, fmt.Errorf("cannot complete power on command: %v", err)
	}
	if err := tcti.platformCommand(cmdNVOn); err != nil {
		return nil, fmt.Errorf("cannot complete NV on command: %v", err)
	}

	return tcti, nil
}
