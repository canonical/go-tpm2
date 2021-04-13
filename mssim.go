// Copyright 2019 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

const (
	cmdPowerOn        uint32 = 1
	cmdTPMSendCommand uint32 = 8
	cmdNVOn           uint32 = 11
	cmdReset          uint32 = 17
	cmdSessionEnd     uint32 = 20
	cmdStop           uint32 = 21
)

// PlatformCommandError corresponds to an error code in response to a platform command executed on a TPM simulator.
type PlatformCommandError struct {
	commandCode uint32
	Code        uint32
}

func (e PlatformCommandError) Error() string {
	return fmt.Sprintf("received error code %d in response to platform command %d", e.Code, e.commandCode)
}

// TctiMssim represents a connection to a TPM simulator that implements the Microsoft TPM2 simulator interface.
type TctiMssim struct {
	locality uint8 // Locality of commands submitted to the simulator on this interface

	tpm      net.Conn
	platform net.Conn

	buf *bytes.Reader
}

func (t *TctiMssim) readMoreData() error {
	var size uint32
	if err := binary.Read(t.tpm, binary.BigEndian, &size); err != nil {
		return xerrors.Errorf("cannot read response size from TPM command channel: %w", err)
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(t.tpm, buf); err != nil {
		return xerrors.Errorf("cannot read response from TPM command channel: %w", err)
	}

	t.buf = bytes.NewReader(buf)

	var trash uint32
	if err := binary.Read(t.tpm, binary.BigEndian, &trash); err != nil {
		return xerrors.Errorf("cannot read zero bytes from TPM command channel after response: %w", err)
	}
	return nil
}

func (t *TctiMssim) Read(data []byte) (int, error) {
	if t.buf == nil {
		if err := t.readMoreData(); err != nil {
			return 0, err
		}
	}

	n, err := t.buf.Read(data)
	if err == io.EOF {
		t.buf = nil
	}
	return n, err
}

func (t *TctiMssim) Write(data []byte) (int, error) {
	buf, err := mu.MarshalToBytes(cmdTPMSendCommand, t.locality, uint32(len(data)), mu.RawBytes(data))
	if err != nil {
		panic(fmt.Sprintf("cannot marshal command: %v", err))
	}
	n, err := t.tpm.Write(buf)
	if err != nil {
		return 0, err
	}
	n -= (len(buf) - len(data))
	if n < 0 {
		n = 0
	}
	if n < len(data) {
		return n, io.ErrShortWrite
	}
	return n, nil
}

func sendSessionEnd(conn net.Conn) error {
	return binary.Write(conn, binary.BigEndian, cmdSessionEnd)
}

func (t *TctiMssim) Close() (out error) {
	if err := sendSessionEnd(t.platform); err != nil {
		out = xerrors.Errorf("cannot send session end command on platform channel: %w", err)
	}
	if err := sendSessionEnd(t.tpm); err != nil {
		out = xerrors.Errorf("cannot send session end command on TPM command channel: %w", err)
	}
	if err := t.platform.Close(); err != nil {
		out = xerrors.Errorf("cannot close platform channel: %w", err)
	}
	if err := t.tpm.Close(); err != nil {
		out = xerrors.Errorf("cannot close TPM command channel: %w", err)
	}
	return
}

func (t *TctiMssim) SetLocality(locality uint8) error {
	t.locality = locality
	return nil
}

func (t *TctiMssim) MakeSticky(handle Handle, sticky bool) error {
	return errors.New("not implemented")
}

func (t *TctiMssim) platformCommand(cmd uint32) error {
	if err := binary.Write(t.platform, binary.BigEndian, cmd); err != nil {
		return xerrors.Errorf("cannot send command: %w", err)
	}

	var resp uint32
	if err := binary.Read(t.platform, binary.BigEndian, &resp); err != nil {
		return xerrors.Errorf("cannot read response to command: %w", err)
	}
	if resp != 0 {
		return &PlatformCommandError{cmd, resp}
	}

	return nil
}

// Reset submits the reset command on the platform connection, which initiates a reset of the TPM simulator and results in the
// execution of _TPM_Init().
func (t *TctiMssim) Reset() error {
	return t.platformCommand(cmdReset)
}

func sendStop(conn net.Conn) error {
	return binary.Write(conn, binary.BigEndian, cmdStop)
}

// Stop submits a stop command on both the TPM command and platform channels, which initiates a shutdown of the TPM simulator.
func (t *TctiMssim) Stop() (out error) {
	if err := sendStop(t.platform); err != nil {
		out = xerrors.Errorf("cannot send stop command on platform channel: %w", err)
	}
	if err := sendStop(t.tpm); err != nil {
		out = xerrors.Errorf("cannot send stop command on TPM command channel: %w", err)
	}
	return nil
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
	tcti.locality = 3

	tpm, err := net.Dial("tcp", tpmAddress)
	if err != nil {
		return nil, xerrors.Errorf("cannot connect to TPM socket: %w", err)
	}
	tcti.tpm = tpm

	platform, err := net.Dial("tcp", platformAddress)
	if err != nil {
		tcti.tpm.Close()
		return nil, xerrors.Errorf("cannot connect to platform socket: %w", err)
	}
	tcti.platform = platform

	if err := tcti.platformCommand(cmdPowerOn); err != nil {
		return nil, xerrors.Errorf("cannot complete power on command: %w", err)
	}
	if err := tcti.platformCommand(cmdNVOn); err != nil {
		return nil, xerrors.Errorf("cannot complete NV on command: %w", err)
	}

	return tcti, nil
}
