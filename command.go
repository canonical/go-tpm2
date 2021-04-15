// Copyright 2021 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/canonical/go-tpm2/mu"

	"golang.org/x/xerrors"
)

const (
	maxResponseSize int = 4096
)

// CommandHeader is the header for a TPM command.
type CommandHeader struct {
	Tag         StructTag
	CommandSize uint32
	CommandCode CommandCode
}

// CommandPacket corresponds to a complete command packet including header and payload.
type CommandPacket []byte

// GetCommandCode returns the command code contained within this packet.
func (p CommandPacket) GetCommandCode() (CommandCode, error) {
	var header CommandHeader
	if _, err := mu.UnmarshalFromBytes(p, &header); err != nil {
		return 0, xerrors.Errorf("cannot unmarshal header: %w", err)
	}
	return header.CommandCode, nil
}

// UnmarshalPayload unmarshals this command packet, returning the handles, auth area and
// parameters. The parameters will still be in the TPM wire format. The number of command
// handles associated with the command must be supplied by the caller.
func (p CommandPacket) UnmarshalPayload(numHandles int) (handles HandleList, authArea []AuthCommand, parameters []byte, err error) {
	buf := bytes.NewReader(p)

	var header CommandHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	if header.CommandSize != uint32(len(p)) {
		return nil, nil, nil, fmt.Errorf("invalid commandSize value (got %d, packet length %d)", header.CommandSize, len(p))
	}

	for i := 0; i < numHandles; i++ {
		var handle Handle
		if _, err := mu.UnmarshalFromReader(buf, &handle); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot unmarshal handles: %w", err)
		}
		handles = append(handles, handle)
	}

	switch header.Tag {
	case TagSessions:
		var authSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &authSize); err != nil {
			return nil, nil, nil, xerrors.Errorf("cannot unmarshal auth area size: %w", err)
		}
		r := &io.LimitedReader{R: buf, N: int64(authSize)}
		for r.N > 0 {
			if len(authArea) >= 3 {
				return nil, nil, nil, fmt.Errorf("%d trailing byte(s) in auth area", r.N)
			}

			var auth AuthCommand
			if _, err := mu.UnmarshalFromReader(r, &auth); err != nil {
				return nil, nil, nil, xerrors.Errorf("cannot unmarshal auth: %w", err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
	default:
		return nil, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	parameters, err = ioutil.ReadAll(buf)
	if err != nil {
		return nil, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
	}

	return handles, authArea, parameters, nil
}

// MarshalCommandPacket serializes a complete TPM packet from the provided arguments. The
// parameters argument must already be serialized to the TPM wire format.
func MarshalCommandPacket(command CommandCode, handles HandleList, authArea []AuthCommand, parameters []byte) CommandPacket {
	header := CommandHeader{CommandCode: command}
	var payload []byte

	hBytes := new(bytes.Buffer)
	for _, h := range handles {
		if _, err := mu.MarshalToWriter(hBytes, h); err != nil {
			panic(fmt.Sprintf("cannot marshal command handle: %v", err))
		}
	}

	switch {
	case len(authArea) > 0:
		header.Tag = TagSessions

		aBytes := new(bytes.Buffer)
		for _, auth := range authArea {
			if _, err := mu.MarshalToWriter(aBytes, auth); err != nil {
				panic(fmt.Sprintf("cannot marshal command auth area: %v", err))
			}
		}

		var err error
		payload, err = mu.MarshalToBytes(mu.RawBytes(hBytes.Bytes()), uint32(aBytes.Len()), mu.RawBytes(aBytes.Bytes()), mu.RawBytes(parameters))
		if err != nil {
			panic(fmt.Sprintf("cannot marshal command payload: %v", err))
		}
	case len(authArea) == 0:
		header.Tag = TagNoSessions

		var err error
		payload, err = mu.MarshalToBytes(mu.RawBytes(hBytes.Bytes()), mu.RawBytes(parameters))
		if err != nil {
			panic(fmt.Sprintf("cannot marshal command payload: %v", err))
		}

	}

	header.CommandSize = uint32(binary.Size(header) + len(payload))

	cmd, err := mu.MarshalToBytes(header, mu.RawBytes(payload))
	if err != nil {
		panic(fmt.Sprintf("cannot marshal complete command packet: %v", err))
	}
	return cmd
}

// ResponseHeader is the header for the TPM's response to a command.
type ResponseHeader struct {
	Tag          StructTag
	ResponseSize uint32
	ResponseCode ResponseCode
}

// ResponsePacket corresponds to a complete response packet including header and payload.
type ResponsePacket []byte

// Unmarshal deserializes the response packet and returns the response code, handle, parameters
// and auth area. The parameters will still be in the TPM wire format. The caller supplies a
// pointer to which the response handle will be written. The pointer must be supplied if the
// command returns a handle, and must be nil if the command does not return a handle, else
// the response will be incorrectly unmarshalled.
func (p ResponsePacket) Unmarshal(handle *Handle) (rc ResponseCode, parameters []byte, authArea []AuthResponse, err error) {
	if len(p) > maxResponseSize {
		return 0, nil, nil, fmt.Errorf("packet too large (%d bytes)", len(p))
	}

	buf := bytes.NewReader(p)

	var header ResponseHeader
	if _, err := mu.UnmarshalFromReader(buf, &header); err != nil {
		return 0, nil, nil, xerrors.Errorf("cannot unmarshal header: %w", err)
	}

	if header.ResponseSize != uint32(len(p)) {
		return 0, nil, nil, fmt.Errorf("invalid responseSize value (got %d, packet length %d)", header.ResponseSize, len(p))
	}

	if header.ResponseCode != Success {
		if buf.Len() != 0 {
			return header.ResponseCode, nil, nil, fmt.Errorf("%d trailing byte(s)", buf.Len())
		}
		return header.ResponseCode, nil, nil, nil
	}

	if handle != nil {
		if _, err := mu.UnmarshalFromReader(buf, handle); err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot unmarshal handle: %w", err)
		}
	}

	switch header.Tag {
	case TagSessions:
		var parameterSize uint32
		if _, err := mu.UnmarshalFromReader(buf, &parameterSize); err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot unmarshal parameterSize: %w", err)
		}

		parameters = make([]byte, parameterSize)
		if _, err := io.ReadFull(buf, parameters); err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
		}

		for buf.Len() > 0 {
			if len(authArea) >= 3 {
				return 0, nil, nil, fmt.Errorf("%d trailing byte(s)", buf.Len())
			}

			var auth AuthResponse
			if _, err := mu.UnmarshalFromReader(buf, &auth); err != nil {
				return 0, nil, nil, xerrors.Errorf("cannot unmarshal auth: %w", err)
			}

			authArea = append(authArea, auth)
		}
	case TagNoSessions:
		parameters, err = ioutil.ReadAll(buf)
		if err != nil {
			return 0, nil, nil, xerrors.Errorf("cannot read parameters: %w", err)
		}
	default:
		return 0, nil, nil, fmt.Errorf("invalid tag: %v", header.Tag)
	}

	return Success, parameters, authArea, nil
}
