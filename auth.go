package tpm2

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

type sessionAttributes uint8

const (
	attrContinueSession sessionAttributes = 1 << iota
	attrAuditExclusive
	attrAuditReset
	_
	_
	attrDecrypt
	attrEncrypt
	attrAudit
)

type authCommand struct {
	SessionHandle Handle
	Nonce         Nonce
	SessionAttrs  sessionAttributes
	HMAC          Auth
}

type authResponse struct {
	Nonce        Nonce
	SessionAttrs sessionAttributes
	HMAC         Auth
}

type commandAuthArea []authCommand

func (a *commandAuthArea) Marshal(buf io.Writer) error {
	tmpBuf := new(bytes.Buffer)
	if err := MarshalToWriter(tmpBuf, RawSlice([]authCommand(*a))); err != nil {
		return nil
	}

	if err := binary.Write(buf, binary.BigEndian, uint32(tmpBuf.Len())); err != nil {
		return fmt.Errorf("failed to write size of auth area to buffer: %v", err)
	}

	n, err := buf.Write(tmpBuf.Bytes())
	if err != nil {
		return fmt.Errorf("failed to write marshalled auth area to buffer: %v", err)
	}
	if n != tmpBuf.Len() {
		return errors.New("failed to write complete marshalled auth area to buffer")
	}
	return nil
}

func (a *commandAuthArea) Unmarshal(buf io.Reader) error {
	return errors.New("no need to unmarshal a command's auth area")
}

func buildCommandPasswordAuth(password []byte) authCommand {
	return authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: password}
}

func buildCommandAuth(auth interface{}) (authCommand, error) {
	switch a := auth.(type) {
	case string:
		return buildCommandPasswordAuth([]byte(a)), nil
	case []byte:
		return buildCommandPasswordAuth(a), nil
	}
	return authCommand{}, InvalidAuthParamError{fmt.Sprintf("unexpected type (%s)", reflect.TypeOf(auth))}
}

func buildCommandAuthArea(auths ...interface{}) (commandAuthArea, error) {
	var area commandAuthArea
	for _, auth := range auths {
		a, err := buildCommandAuth(auth)
		if err != nil {
			return nil, err
		}
		area = append(area, a)
	}
	return area, nil
}

func processAuthResponse(auths []authResponse) error {
	return nil
}
