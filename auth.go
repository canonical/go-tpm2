package tpm2

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
)

type sessionAttrs uint8

const (
	attrContinueSession sessionAttrs = 1 << iota
	attrAuditExclusive
	attrAuditReset
	attrDecrypt = 1 << iota + 2
	attrEncrypt
	attrAudit
)

type SessionAttributes int

const (
	AttrContinueSession SessionAttributes = 1 << iota
)

type Session struct {
	Handle ResourceContext
	AuthValue []byte
	Attributes SessionAttributes
}

type authCommand struct {
	SessionHandle Handle
	Nonce         Nonce
	SessionAttrs  sessionAttrs
	HMAC          Auth
}

type authResponse struct {
	Nonce        Nonce
	SessionAttrs sessionAttrs
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

func attrsFromSession(session *Session) sessionAttrs {
	var attrs sessionAttrs
	if session.Attributes&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	return attrs
}

func buildCommandSessionAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	session *Session) (authCommand, error) {
	context, isSessionContext := session.Handle.(*sessionContext)
	if !isSessionContext {
		return authCommand{}, InvalidAuthParamError{"handle is not a session handle"}
	}

	attrs := attrsFromSession(session)
	var hmac []byte

	if len(context.sessionKey) > 0 || len(session.AuthValue) > 0 {
		if _, err := rand.Read(context.nonceCaller); err != nil {
			return authCommand{}, fmt.Errorf("cannot read random bytes for nonceCaller: %v", err)
		}
		cpHash := cryptComputeCpHash(context.hashAlg, commandCode, commandHandles, cpBytes)
		hmac = cryptComputeSessionCommandHMAC(context, session.AuthValue, cpHash, attrs)
	}

	return authCommand{SessionHandle: session.Handle.Handle(),
		Nonce: context.nonceCaller,
		SessionAttrs: attrs,
		HMAC: hmac}, nil
}

func buildCommandPasswordAuth(authValue Auth) authCommand {
	return authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: authValue}
}

func buildCommandAuth(commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	auth interface{}) (authCommand, error) {
	switch a := auth.(type) {
	case string:
		return buildCommandPasswordAuth(Auth(a)), nil
	case []byte:
		return buildCommandPasswordAuth(Auth(a)), nil
	case Auth:
		return buildCommandPasswordAuth(a), nil
	case nil:
		return buildCommandPasswordAuth(nil), nil
	case *Session:
		return buildCommandSessionAuth(commandCode, commandHandles, cpBytes, a)
	}
	return authCommand{}, InvalidAuthParamError{fmt.Sprintf("unexpected type (%s)", reflect.TypeOf(auth))}
}

func buildCommandAuthArea(commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	auths ...interface{}) (commandAuthArea, error) {
	var area commandAuthArea
	for _, auth := range auths {
		a, err := buildCommandAuth(commandCode, commandHandles, cpBytes, auth)
		if err != nil {
			return nil, err
		}
		area = append(area, a)
	}
	return area, nil
}

func processAuthSessionResponse(responseCode ResponseCode, commandCode CommandCode, rpBytes []byte,
	resp authResponse, session *Session) error {
	context := session.Handle.(*sessionContext)
	context.nonceTPM = resp.Nonce
	if len(context.sessionKey) == 0 && len(session.AuthValue) == 0 {
		return nil
	}

	rpHash := cryptComputeRpHash(context.hashAlg, responseCode, commandCode, rpBytes)
	hmac := cryptComputeSessionResponseHMAC(context, session.AuthValue, rpHash, attrsFromSession(session))

	if !bytes.Equal(hmac, resp.HMAC) {
		return InvalidAuthResponseError{"incorrect HMAC"}
	}

	return nil
}

func processAuthResponse(responseCode ResponseCode, commandCode CommandCode, rpBytes []byte,
	resp authResponse, auth interface{}) error {
	switch a := auth.(type) {
	case *Session:
		return processAuthSessionResponse(responseCode, commandCode, rpBytes, resp, a)
	}
	return nil
}

func processAuthResponseArea(responseCode ResponseCode, commandCode CommandCode, rpBytes []byte,
	authResponses []authResponse, auths ...interface{}) error {
	for i, resp := range authResponses {
		if err := processAuthResponse(responseCode, commandCode, rpBytes, resp, auths[i]); err != nil {
			return err
		}
	}
	return nil
}
