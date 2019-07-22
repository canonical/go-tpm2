package tpm2

import (
	"bytes"
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
	attrDecrypt = 1<<iota + 2
	attrEncrypt
	attrAudit
)

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
		return fmt.Errorf("cannot write size of auth area to buffer: %v", err)
	}

	n, err := buf.Write(tmpBuf.Bytes())
	if err != nil {
		return fmt.Errorf("cannot write marshalled auth area to buffer: %v", err)
	}
	if n != tmpBuf.Len() {
		return errors.New("cannot write complete marshalled auth area to buffer")
	}
	return nil
}

func (a *commandAuthArea) Unmarshal(buf io.Reader) error {
	return errors.New("no need to unmarshal a command's auth area")
}

func attrsFromSession(session *Session) sessionAttrs {
	var attrs sessionAttrs
	if session.Attrs&AttrContinueSession > 0 {
		attrs |= attrContinueSession
	}
	return attrs
}

func buildCommandSessionAuth(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	session *Session, handle ResourceContext) (*authCommand, error) {
	if err := tpm.checkResourceContextParam(session.Handle, "session"); err != nil {
		return nil, err
	}
	context, isSessionContext := session.Handle.(*sessionContext)
	if !isSessionContext {
		return nil, errors.New("invalid resource context for session: not a session handle")
	}

	useAuthValue := !context.isBoundTo(handle)

	attrs := attrsFromSession(session)
	var hmac []byte

	if len(context.sessionKey) > 0 || (len(session.AuthValue) > 0 && useAuthValue) {
		if err := cryptComputeNonce(context.nonceCaller); err != nil {
			return nil, fmt.Errorf("cannot compute new nonceCaller: %v", err)
		}

		var authValue []byte
		if useAuthValue {
			authValue = session.AuthValue
		}

		cpHash := cryptComputeCpHash(context.hashAlg, commandCode, commandHandles, cpBytes)
		hmac = cryptComputeSessionCommandHMAC(context, authValue, cpHash, attrs)
	}

	return &authCommand{SessionHandle: session.Handle.Handle(),
		Nonce:        context.nonceCaller,
		SessionAttrs: attrs,
		HMAC:         hmac}, nil
}

func buildCommandPasswordAuth(authValue Auth) *authCommand {
	return &authCommand{SessionHandle: HandlePW, SessionAttrs: attrContinueSession, HMAC: authValue}
}

func buildCommandAuth(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	session interface{}, handle ResourceContext) (*authCommand, error) {
	switch s := session.(type) {
	case HandleWithAuth:
		rc := &permanentContext{handle: s.Handle}
		return buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, s.Auth, rc)
	case ResourceWithAuth:
		return buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, s.Auth, s.Handle)
	case string:
		return buildCommandPasswordAuth(Auth(s)), nil
	case []byte:
		return buildCommandPasswordAuth(Auth(s)), nil
	case Auth:
		return buildCommandPasswordAuth(s), nil
	case nil:
		return buildCommandPasswordAuth(nil), nil
	case *Session:
		return buildCommandSessionAuth(tpm, commandCode, commandHandles, cpBytes, s, handle)
	}
	return nil, fmt.Errorf("unexpected type %s for session / auth parameter", reflect.TypeOf(session))
}

func buildCommandAuthArea(tpm *tpmContext, commandCode CommandCode, commandHandles []Name, cpBytes []byte,
	sessions ...interface{}) (commandAuthArea, error) {
	var area commandAuthArea
	for _, session := range sessions {
		a, err := buildCommandAuth(tpm, commandCode, commandHandles, cpBytes, session, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot build auth area for command %s: %v", commandCode, err)
		}
		area = append(area, *a)
	}
	return area, nil
}

func processAuthSessionResponse(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode,
	rpBytes []byte, resp authResponse, session *Session, handle ResourceContext) error {
	context := session.Handle.(*sessionContext)
	context.nonceTPM = resp.Nonce

	if resp.SessionAttrs&attrContinueSession == 0 {
		tpm.evictResourceContext(context)
	}

	useAuthValue := !context.isBoundTo(handle)

	if len(context.sessionKey) == 0 && (len(session.AuthValue) == 0 || !useAuthValue) {
		return nil
	}

	var authValue []byte
	if useAuthValue {
		authValue = session.AuthValue
	}

	rpHash := cryptComputeRpHash(context.hashAlg, responseCode, commandCode, rpBytes)
	hmac := cryptComputeSessionResponseHMAC(context, authValue, rpHash, attrsFromSession(session))

	if !bytes.Equal(hmac, resp.HMAC) {
		return InvalidAuthResponseError{Command: commandCode, msg: "incorrect HMAC"}
	}

	return nil
}

func processAuthResponse(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode, rpBytes []byte,
	resp authResponse, session interface{}, handle ResourceContext) error {
	switch s := session.(type) {
	case HandleWithAuth:
		rc := &permanentContext{handle: s.Handle}
		return processAuthResponse(tpm, responseCode, commandCode, rpBytes, resp, s.Auth, rc)
	case ResourceWithAuth:
		return processAuthResponse(tpm, responseCode, commandCode, rpBytes, resp, s.Auth, s.Handle)
	case *Session:
		return processAuthSessionResponse(tpm, responseCode, commandCode, rpBytes, resp, s, handle)
	}
	return nil
}

func processAuthResponseArea(tpm *tpmContext, responseCode ResponseCode, commandCode CommandCode,
	rpBytes []byte, authResponses []authResponse, sessions ...interface{}) error {
	for i, resp := range authResponses {
		if err := processAuthResponse(tpm, responseCode, commandCode, rpBytes, resp,
			sessions[i], nil); err != nil {
			return err
		}
	}
	return nil
}
