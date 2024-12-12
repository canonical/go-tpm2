/*
Package transportutil provides helpers when implementing tpm2.Transport
*/
package transportutil

import "github.com/canonical/go-tpm2"

var (
	// ErrBusy should be returned from calls to Write if a previously
	// submitted command has not finished or not all of its bytes have
	// been read back yet.
	ErrBusy = tpm2.ErrTransportBusy

	// ErrClosed indicates that a transport is closed.
	ErrClosed = tpm2.ErrTransportClosed
)

type transportResult struct {
	n   int
	err error
}

type (
	transportResultChan     = chan transportResult
	transportResultSendChan = chan<- transportResult
	transportResultRecvChan = <-chan transportResult
)
