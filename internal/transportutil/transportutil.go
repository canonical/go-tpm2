package transportutil

import "errors"

var ErrClosed = errors.New("transport already closed")

type transportResult struct {
	n   int
	err error
}

type (
	transportResultChan     = chan transportResult
	transportResultSendChan = chan<- transportResult
	transportResultRecvChan = <-chan transportResult
)
