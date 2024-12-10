package transportutil

type transportResult struct {
	n   int
	err error
}

type (
	transportResultChan     = chan transportResult
	transportResultSendChan = chan<- transportResult
	transportResultRecvChan = <-chan transportResult
)
