package transportutil_test

import (
	"bytes"
	"io"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	. "github.com/canonical/go-tpm2/internal/transportutil"
	"github.com/canonical/go-tpm2/mu"
	. "gopkg.in/check.v1"
)

type bufferSuite struct{}

var _ = Suite(&bufferSuite{})

type countingWriter struct {
	buf *bytes.Buffer
	n   int
}

func (w *countingWriter) Write(data []byte) (int, error) {
	w.n += 1
	return w.buf.Write(data)
}

func (s *bufferSuite) TestBufferCommands(c *C) {
	hdr := tpm2.CommandHeader{
		Tag:         tpm2.TagNoSessions,
		CommandSize: 12,
		CommandCode: tpm2.CommandStartup,
	}
	w := &countingWriter{buf: new(bytes.Buffer)}
	_, err := mu.MarshalToWriter(BufferCommands(w, 4096), hdr, mu.Raw(internal_testutil.DecodeHexString(c, "0000")))
	c.Check(err, IsNil)
	c.Check(w.n, Equals, 1)
	c.Check(w.buf.Bytes(), DeepEquals, internal_testutil.DecodeHexString(c, "80010000000c000001440000"))
}

func (s *bufferSuite) TestBufferCommandsShortWrite(c *C) {
	hdr := tpm2.CommandHeader{
		Tag:         tpm2.TagNoSessions,
		CommandSize: 12,
		CommandCode: tpm2.CommandStartup,
	}
	w := &countingWriter{buf: new(bytes.Buffer)}
	_, err := mu.MarshalToWriter(BufferCommands(w, 4096), hdr, mu.Raw(internal_testutil.DecodeHexString(c, "00000000")))
	c.Check(err, internal_testutil.ErrorIs, io.ErrShortWrite)
	c.Check(w.n, Equals, 1)
	c.Check(w.buf.Bytes(), DeepEquals, internal_testutil.DecodeHexString(c, "80010000000c000001440000"))
}

func (s *bufferSuite) TestBufferCommandsTooLarge(c *C) {
	w := &countingWriter{buf: new(bytes.Buffer)}
	_, err := BufferCommands(w, 4096).Write(internal_testutil.DecodeHexString(c, "800100001388000001440000"))
	c.Check(err, ErrorMatches, `invalid command size \(5000 bytes\)`)
	c.Check(w.n, Equals, 0)
}

type countingReader struct {
	buf          io.Reader
	n            int
	lastReadSize int
}

func (r *countingReader) Read(data []byte) (int, error) {
	r.n += 1
	r.lastReadSize = len(data)

	return r.buf.Read(data)
}

func (s *bufferSuite) TestBufferResponses(c *C) {
	r := &countingReader{buf: bytes.NewReader(internal_testutil.DecodeHexString(c, "80010000000a00000000"))}

	var hdr tpm2.ResponseHeader
	_, err := mu.UnmarshalFromReader(BufferResponses(r, 4096), &hdr)
	c.Check(err, IsNil)
	c.Check(r.n, Equals, 1)
	c.Check(r.lastReadSize, Equals, 4096)
	c.Check(hdr, DeepEquals, tpm2.ResponseHeader{
		Tag:          tpm2.TagNoSessions,
		ResponseSize: 10,
		ResponseCode: tpm2.ResponseSuccess,
	})
}

func (s *bufferSuite) TestBufferResponsesEOF(c *C) {
	r := &countingReader{buf: bytes.NewReader(internal_testutil.DecodeHexString(c, "80010000000a00000000"))}

	data, err := io.ReadAll(BufferResponses(r, 4096))
	c.Check(err, IsNil)
	c.Check(data, DeepEquals, internal_testutil.DecodeHexString(c, "80010000000a00000000"))
}
