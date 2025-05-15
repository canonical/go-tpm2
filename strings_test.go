// Copyright 2025 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package tpm2_test

import (
	"io"

	. "gopkg.in/check.v1"

	. "github.com/canonical/go-tpm2"
)

type mockFmtFlags int

const (
	fmtPlus mockFmtFlags = 1 << iota
	fmtMinus
	fmtHash
	fmtSpace
	fmtZero
	widthSet
	precisionSet
)

type mockState struct {
	flags     mockFmtFlags
	width     int
	precision int
}

func (*mockState) Write(b []byte) (int, error) {
	return 0, io.ErrShortWrite
}

func (s *mockState) Width() (wid int, set bool) {
	if s.flags&widthSet == 0 {
		return 0, false
	}
	return s.width, true
}

func (s *mockState) Precision() (prec int, set bool) {
	if s.flags&precisionSet == 0 {
		return 0, false
	}
	return s.precision, true
}

func (s *mockState) Flag(c int) bool {
	switch c {
	case '+':
		return s.flags&fmtPlus != 0
	case '-':
		return s.flags&fmtMinus != 0
	case '#':
		return s.flags&fmtHash != 0
	case ' ':
		return s.flags&fmtSpace != 0
	case '0':
		return s.flags&fmtZero != 0
	default:
		return false
	}
}

type stringsSuite struct{}

var _ = Suite(&stringsSuite{})

func (*stringsSuite) TestFormatStringS(c *C) {
	c.Check(FormatString(new(mockState), 's'), Equals, "%s")
}

func (*stringsSuite) TestFormatStringV(c *C) {
	c.Check(FormatString(new(mockState), 'v'), Equals, "%v")
}

func (*stringsSuite) TestFormatStringHashX(c *C) {
	c.Check(FormatString(&mockState{flags: fmtHash}, 'x'), Equals, "%#x")
}

func (*stringsSuite) TestFormatStringHashZeroPaddedX(c *C) {
	c.Check(FormatString(&mockState{flags: fmtHash | fmtZero | widthSet, width: 4}, 'x'), Equals, "%#04x")
}

func (*stringsSuite) TestFormatStringDWithWidthAndPrecision(c *C) {
	c.Check(FormatString(&mockState{flags: widthSet | precisionSet, width: 2, precision: 4}, 'd'), Equals, "%2.4d")
}
