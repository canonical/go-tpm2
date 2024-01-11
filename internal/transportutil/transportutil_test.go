package transportutil_test

import (
	"testing"

	"github.com/canonical/go-tpm2/testutil"
	. "gopkg.in/check.v1"
)

func init() {
	testutil.AddCommandLineFlags()
}

func Test(t *testing.T) { TestingT(t) }
