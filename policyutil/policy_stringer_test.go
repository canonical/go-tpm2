// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	. "gopkg.in/check.v1"

	"github.com/canonical/go-tpm2"
	internal_testutil "github.com/canonical/go-tpm2/internal/testutil"
	"github.com/canonical/go-tpm2/objectutil"
	. "github.com/canonical/go-tpm2/policyutil"
)

type policyStringerSuite struct{}

var _ = Suite(&policyStringerSuite{})

func (s *policyStringerSuite) TestPolicyStringerWithAuthorized(c *C) {
	keyPEM := `
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghoJh0RNpHMdQGWw1
c4iu0s8/VoGE1Xx5ds7Zvpne/BOhRANCAAS9VCRI2K86GPrzKRZ92uhtpM8o+m/5
Q24QvsY89QC+L3a2SRfoRs+9jlcc13V7qOxbu2vnI0+Ql7VP4ePUfEQ0
-----END PRIVATE KEY-----`

	b, _ := pem.Decode([]byte(keyPEM))
	key, err := x509.ParsePKCS8PrivateKey(b.Bytes)
	c.Assert(err, IsNil)
	c.Assert(key, internal_testutil.ConvertibleTo, &ecdsa.PrivateKey{})

	pub, err := objectutil.NewECCPublicKey(&key.(*ecdsa.PrivateKey).PublicKey)
	c.Assert(err, IsNil)

	builder := NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthorize([]byte("foo"), pub)

	digest, policy, err := builder.Policy()
	c.Assert(err, IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicyAuthValue()
	digest1, authPolicy1, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy1.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	builder = NewPolicyBuilder(tpm2.HashAlgorithmSHA256)
	builder.RootBranch().PolicySecret(tpm2.MakeHandleName(tpm2.HandleOwner), []byte("bar"))
	digest2, authPolicy2, err := builder.Policy()
	c.Assert(err, IsNil)
	c.Check(authPolicy2.Authorize(rand.Reader, pub, []byte("foo"), key.(crypto.Signer), tpm2.HashAlgorithmSHA256), IsNil)

	stringer := policy.Stringer(tpm2.HashAlgorithmNull, NewAuthorizedPolicies([]*Policy{authPolicy1, authPolicy2}, nil))
	c.Check(stringer.String(), Equals, fmt.Sprintf(`
Policy {
 # digest TPM_ALG_SHA256:%#[1]x
 AuthorizedPolicies {
   AuthorizedPolicy %[2]x {
    # digest TPM_ALG_SHA256:%#[2]x
    PolicyAuthValue()
   }
   AuthorizedPolicy %[3]x {
    # digest TPM_ALG_SHA256:%#[3]x
    PolicySecret(authObject:0x40000001, policyRef:0x626172)
   }
 }
 PolicyAuthorize(policyRef:0x666f6f, keySign:%#[4]x)
}`, digest, digest1, digest2, pub.Name()))
}
