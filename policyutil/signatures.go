// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"crypto"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/mu"
)

// SignPolicyAuthorization creates a signed authorization using the supplied signer and options.
// Note that only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures can be created. The returned
// signed authorization can be used in a TPM2_PolicySigned assertion using the
// [tpm2.TPMContext.PolicySigned] function or by executing a [Policy] that contains this assertion.
//
// The authorizing party can apply contraints on how the session that includes this authorization
// can be used.
//
// If nonceTPM is supplied, then the signed authorization can only be used for the session
// associated with the supplied nonce.
//
// If expiration is non-zero, then the absolute value of this limits the number of seconds that the
// signed authorization is valid for once verified with the TPM2_PolicySigned assertion. If nonceTPM
// is supplied, then the validity period starts from when nonceTPM was generated. If nonceTPM is not
// supplied, then the validity period starts from when the assertion is executed.
//
// If expiration is negative, the TPM will return a ticket that can be used to satisfy the policy in
// subsequent sessions until it expires or until the next TPM reset if nonceTPM is not supplied.
//
// If cpHash is supplied, then the signed authorization is only valid for use in a command with the
// associated command code and set of command parameters. The command parameter digest can be
// computed using [ComputeCpHash].
//
// This will panic if the requested digest algorithm is not available.
func SignPolicyAuthorization(rand io.Reader, signer crypto.Signer, nonceTPM tpm2.Nonce, cpHashA tpm2.Digest, policyRef tpm2.Nonce, expiration int32, opts crypto.SignerOpts) (*tpm2.Signature, error) {
	h := opts.HashFunc().New()
	mu.MustMarshalToWriter(h, mu.Raw(nonceTPM), expiration, mu.Raw(cpHashA), mu.Raw(policyRef))
	return cryptutil.Sign(rand, signer, h.Sum(nil), opts)
}
