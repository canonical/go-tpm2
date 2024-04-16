// Copyright 2023 Canonical Ltd.
// Licensed under the LGPLv3 with static-linking exception.
// See LICENCE file for details.

package policyutil

import (
	"crypto"
	"errors"
	"io"

	"github.com/canonical/go-tpm2"
	"github.com/canonical/go-tpm2/cryptutil"
	"github.com/canonical/go-tpm2/mu"
)

// ComputePolicyAuthorizationTBSDigest computes the TBS digest for a policy authorization from the
// supplied message and policy reference. For a TPM2_PolicyAuthorize assertion, message is the
// approved policy digest.
//
// This will panic if the specified digest algorithm is not available.
func ComputePolicyAuthorizationTBSDigest(alg crypto.Hash, message []byte, policyRef tpm2.Nonce) []byte {
	h := alg.New()
	h.Write(message)
	h.Write(policyRef)
	return h.Sum(nil)
}

// PolicyAuthorization corresponds to a signed authorization.
type PolicyAuthorization struct {
	AuthKey   *tpm2.Public    // The public key of the signer, associated with the corresponding assertion.
	PolicyRef tpm2.Nonce      // The policy ref of the corresponding assertion
	Signature *tpm2.Signature // The actual signature
}

// SignPolicyAuthorization signs a new policy authorization using the supplied signer and
// options. Note that only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures can be created.
//
// The authKey argument is the corresponding public key. Both the authKey and policyRef arguments
// bind the authorization to a specific assertion in a policy.
//
// If the authorization is for use with TPM2_PolicyAuthorize then the supplied message is the
// approved policy digest. This can sign authorizations for TPM2_PolicySigned as well, but
// [SignPolicySignedAuthorization] is preferred for that because it constructs the message
// appropriately.
func SignPolicyAuthorization(rand io.Reader, message []byte, authKey *tpm2.Public, policyRef tpm2.Nonce, signer crypto.Signer, opts crypto.SignerOpts) (*PolicyAuthorization, error) {
	if !opts.HashFunc().Available() {
		return nil, errors.New("digest algorithm is not available")
	}
	digest := ComputePolicyAuthorizationTBSDigest(opts.HashFunc(), message, policyRef)
	sig, err := cryptutil.Sign(rand, signer, digest, opts)
	if err != nil {
		return nil, err
	}
	return &PolicyAuthorization{
		AuthKey:   authKey,
		PolicyRef: policyRef,
		Signature: sig,
	}, nil
}

// Verify verifies the signature of this authorization. If the authorization is for
// use with TPM2_PolicyAuthorize then the supplied message is the approved policy digest.
// This can verify authorizations for TPM2_PolicySigned as well, but
// [PolicySignedAuthorization.Verify] is preferred for that because it constructs the
// message appropriately.
func (a *PolicyAuthorization) Verify(message []byte) (ok bool, err error) {
	if a.AuthKey == nil || a.Signature == nil {
		return false, errors.New("invalid authorization")
	}
	if !a.Signature.SigAlg.IsValid() {
		return false, errors.New("invalid signature algorithm")
	}
	hashAlg := a.Signature.HashAlg().GetHash()
	if !hashAlg.Available() {
		return false, errors.New("digest algorithm is not available")
	}
	if !a.AuthKey.IsAsymmetric() {
		return false, errors.New("cannot verify HMAC signature")
	}
	digest := ComputePolicyAuthorizationTBSDigest(hashAlg, message, a.PolicyRef)
	return cryptutil.VerifySignature(a.AuthKey.Public(), digest, a.Signature)
}

// PolicySignedAuthorization represents a signed authorization for a TPM2_PolicySigned assertion.
type PolicySignedAuthorization struct {
	NonceTPM   tpm2.Nonce  // The TPM nonce of the session that this authorization is bound to
	CpHash     tpm2.Digest // The command parameters that this authorization is bound to
	Expiration int32       // The expiration time of this authorization
	PolicyAuthorization
}

// Verify verifies the signature of this signed authorization.
func (a *PolicySignedAuthorization) Verify() (ok bool, err error) {
	msg := mu.MustMarshalToBytes(mu.MakeRaw(a.NonceTPM), a.Expiration, mu.MakeRaw(a.CpHash))
	return a.PolicyAuthorization.Verify(msg)
}

type PolicySignedParams struct {
	NonceTPM   tpm2.Nonce  // The TPM nonce of the session that an authorization should be bound to
	CpHash     tpm2.Digest // The command parameters that an authorization should be bound to
	Expiration int32       // The expiration time of an authorization
}

// SignPolicySignedAuthorization creates a signed authorization that can be used by [Policy.Execute]
// for a TPM2_PolicySigned assertion or by using [tpm2.TPMContext.PolicySigned] directly. Note that
// only RSA-SSA, RSA-PSS, ECDSA and HMAC signatures can be created. The signer must be the owner of
// the corresponding authKey. The policyRef argument binds the authorization to a specific assertion
// in a policy.
//
// The authorizing party chooses the values of the supplied parameters in order to limit the scope of
// the authorization.
//
// If nonceTPM is supplied, the authorization will be bound to the session with the specified TPM
// nonce. If it is not supplied, the authorization is not bound to a specific session.
//
// If cpHashA is supplied, the authorization will be bound to the corresponding command parameters.
// If it is not supplied, the authorization is not bound to any specific command parameters.
//
// If expiration is not zero, then the absolute value of this specifies an expiration time in
// seconds, after which the authorization will expire. If nonceTPM is also provided, the expiration
// time is measured from the time that nonceTPM was generated. If nonceTPM is not provided, the
// expiration time is measured from the time that this authorization is used in the
// TPM2_PolicySigned assertion.
//
// The expiration field can be used to request a ticket from the TPM by specifying a negative
// value. The ticket can be used to satisfy the corresponding TPM2_PolicySigned assertion in future
// sessions, and its validity period and scope are restricted by the expiration and cpHashA
// arguments. If the authorization is not bound to a specific session, the ticket will expire on
// the next TPM reset if this occurs before the calculated expiration time
func SignPolicySignedAuthorization(rand io.Reader, params *PolicySignedParams, authKey *tpm2.Public, policyRef tpm2.Nonce, signer crypto.Signer, opts crypto.SignerOpts) (*PolicySignedAuthorization, error) {
	if params == nil {
		params = new(PolicySignedParams)
	}

	msg := mu.MustMarshalToBytes(mu.MakeRaw(params.NonceTPM), params.Expiration, mu.MakeRaw(params.CpHash))
	auth, err := SignPolicyAuthorization(rand, msg, authKey, policyRef, signer, opts)
	if err != nil {
		return nil, err
	}

	return &PolicySignedAuthorization{
		NonceTPM:            params.NonceTPM,
		CpHash:              params.CpHash,
		Expiration:          params.Expiration,
		PolicyAuthorization: *auth,
	}, nil
}
