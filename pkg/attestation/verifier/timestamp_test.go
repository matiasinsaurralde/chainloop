//
// Copyright 2026 The Chainloop Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package verifier

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	dttimestamp "github.com/digitorus/timestamp"
	protobundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	protocommon "github.com/sigstore/protobuf-specs/gen/pb-go/common/v1"
	sigstoredsse "github.com/sigstore/protobuf-specs/gen/pb-go/dsse"
	sigstorebundlepkg "github.com/sigstore/sigstore-go/pkg/bundle"
	tsasigner "github.com/sigstore/timestamp-authority/v2/pkg/signer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyTimestamps(t *testing.T) {
	certChain, tsaKey := newTSACertChain(t)
	tsaRoots := &TrustedRoot{
		TimestampAuthorities: map[string][]*x509.Certificate{"tsa": certChain},
	}

	// sigBytes used as the DSSE envelope signature and as the timestamped artifact.
	sigBytes := []byte("test-signature-bytes")
	validTSAResp := createRFC3161Timestamp(t, sigBytes, certChain, tsaKey, time.Now())

	// TSA response whose timestamp time is AFTER the TSA leaf cert's NotAfter (~9 years).
	// VerifyTimestampResponse succeeds (cert valid at time.Now()), but the time-window
	// check (ts.Time.After(tsaCert.NotAfter)) fails → continue.
	futureTS := createRFC3161Timestamp(t, sigBytes, certChain, tsaKey, time.Now().AddDate(10, 0, 0))

	// Self-signed signing cert that expires in 5 years; combined with a timestamp at
	// time.Now()+8 years it exercises the vc.ValidAtTime path.
	signingCertDER := makeSelfSignedCert(t, time.Now().Add(5*365*24*time.Hour))
	tsWithin9y := createRFC3161Timestamp(t, sigBytes, certChain, tsaKey, time.Now().AddDate(8, 0, 0))

	// Double-base64 encoded signature: the DSSE sig is base64(rawSig), but the
	// timestamp was created over rawSig. The decode shim in VerifyTimestamps
	// strips the outer encoding so verification still succeeds.
	rawSig := []byte("raw-sig-for-double-encode-test")
	doubleEncodedSig := []byte(base64.StdEncoding.EncodeToString(rawSig))
	doubleEncodedTSAResp := createRFC3161Timestamp(t, rawSig, certChain, tsaKey, time.Now())
	doubleEncodedBundle := buildBundleForTest(t, doubleEncodedSig, doubleEncodedTSAResp, nil)

	cases := []struct {
		name      string
		bundle    *sigstorebundlepkg.Bundle
		roots     *TrustedRoot
		expectErr string
	}{
		{
			// Timestamps() returns empty slice when TimestampVerificationData is nil.
			name:      "no TimestampVerificationData → ErrMissingVerificationMaterial",
			bundle:    bundleWithNoTimestamps(t),
			roots:     tsaRoots,
			expectErr: ErrMissingVerificationMaterial.Error(),
		},
		{
			// Timestamps present but no DSSE content → SignatureContent() fails.
			name:      "timestamps present but no signature content",
			bundle:    buildBundleForTest(t, nil, validTSAResp, nil),
			roots:     tsaRoots,
			expectErr: "could not get signature material",
		},
		{
			// Timestamps present, DSSE present, but TSA list is empty → no verifications.
			name:      "timestamps present but no TSA authorities configured",
			bundle:    buildBundleForTest(t, sigBytes, validTSAResp, nil),
			roots:     &TrustedRoot{},
			expectErr: "some timestamps verification failed",
		},
		{
			// VerifyTimestampResponse succeeds but ts.Time is after tsaCert.NotAfter.
			name:      "timestamp time after TSA cert NotAfter → time window check fails",
			bundle:    buildBundleForTest(t, sigBytes, futureTS, nil),
			roots:     tsaRoots,
			expectErr: "some timestamps verification failed",
		},
		{
			// ts.Time within TSA cert validity but after signing cert NotAfter → ValidAtTime fails.
			name:      "signing cert not valid at timestamp time",
			bundle:    buildBundleForTest(t, sigBytes, tsWithin9y, signingCertDER),
			roots:     tsaRoots,
			expectErr: "some timestamps verification failed",
		},
		{
			// Happy path: all checks pass, timestamp verified successfully.
			name:   "valid timestamp verified successfully",
			bundle: buildBundleForTest(t, sigBytes, validTSAResp, nil),
			roots:  tsaRoots,
		},
		{
			// The DSSE signature is base64(rawSig) but the timestamp covers rawSig.
			// The double-decode shim strips the outer encoding so verification succeeds.
			name:   "double-base64 encoded signature decoded and verified",
			bundle: doubleEncodedBundle,
			roots:  tsaRoots,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyTimestamps(tc.bundle, tc.roots)
			if tc.expectErr != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// newTSACertChain creates a fresh in-memory TSA certificate chain and returns
// the chain (leaf, intermediate, root) together with the leaf's signing key.
func newTSACertChain(t *testing.T) ([]*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	chain, err := tsasigner.NewTimestampingCertWithChain(key)
	require.NoError(t, err)
	return chain, key
}

// createRFC3161Timestamp creates a real RFC3161 timestamp response over data
// with the given time embedded as the timestamp time.
func createRFC3161Timestamp(t *testing.T, data []byte, chain []*x509.Certificate, key crypto.Signer, tsTime time.Time) []byte {
	t.Helper()
	tsq, err := dttimestamp.CreateRequest(bytes.NewReader(data), &dttimestamp.RequestOptions{
		Hash:         crypto.SHA256,
		Certificates: false,
	})
	require.NoError(t, err)

	req, err := dttimestamp.ParseRequest(tsq)
	require.NoError(t, err)

	tmpl := dttimestamp.Timestamp{
		HashAlgorithm:     req.HashAlgorithm,
		HashedMessage:     req.HashedMessage,
		Time:              tsTime,
		Policy:            asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 2},
		Ordering:          false,
		AddTSACertificate: false,
	}
	resp, err := tmpl.CreateResponseWithOpts(chain[0], key, crypto.SHA256)
	require.NoError(t, err)
	return resp
}

// makeSelfSignedCert creates a minimal self-signed certificate with the given NotAfter.
func makeSelfSignedCert(t *testing.T, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Signing Cert"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	require.NoError(t, err)
	return der
}

// buildBundleForTest assembles a sigstorebundle.Bundle with a DSSE envelope
// (when sigBytes != nil), an RFC3161 timestamp (when tsaResp != nil), and an
// optional signing certificate (when signingCertDER != nil).
func buildBundleForTest(t *testing.T, sigBytes, tsaResp, signingCertDER []byte) *sigstorebundlepkg.Bundle {
	t.Helper()

	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}

	if tsaResp != nil {
		pb.VerificationMaterial.TimestampVerificationData = &protobundle.TimestampVerificationData{
			Rfc3161Timestamps: []*protocommon.RFC3161SignedTimestamp{
				{SignedTimestamp: tsaResp},
			},
		}
	}

	if signingCertDER != nil {
		pb.VerificationMaterial.Content = &protobundle.VerificationMaterial_Certificate{
			Certificate: &protocommon.X509Certificate{RawBytes: signingCertDER},
		}
	}

	if sigBytes != nil {
		pb.Content = &protobundle.Bundle_DsseEnvelope{
			DsseEnvelope: &sigstoredsse.Envelope{
				Payload:     []byte("fake-payload"),
				PayloadType: "application/vnd.in-toto+json",
				Signatures: []*sigstoredsse.Signature{
					{Sig: sigBytes},
				},
			},
		}
	}

	return &sigstorebundlepkg.Bundle{Bundle: pb}
}

// bundleWithNoTimestamps returns a bundle whose VerificationMaterial has no
// TimestampVerificationData, so Timestamps() returns an empty slice.
func bundleWithNoTimestamps(t *testing.T) *sigstorebundlepkg.Bundle {
	t.Helper()
	pb := &protobundle.Bundle{
		MediaType:            "application/vnd.dev.sigstore.bundle+json;version=0.3",
		VerificationMaterial: &protobundle.VerificationMaterial{},
	}
	return &sigstorebundlepkg.Bundle{Bundle: pb}
}
