//
// Copyright 2025-2026 The Chainloop Authors.
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
	"context"
	"crypto/x509"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestVerifyBundle(t *testing.T) {
	ca, err := os.ReadFile("testdata/ca.pub")
	require.NoError(t, err)
	certs, err := cryptoutils.LoadCertificatesFromPEM(bytes.NewReader(ca))
	require.NoError(t, err)
	roots := &TrustedRoot{Keys: map[string][]*x509.Certificate{
		"2a522d9652e0933d2a1237c395bc116e012f86dffff13122da59f76e0d2abe27": certs,
	}}

	// Bundle with fake RFC3161 timestamps — all TSA verifications will fail.
	fakeTS := buildBundleForTest(t, []byte("some-sig-bytes"), []byte("fake-tsa-response"), nil)
	fakeTSBytes, err := protojson.Marshal(fakeTS.Bundle)
	require.NoError(t, err)

	// Bundle with a real RFC3161 timestamp and no signing cert — verifiable via timestamp alone.
	certChain, tsaKey := newTSACertChain(t)
	sigBytes := []byte("deterministic-test-signature-bytes")
	validResp := createRFC3161Timestamp(t, sigBytes, certChain, tsaKey, time.Now())
	realTSBundle := buildBundleForTest(t, sigBytes, validResp, nil)
	realTSBundleBytes, err := protojson.Marshal(realTSBundle.Bundle)
	require.NoError(t, err)
	realTSRoots := &TrustedRoot{
		TimestampAuthorities: map[string][]*x509.Certificate{"tsa": certChain},
	}

	// TrustedRoot with the correct AKI for bundle_valid.json but an unrelated cert chain.
	// cosign.ValidateAndUnpackCertWithChain will fail since the chain does not match.
	wrongChainRoots := &TrustedRoot{Keys: map[string][]*x509.Certificate{
		"2a522d9652e0933d2a1237c395bc116e012f86dffff13122da59f76e0d2abe27": certChain,
	}}

	cases := []struct {
		name        string
		roots       *TrustedRoot
		bundleBytes []byte
		bundleFile  string
		expectErr   string
	}{
		{
			name:        "nil bundle bytes",
			roots:       roots,
			bundleBytes: nil,
			expectErr:   "missing material",
		},
		{
			name:        "invalid JSON",
			roots:       roots,
			bundleBytes: []byte("not-valid-json"),
			expectErr:   "invalid bundle",
		},
		{
			name:       "invalid bundle, but still verifiable",
			roots:      roots,
			bundleFile: "testdata/bundle_wrongversion.json",
		},
		{
			name:       "valid bundle",
			roots:      roots,
			bundleFile: "testdata/bundle_valid.json",
		},
		{
			name:       "valid bundle without verification material",
			roots:      roots,
			bundleFile: "testdata/bundle_valid_nomaterial.json",
			expectErr:  "missing material",
		},
		{
			name:       "corrupted bundle",
			roots:      roots,
			bundleFile: "testdata/bundle_invalid.json",
			expectErr:  "validating the DSSE envelope",
		},
		{
			name:       "cert AKI not in trusted root",
			roots:      &TrustedRoot{Keys: map[string][]*x509.Certificate{}},
			bundleFile: "testdata/bundle_valid.json",
			expectErr:  "trusted root not found",
		},
		{
			name:       "cert chain validation fails",
			roots:      wrongChainRoots,
			bundleFile: "testdata/bundle_valid.json",
			expectErr:  "validating the certificate",
		},
		{
			name:        "bundle with timestamps that all fail verification",
			roots:       &TrustedRoot{TimestampAuthorities: map[string][]*x509.Certificate{"k": certs}},
			bundleBytes: fakeTSBytes,
			expectErr:   "could not verify timestamps",
		},
		{
			name:        "bundle with valid timestamps — succeeds via timestamp material",
			roots:       realTSRoots,
			bundleBytes: realTSBundleBytes,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var bundleBytes []byte
			if tc.bundleFile != "" {
				bundleBytes, err = os.ReadFile(tc.bundleFile)
				require.NoError(t, err)
			} else {
				bundleBytes = tc.bundleBytes
			}

			gotErr := VerifyBundle(context.TODO(), bundleBytes, tc.roots)
			if tc.expectErr != "" {
				assert.Error(t, gotErr)
				assert.True(t,
					errors.Is(gotErr, ErrMissingVerificationMaterial) || strings.Contains(gotErr.Error(), tc.expectErr),
					"expected error containing %q, got: %v", tc.expectErr, gotErr)
				return
			}
			assert.NoError(t, gotErr)
		})
	}
}
