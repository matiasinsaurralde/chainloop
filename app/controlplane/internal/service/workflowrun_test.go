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

package service

import (
	"context"
	"errors"
	"io"
	"testing"

	pb "github.com/chainloop-dev/chainloop/app/controlplane/api/controlplane/v1"
	conf "github.com/chainloop-dev/chainloop/app/controlplane/internal/conf/controlplane/config/v1"
	"github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz"
	bizMocks "github.com/chainloop-dev/chainloop/app/controlplane/pkg/biz/mocks"
	attestationpb "github.com/chainloop-dev/chainloop/pkg/attestation/crafter/api/attestation/v1"
	"github.com/chainloop-dev/chainloop/pkg/attestation/renderer/chainloop"
	"github.com/chainloop-dev/chainloop/pkg/cache/policyevalbundle"
	"github.com/google/uuid"
	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	sha256Alg           = "sha256"
	testBundleHexDigest = "cf4c9c8b7b1b4f4d0b4e3f4a5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d"
	testBundleDigest    = sha256Alg + ":" + testBundleHexDigest
)

// policyEvaluationsBundle builds a valid protojson-encoded bundle carrying a
// single evaluation with one violation.
func policyEvaluationsBundle(t *testing.T) []byte {
	t.Helper()

	bundle := &attestationpb.PolicyEvaluationBundle{
		Evaluations: []*attestationpb.PolicyEvaluation{
			{
				Name:         "strong-acl",
				MaterialName: "registry-report",
				Violations: []*attestationpb.PolicyEvaluation_Violation{
					{Subject: "HKLM\\Software", Message: "weak ACL"},
				},
			},
		},
	}

	data, err := protojson.Marshal(bundle)
	require.NoError(t, err)

	return data
}

// testPolicyEvaluationsRef builds the reference an attestation carries. A
// sizeBytes of zero records no size, standing in for an attestation that does
// not report one.
func testPolicyEvaluationsRef(sizeBytes int64) *chainloop.PolicyEvaluationsRef {
	return &chainloop.PolicyEvaluationsRef{
		ResourceDescriptor: &intoto.ResourceDescriptor{
			Name:      "policy-evaluations",
			Digest:    map[string]string{sha256Alg: testBundleHexDigest},
			MediaType: chainloop.PolicyEvaluationsBundleMediaType,
		},
		SizeBytes: sizeBytes,
	}
}

func TestResolvePolicyEvaluations(t *testing.T) {
	orgID := uuid.New()
	bundle := policyEvaluationsBundle(t)

	testCases := []struct {
		name string
		// ref defaults to a valid one when nil and useNilRef is false
		ref       *chainloop.PolicyEvaluationsRef
		useNilRef bool
		// bundleSize is what the reference records; zero means it records none
		bundleSize int64
		// maxInlineBytes 0 selects the built-in default
		maxInlineBytes int64
		// seedCache pre-populates the bundle cache with these bytes
		seedCache []byte
		// mappingErr makes the CAS mapping lookup fail
		mappingErr error
		// downloadBody is what the CAS download writes out
		downloadBody []byte
		// downloadExceedsCap models a transfer that overruns the cap: the bounded
		// writer refuses the write and the CAS client surfaces a download error
		downloadExceedsCap bool

		wantNilResolution bool
		wantEvaluations   bool
		wantRefReason     pb.PolicyEvaluationsRef_Reason
		wantRefSize       int64
		// the reference carries no digest when the descriptor had no sha256
		wantEmptyRefDigest bool
		wantMappingLookup  bool
		wantDownloadCall   bool
	}{
		{
			name:              "no reference resolves to nothing",
			useNilRef:         true,
			wantNilResolution: true,
		},
		{
			name:              "a recorded size under the cap is downloaded and inlined",
			bundleSize:        int64(len(bundle)),
			downloadBody:      bundle,
			wantEvaluations:   true,
			wantMappingLookup: true,
			wantDownloadCall:  true,
		},
		{
			name:           "a recorded size over the cap never reaches the CAS",
			maxInlineBytes: 16,
			bundleSize:     64 * 1024 * 1024,
			wantRefReason:  pb.PolicyEvaluationsRef_REASON_TOO_LARGE,
			wantRefSize:    64 * 1024 * 1024,
		},
		{
			name:              "a recorded size exactly at the cap is inlined",
			maxInlineBytes:    int64(len(bundle)),
			bundleSize:        int64(len(bundle)),
			downloadBody:      bundle,
			wantEvaluations:   true,
			wantMappingLookup: true,
			wantDownloadCall:  true,
		},
		{
			// With no recorded size the cap cannot be applied up front, but the
			// download is still bounded, so a bundle under the cap inlines...
			name:              "a reference with no recorded size under the cap is inlined",
			downloadBody:      bundle,
			wantEvaluations:   true,
			wantMappingLookup: true,
			wantDownloadCall:  true,
		},
		{
			// ...and one that overruns the cap is refused mid-transfer rather than
			// pulled into memory, even though it recorded no size. A zero or omitted
			// size must never authorize an unbounded read (the View-API DoS regression).
			name:               "a reference with no recorded size over the cap is bounded",
			maxInlineBytes:     4,
			downloadBody:       bundle,
			downloadExceedsCap: true,
			wantRefReason:      pb.PolicyEvaluationsRef_REASON_TOO_LARGE,
			wantRefSize:        0,
			wantMappingLookup:  true,
			wantDownloadCall:   true,
		},
		{
			// The recorded size is client-influenced (it travels in the attestation
			// predicate), so a small claim must not be trusted to authorize an
			// oversized transfer: the bound catches it regardless of the claim.
			name:               "a small recorded size cannot authorize an oversized download",
			bundleSize:         4,
			maxInlineBytes:     8,
			downloadBody:       bundle,
			downloadExceedsCap: true,
			wantRefReason:      pb.PolicyEvaluationsRef_REASON_TOO_LARGE,
			wantRefSize:        0,
			wantMappingLookup:  true,
			wantDownloadCall:   true,
		},
		{
			// A cached entry is size-checked too, so a lowered cap (or an entry
			// written before the cap existed) is never served from cache unbounded.
			name:           "a cached bundle over the cap is not inlined even without a recorded size",
			seedCache:      bundle,
			maxInlineBytes: 4,
			wantRefReason:  pb.PolicyEvaluationsRef_REASON_TOO_LARGE,
			wantRefSize:    int64(len(bundle)),
		},
		{
			name:              "missing CAS mapping is not downloaded",
			bundleSize:        int64(len(bundle)),
			mappingErr:        biz.NewErrNotFound("digest"),
			wantRefReason:     pb.PolicyEvaluationsRef_REASON_UNAVAILABLE,
			wantRefSize:       int64(len(bundle)),
			wantMappingLookup: true,
		},
		{
			name:            "cached bundle skips the CAS entirely",
			bundleSize:      int64(len(bundle)),
			seedCache:       bundle,
			wantEvaluations: true,
		},
		{
			name:           "a cached bundle is still capped by the recorded size",
			seedCache:      bundle,
			bundleSize:     int64(len(bundle)),
			maxInlineBytes: 4,
			wantRefReason:  pb.PolicyEvaluationsRef_REASON_TOO_LARGE,
			wantRefSize:    int64(len(bundle)),
		},
		{
			name:              "undecodable bundle reports unavailable",
			bundleSize:        16,
			downloadBody:      []byte("this is not protojson"),
			wantRefReason:     pb.PolicyEvaluationsRef_REASON_UNAVAILABLE,
			wantRefSize:       int64(len("this is not protojson")),
			wantMappingLookup: true,
			wantDownloadCall:  true,
		},
		{
			name: "a reference without a sha256 digest reports unavailable",
			ref: &chainloop.PolicyEvaluationsRef{
				ResourceDescriptor: &intoto.ResourceDescriptor{
					Name:   "policy-evaluations",
					Digest: map[string]string{"sha512": "abc"},
				},
			},
			wantRefReason:      pb.PolicyEvaluationsRef_REASON_UNAVAILABLE,
			wantEmptyRefDigest: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()

			casClient := bizMocks.NewCASClient(t)
			if tc.wantDownloadCall {
				var downloadErr error
				if tc.downloadExceedsCap {
					downloadErr = errors.New("content exceeds the maximum")
				}
				casClient.On("Download", mock.Anything, mock.Anything, mock.Anything, orgID, mock.Anything, testBundleDigest).
					Run(func(args mock.Arguments) {
						w, ok := args.Get(4).(io.Writer)
						require.True(t, ok)
						n, err := w.Write(tc.downloadBody)
						if tc.downloadExceedsCap {
							// The bounded writer refuses the write that would overrun
							// the cap and reports a short write, which the real CAS
							// client surfaces as the download error returned below.
							require.Error(t, err)
							require.Less(t, n, len(tc.downloadBody))

							return
						}
						require.NoError(t, err)
					}).Return(downloadErr)
			}

			mappingRepo := bizMocks.NewCASMappingRepo(t)
			if tc.wantMappingLookup {
				mapping := &biz.CASMapping{CASBackend: &biz.CASBackend{
					Provider:       "OCI_REPOSITORY",
					SecretName:     "secret-name",
					OrganizationID: orgID,
				}}
				if tc.mappingErr != nil {
					mapping = nil
				}
				mappingRepo.On("FindByDigestInOrgs", mock.Anything, testBundleDigest, mock.Anything, mock.Anything).
					Return(mapping, tc.mappingErr)
			}

			cache, err := policyevalbundle.New(ctx, nil, nil)
			require.NoError(t, err)
			if tc.seedCache != nil {
				require.NoError(t, cache.Set(ctx, testBundleDigest, tc.seedCache))
			}

			svc := NewWorkflowRunService(&NewWorkflowRunServiceOpts{
				CASClient:       casClient,
				CASMappingUC:    biz.NewCASMappingUseCase(mappingRepo, nil, nil),
				PolicyEvalCache: cache,
				BootstrapConfig: &conf.Bootstrap{
					Attestations: &conf.Attestations{
						PolicyEvaluationsMaxInlineBytes: tc.maxInlineBytes,
					},
				},
			})

			ref := tc.ref
			if !tc.useNilRef && ref == nil {
				ref = testPolicyEvaluationsRef(tc.bundleSize)
			}

			got := svc.resolvePolicyEvaluations(ctx, ref, orgID)

			if tc.wantNilResolution {
				assert.Nil(t, got)
				return
			}

			require.NotNil(t, got)

			if tc.wantEvaluations {
				require.NotEmpty(t, got.evaluations)
				assert.Len(t, got.evaluations["registry-report"], 1)

				// The bundle is referenced alongside the evaluations so callers
				// always know where the full set lives.
				require.NotNil(t, got.ref)
				assert.True(t, got.ref.GetInlined())
				assert.Equal(t, pb.PolicyEvaluationsRef_REASON_UNSPECIFIED, got.ref.GetReason())
				assert.Equal(t, testBundleDigest, got.ref.GetDigest())
				assert.Equal(t, chainloop.PolicyEvaluationsBundleMediaType, got.ref.GetMediaType())
				// The decoded byte count, not the size the attestation recorded.
				assert.Equal(t, int64(len(bundle)), got.ref.GetSizeBytes())

				return
			}

			assert.Empty(t, got.evaluations)
			require.NotNil(t, got.ref)
			assert.False(t, got.ref.GetInlined())
			assert.Equal(t, tc.wantRefReason, got.ref.GetReason())
			assert.Equal(t, tc.wantRefSize, got.ref.GetSizeBytes())

			wantRefDigest := testBundleDigest
			if tc.wantEmptyRefDigest {
				wantRefDigest = ""
			}
			assert.Equal(t, wantRefDigest, got.ref.GetDigest())

			if !tc.wantDownloadCall {
				casClient.AssertNotCalled(t, "Download", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
			}
		})
	}
}
