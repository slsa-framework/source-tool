// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector"
	"github.com/policylabs/collector/envelope"
	"github.com/policylabs/collector/repository"
	"github.com/stretchr/testify/require"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/provenance"
)

// fakeStorer records the predicate types it gets on each call and fails
// with the errors it is loaded with, one per call.
type fakeStorer struct {
	errs  []error
	calls [][]string
}

func (f *fakeStorer) Store(_ context.Context, _ attestation.StoreOptions, envs []attestation.Envelope) error {
	types := make([]string, 0, len(envs))
	for _, env := range envs {
		types = append(types, string(env.GetStatement().GetPredicateType()))
	}
	f.calls = append(f.calls, types)
	if len(f.calls) <= len(f.errs) {
		return f.errs[len(f.calls)-1]
	}
	return nil
}

func testEnvelope(t *testing.T, predicateType string) attestation.Envelope {
	t.Helper()
	data := fmt.Sprintf(
		`{"_type":"https://in-toto.io/Statement/v1","subject":[{"digest":{"gitCommit":"2fa9ea0072ad0090e0234d1e7f2b3e9c8b8a5b8d"}}],"predicateType":%q,"predicate":{}}`,
		predicateType,
	)
	envs, err := envelope.Parsers.Parse(strings.NewReader(data))
	require.NoError(t, err)
	require.Len(t, envs, 1)
	return envs[0]
}

func testAgent(t *testing.T, storers ...*fakeStorer) *collector.Agent {
	t.Helper()
	agent, err := collector.New()
	require.NoError(t, err)
	for _, s := range storers {
		require.NoError(t, agent.AddRepository(s))
	}
	return agent
}

// The tests swap the package-level retry delay, so they cannot run in parallel.
func TestPushAttestations(t *testing.T) { //nolint:paralleltest
	storeRetryDelay = time.Millisecond

	provType := provenance.SourceProvPredicateType
	vsaType := attest.VsaPredicateType
	transient := errors.New("connection reset")

	newEnvelopes := func(t *testing.T) []attestation.Envelope {
		t.Helper()
		return []attestation.Envelope{testEnvelope(t, provType), testEnvelope(t, vsaType)}
	}

	t.Run("vsa-goes-first", func(t *testing.T) { //nolint:paralleltest
		s := &fakeStorer{}
		envs := newEnvelopes(t)
		require.NoError(t, pushAttestations(t.Context(), testAgent(t, s), envs))
		require.Equal(t, [][]string{{vsaType, provType}}, s.calls)
		// The caller's slice is left as it was
		require.Equal(t, provType, string(envs[0].GetStatement().GetPredicateType()))
	})

	t.Run("retries-transient-failure", func(t *testing.T) { //nolint:paralleltest
		s := &fakeStorer{errs: []error{transient, transient}}
		require.NoError(t, pushAttestations(t.Context(), testAgent(t, s), newEnvelopes(t)))
		require.Len(t, s.calls, 3)
	})

	t.Run("gives-up-after-max-attempts", func(t *testing.T) { //nolint:paralleltest
		s := &fakeStorer{errs: []error{transient, transient, transient, transient}}
		err := pushAttestations(t.Context(), testAgent(t, s), newEnvelopes(t))
		require.ErrorIs(t, err, transient)
		require.Len(t, s.calls, maxStoreAttempts)
	})

	t.Run("resends-only-failed-envelopes", func(t *testing.T) { //nolint:paralleltest
		// The store took the VSA (#0) but not the provenance (#1)
		partial := &repository.StoreError{Stored: 1, Failed: map[int]error{1: transient}}
		s := &fakeStorer{errs: []error{partial}}
		require.NoError(t, pushAttestations(t.Context(), testAgent(t, s), newEnvelopes(t)))
		require.Equal(t, [][]string{{vsaType, provType}, {provType}}, s.calls)
	})

	t.Run("does-not-retry-access-errors", func(t *testing.T) { //nolint:paralleltest
		denied := fmt.Errorf("pushing notes: %w", transport.ErrAuthorizationFailed)
		s := &fakeStorer{errs: []error{denied, denied}}
		err := pushAttestations(t.Context(), testAgent(t, s), newEnvelopes(t))
		require.ErrorIs(t, err, transport.ErrAuthorizationFailed)
		require.Len(t, s.calls, 1)
	})

	t.Run("does-not-retry-when-context-is-done", func(t *testing.T) { //nolint:paralleltest
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		s := &fakeStorer{errs: []error{transient, transient}}
		require.Error(t, pushAttestations(ctx, testAgent(t, s), newEnvelopes(t)))
		require.Len(t, s.calls, 1)
	})

	t.Run("stores-are-retried-independently", func(t *testing.T) { //nolint:paralleltest
		good := &fakeStorer{}
		flaky := &fakeStorer{errs: []error{transient}}
		require.NoError(t, pushAttestations(t.Context(), testAgent(t, good, flaky), newEnvelopes(t)))
		// The store that worked is written once
		require.Len(t, good.calls, 1)
		require.Len(t, flaky.calls, 2)
	})

	t.Run("no-storers", func(t *testing.T) { //nolint:paralleltest
		require.Error(t, pushAttestations(t.Context(), testAgent(t), newEnvelopes(t)))
	})
}
