// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/policylabs/attestation"
	"github.com/policylabs/collector"
	"github.com/policylabs/collector/repository"

	"github.com/slsa-framework/source-tool/pkg/attest"
)

// maxStoreAttempts is how many times the attestations are sent to a store
// before giving up.
const maxStoreAttempts = 3

// storeRetryDelay is waited before the second attempt and doubled before each
// one after it. A variable so tests do not wait.
var storeRetryDelay = 2 * time.Second

// pushAttestations publishes the envelopes to every store configured in the
// agent. Each store is retried on its own: a store that already has the
// attestations is never written again because another one failed, which would
// duplicate them.
func pushAttestations(ctx context.Context, agent *collector.Agent, envelopes []attestation.Envelope) error {
	storers := []attestation.Storer{}
	for _, repo := range agent.Repositories {
		if s, ok := repo.(attestation.Storer); ok {
			storers = append(storers, s)
		}
	}
	if len(storers) == 0 {
		return errors.New("no storer repositories configured")
	}

	envelopes = orderForPush(envelopes)

	errs := []error{}
	for _, s := range storers {
		if err := storeWithRetry(ctx, s, agent.Options.Store, envelopes); err != nil {
			errs = append(errs, fmt.Errorf("storing attestations: %w", err))
		}
	}
	return errors.Join(errs...)
}

// orderForPush returns the envelopes with the VSAs first. The provenance of a
// revision states that its VSA exists. Stores that take one envelope at a time
// can fail between the two, publishing the VSA first means such a failure
// never leaves a provenance pointing to a VSA that was not published.
func orderForPush(envelopes []attestation.Envelope) []attestation.Envelope {
	ordered := slices.Clone(envelopes)
	slices.SortStableFunc(ordered, func(a, b attestation.Envelope) int {
		switch av, bv := isVSA(a), isVSA(b); {
		case av && !bv:
			return -1
		case !av && bv:
			return 1
		default:
			return 0
		}
	})
	return ordered
}

func isVSA(env attestation.Envelope) bool {
	if env == nil || env.GetStatement() == nil {
		return false
	}
	return env.GetStatement().GetPredicateType() == attestation.PredicateType(attest.VsaPredicateType)
}

// storeWithRetry sends the envelopes to a store, trying again when it fails.
// When the store reports which envelopes it could not take, only those are
// sent again.
func storeWithRetry(
	ctx context.Context, storer attestation.Storer, opts attestation.StoreOptions, envelopes []attestation.Envelope,
) error {
	pending := envelopes
	delay := storeRetryDelay
	for attempt := 1; ; attempt++ {
		err := storer.Store(ctx, opts, pending)
		if err == nil {
			return nil
		}
		if attempt >= maxStoreAttempts || !retryableStore(ctx, err) {
			return err
		}

		// Keep only the envelopes the store did not take
		var serr *repository.StoreError
		if errors.As(err, &serr) {
			failed := make([]attestation.Envelope, 0, len(serr.Failed))
			for i, env := range pending {
				if _, ok := serr.Failed[i]; ok {
					failed = append(failed, env)
				}
			}
			if len(failed) > 0 {
				pending = failed
			}
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("%w (last error: %w)", ctx.Err(), err)
		case <-time.After(delay):
		}
		delay *= 2
	}
}

// retryableStore reports whether a failed store is worth another attempt.
// Failures for lack of access will fail again, as will any under a context
// that is done.
func retryableStore(ctx context.Context, err error) bool {
	if ctx.Err() != nil {
		return false
	}
	for _, permanent := range []error{
		transport.ErrAuthenticationRequired,
		transport.ErrAuthorizationFailed,
		transport.ErrRepositoryNotFound,
		transport.ErrInvalidAuthMethod,
	} {
		if errors.Is(err, permanent) {
			return false
		}
	}
	return true
}
