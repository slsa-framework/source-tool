// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/audit"
	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
)

type AuditMode int

const (
	AuditModeBasic AuditMode = 1
	AuditModeFull  AuditMode = 2
)

const (
	statusPassed = "passed"
	statusFailed = "failed"
)

// Enable audit mode enum
// String is used both by fmt.Print and by Cobra in help text
func (e *AuditMode) String() string {
	switch *e {
	case AuditModeBasic:
		return "basic"
	case AuditModeFull:
		return "full"
	}
	return "error"
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *AuditMode) Set(v string) error {
	switch v {
	case "basic":
		*e = AuditModeBasic
		return nil
	case "full":
		*e = AuditModeFull
		return nil
	default:
		return errors.New(`must be one of "foo", "bar", or "moo"`)
	}
}

// Type is only used in help text
func (e *AuditMode) Type() string {
	return "AuditMode"
}

type auditOpts struct {
	branchOptions
	verifierOptions
	outputOptions
	auditDepth   int
	endingCommit string
	auditMode    AuditMode
}

// AuditCommitResultJSON represents a single commit audit result in JSON format
type AuditCommitResultJSON struct {
	Commit            string      `json:"commit"`
	Status            string      `json:"status"`
	VerifiedLevels    []string    `json:"verified_levels,omitempty"`
	PrevCommitMatches *bool       `json:"prev_commit_matches,omitempty"`
	ProvControls      interface{} `json:"prov_controls,omitempty"`
	GhControls        interface{} `json:"gh_controls,omitempty"`
	PrevCommit        string      `json:"prev_commit,omitempty"`
	GhPriorCommit     string      `json:"gh_prior_commit,omitempty"`
	Link              string      `json:"link,omitempty"`
	Error             string      `json:"error,omitempty"`
}

// AuditResultJSON represents the full audit result in JSON format
type AuditResultJSON struct {
	Owner         string                  `json:"owner"`
	Repository    string                  `json:"repository"`
	Branch        string                  `json:"branch"`
	LatestCommit  string                  `json:"latest_commit"`
	CommitResults []AuditCommitResultJSON `json:"commit_results"`
	Summary       *AuditSummary           `json:"summary,omitempty"`
}

// AuditSummary provides summary statistics for the audit
type AuditSummary struct {
	TotalCommits  int `json:"total_commits"`
	PassedCommits int `json:"passed_commits"`
	FailedCommits int `json:"failed_commits"`
}

func (ao *auditOpts) Validate() error {
	errs := []error{
		ao.branchOptions.Validate(),
		ao.verifierOptions.Validate(),
		ao.outputOptions.Validate(),
	}
	return errors.Join(errs...)
}

func (ao *auditOpts) AddFlags(cmd *cobra.Command) {
	ao.branchOptions.AddFlags(cmd)
	ao.verifierOptions.AddFlags(cmd)
	ao.outputOptions.AddFlags(cmd)
	cmd.PersistentFlags().IntVar(&ao.auditDepth, "depth", 0, "The max number of revisions to audit (depth <= audit all revisions).")
	cmd.PersistentFlags().StringVar(&ao.endingCommit, "ending-commit", "", "The commit to stop auditing at.")
	ao.auditMode = AuditModeBasic
	cmd.PersistentFlags().Var(&ao.auditMode, "audit-mode", "'basic' for limited details (default), 'full' for all details")
}

func addAudit(parentCmd *cobra.Command) {
	opts := &auditOpts{}
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "Audits the SLSA properties and controls of a repository",
		Long: `Checks the revisions on the specified branch within the repository.

Revisions 'pass' an audit if they have:
1. A corresponding VSA
2. Corresponding source provenance
3. The revision (commit) listed in the provenance matches the revision reported by GitHub

Future:
* Check the provenance to validate the verifiedLevels in the VSA match expectations
  (i.e. that the VSA was issued correctly)
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return err
			}
			return doAudit(opts)
		},
	}
	opts.AddFlags(auditCmd)
	parentCmd.AddCommand(auditCmd)
}

func printResult(ghc *ghcontrol.GitHubConnection, ar *audit.AuditCommitResult, mode AuditMode) {
	good := ar.IsGood()
	status := statusPassed
	if !good {
		status = statusFailed
	}
	fmt.Printf("commit: %s - %v\n", ar.Commit, status)

	if good && AuditModeBasic == mode {
		return
	}

	if ar.VsaPred != nil {
		fmt.Printf("\tvsa: %v\n", ar.VsaPred.GetVerifiedLevels())
	} else {
		fmt.Printf("\tvsa: none\n")
	}
	if ar.ProvPred != nil {
		fmt.Print("\tprov:\n")
		fmt.Printf("\t\tcontrols: %v\n", ar.ProvPred.GetControls())
		if ar.ProvPred.GetPrevCommit() == ar.GhPriorCommit {
			fmt.Printf("\t\tPrevCommit matches GH commit: true\n")
		} else {
			fmt.Printf("\t\tPrevCommit matches GH commit: false: %s != %s\n", ar.ProvPred.GetPrevCommit(), ar.GhPriorCommit)
		}
	} else {
		fmt.Printf("\tprov: none\n")
	}
	if ar.GhControlStatus != nil {
		fmt.Printf("\tgh controls: %v\n", ar.GhControlStatus.Controls)
	}

	fmt.Printf("\tlink: https://github.com/%s/%s/commit/%s\n", ghc.Owner(), ghc.Repo(), ar.GhPriorCommit)
}

func convertAuditResultToJSON(ghc *ghcontrol.GitHubConnection, ar *audit.AuditCommitResult, mode AuditMode) AuditCommitResultJSON {
	good := ar.IsGood()
	status := statusPassed
	if !good {
		status = statusFailed
	}

	result := AuditCommitResultJSON{
		Commit: ar.Commit,
		Status: status,
		Link:   fmt.Sprintf("https://github.com/%s/%s/commit/%s", ghc.Owner(), ghc.Repo(), ar.GhPriorCommit),
	}

	// Only include details if mode is Full or status is failed
	if mode == AuditModeFull || !good {
		if ar.VsaPred != nil {
			result.VerifiedLevels = ar.VsaPred.GetVerifiedLevels()
		}

		if ar.ProvPred != nil {
			result.ProvControls = ar.ProvPred.GetControls()
			result.PrevCommit = ar.ProvPred.GetPrevCommit()
			result.GhPriorCommit = ar.GhPriorCommit
			matches := ar.ProvPred.GetPrevCommit() == ar.GhPriorCommit
			result.PrevCommitMatches = &matches
		}

		if ar.GhControlStatus != nil {
			result.GhControls = ar.GhControlStatus.Controls
		}
	}

	return result
}

func doAudit(auditArgs *auditOpts) error {
	ghc := ghcontrol.NewGhConnection(auditArgs.owner, auditArgs.repository, ghcontrol.BranchToFullRef(auditArgs.branch)).WithAuthToken(githubToken)
	ctx := context.Background()
	verifier := getVerifier(&auditArgs.verifierOptions)
	pa := attest.NewProvenanceAttestor(ghc, verifier)

	auditor := audit.NewAuditor(ghc, pa, verifier)

	latestCommit, err := ghc.GetLatestCommit(ctx, auditArgs.branch)
	if err != nil {
		return fmt.Errorf("could not get latest commit for %s", auditArgs.branch)
	}

	// Initialize JSON result structure if needed
	var jsonResult *AuditResultJSON
	if auditArgs.outputFormatIsJSON() {
		jsonResult = &AuditResultJSON{
			Owner:         auditArgs.owner,
			Repository:    auditArgs.repository,
			Branch:        auditArgs.branch,
			LatestCommit:  latestCommit,
			CommitResults: []AuditCommitResultJSON{},
		}
	} else {
		// Print header for text output
		auditArgs.writeTextf("Auditing branch %s starting from revision %s\n", auditArgs.branch, latestCommit)
	}

	// Single loop for both JSON and text output
	count := 0
	passed := 0
	failed := 0

	for ar, err := range auditor.AuditBranch(ctx, auditArgs.branch) {
		if ar == nil {
			return err
		}

		// Process result based on output format
		if auditArgs.outputFormatIsJSON() {
			commitResult := convertAuditResultToJSON(ghc, ar, auditArgs.auditMode)
			if err != nil {
				commitResult.Error = err.Error()
			}
			if commitResult.Status == statusPassed {
				passed++
			} else {
				failed++
			}
			jsonResult.CommitResults = append(jsonResult.CommitResults, commitResult)
		} else {
			// Text output
			if err != nil {
				auditArgs.writeTextf("\terror: %v\n", err)
			}
			printResult(ghc, ar, auditArgs.auditMode)
		}

		// Check for early termination conditions
		if auditArgs.endingCommit != "" && auditArgs.endingCommit == ar.Commit {
			if !auditArgs.outputFormatIsJSON() {
				auditArgs.writeTextf("Found ending commit %s\n", auditArgs.endingCommit)
			}
			break
		}
		if auditArgs.auditDepth > 0 && count >= auditArgs.auditDepth {
			if !auditArgs.outputFormatIsJSON() {
				auditArgs.writeTextf("Reached depth limit %d\n", auditArgs.auditDepth)
			}
			break
		}
		count++
	}

	// Write JSON output if needed
	if auditArgs.outputFormatIsJSON() {
		jsonResult.Summary = &AuditSummary{
			TotalCommits:  len(jsonResult.CommitResults),
			PassedCommits: passed,
			FailedCommits: failed,
		}
		return auditArgs.writeJSON(jsonResult)
	}

	return nil
}
