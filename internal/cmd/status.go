// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/ghcontrol"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
)

var (
	w  = color.New(color.FgHiWhite, color.BgBlack).SprintFunc()
	w2 = color.New(color.Faint, color.FgWhite, color.BgBlack).SprintFunc()
)

// statusOptions
type statusOptions struct {
	commitOptions
	level bool
}

// Validate checks the options
func (so *statusOptions) Validate() error {
	errs := []error{} //nolint:prealloc
	errs = append(errs, so.commitOptions.Validate())

	return errors.Join(errs...)
}

// AddFlags adds the subcommands flags
func (so *statusOptions) AddFlags(cmd *cobra.Command) {
	so.commitOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&so.level, "level", false, "print only the SLSA source level and exit")
}

// TODO(puerco): Most of the logic in this subcommand (except maybe the output)
// will be moved to a sourcetool object in the future to consolidate it into
// a reusable library.
func addStatus(parentCmd *cobra.Command) {
	opts := &statusOptions{}
	statusCmd := &cobra.Command{
		GroupID: cmdGroupVerification,
		Short:   "Check the SLSA Source status of a repo/branch",
		Long: `
sourcetool status: Check the SLSA Source status of a repo/branch

The status subcommand reads the current controls enabled for a branch
and reports the SLSA source level that the repository can claim. This
command is intended to help maintainers implementing SLSA controls
understand the next steps to secure their repos and progress in their
SLSA journey. 
`,
		Use:           "status [flags] owner/repo@branch",
		SilenceUsage:  false,
		SilenceErrors: true,
		Example: `Check the SLSA tooling status on a repository:
sourcetool status myorg/myrepo

A branch other than the default can be specified by appending it to
the repository slug:

sourcetool status myorg/myrepo@mybranch
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseLocator(args[0]); err != nil {
					return err
				}
			}

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.repoOptions.Validate(); err != nil {
				return err
			}

			if err := opts.EnsureDefaults(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate the options
			if err := opts.Validate(); err != nil {
				return err
			}

			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
			)
			if err != nil {
				return err
			}

			// Get the active repository controls
			controls, err := srctool.GetBranchControls(cmd.Context(), opts.GetBranch())
			if err != nil {
				return fmt.Errorf("fetching active controls: %w", err)
			}

			// The verified level is what the repository policy actually grants.
			// It can be lower than the eligible level when the policy targets a
			// lower level or when the policy is not fully met.
			pe := policy.NewPolicyEvaluator()
			evalResult, err := pe.EvaluateControl(cmd.Context(), opts.GetRepository(), opts.GetBranch(), controls)
			if err != nil {
				return fmt.Errorf("evaluating controls against policy: %w", err)
			}

			// A level is only verified by a VSA. When the latest commit of the
			// branch has none there is no verified level to report.
			tipHasVSA := isControlActive(controls, slsa.SLSA_SOURCE_SCS_VSA)
			verifiedLevel := verifiedSourceLevel(evalResult.VerifiedLevels, tipHasVSA)

			// --level prints just the policy-verified level and exits, for scripting.
			if opts.level {
				fmt.Println(verifiedLevel)
				return nil
			}

			// Look for provenance workflows that need to be updated
			workflows, err := srctool.FindProvenanceWorkflows(cmd.Context(), opts.GetBranch())
			if err != nil {
				return fmt.Errorf("checking provenance workflows: %w", err)
			}

			// The eligible level is the highest the active controls could
			// support, ignoring the repository policy.
			toplevel := eligibleLevel(controls, len(workflows) > 0)

			title := fmt.Sprintf(
				"\nSLSA Source Status for %s/%s@%s", opts.owner, opts.repository,
				ghcontrol.BranchToFullRef(opts.branch),
			)

			fmt.Println(w(title))
			fmt.Println(strings.Repeat("=", len(title)))

			var policyControlStatus *slsa.Control
			for _, c := range controls.Controls {
				if c.Name == slsa.PolicyAvailable {
					policyControlStatus = c
					continue
				}
				fmt.Printf("%-35s  ", c.Name)
				switch c.State {
				case slsa.StateActive:
					fmt.Println("✅")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if c.Message != "" {
						fmt.Print(w2(c.Message))
					}
					fmt.Println()
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				}
			}

			fmt.Println()
			policyNeedsUpdate := false
			if policyControlStatus != nil {
				fmt.Printf("%-35s  ", "Repo policy found:")
				switch policyControlStatus.State {
				case slsa.StateActive:
					fmt.Print("✅")
					// Check if the policy needs updating
					pcy, err := srctool.GetRepositoryPolicy(context.Background(), opts.GetRepository())
					if err == nil {
						pb := pcy.GetBranchPolicy(opts.GetBranch().Name)
						if pb != nil && pb.GetTargetSlsaSourceLevel() != string(toplevel) {
							fmt.Print(w2(fmt.Sprintf(" (needs update to %s)", toplevel)))
							policyNeedsUpdate = true
						}
					}
					fmt.Println()
				case slsa.StateNotEnabled:
					fmt.Println("🚫")
				case slsa.StateInProgress:
					fmt.Print("⏳")
					if policyControlStatus.Message != "" {
						fmt.Printf(" (%s)", policyControlStatus.Message)
					}
					fmt.Println()
				}
				fmt.Println()
			}

			fmt.Println(w("Current SLSA Source level: " + verifiedLevel))
			if tipHasVSA {
				printLevelGap(toplevel, verifiedLevel, evalResult.Shortfall)
			} else {
				printMissingVSA(toplevel, len(workflows) > 0)
			}
			printLegacyWorkflows(workflows)
			printFailingWorkflows(workflows)
			fmt.Println("")

			// Collect the recommended actions from the controls
			actions := []*slsa.ControlRecommendedAction{}
			for _, status := range controls.Controls {
				if status.RecommendedAction == nil {
					continue
				}

				// Suggest creating the policy but only when reaching SLSA3+
				if status.Name == slsa.PolicyAvailable && !slsa.IsLevelHigherOrEqualTo(toplevel, slsa.SlsaSourceLevel3) {
					continue
				}
				actions = append(actions, status.RecommendedAction)
			}

			// ... from the provenance workflows
			for _, wf := range workflows {
				if wf.RecommendedAction != nil {
					actions = append(actions, wf.RecommendedAction)
				}
			}

			// ... and from the policy
			if policyNeedsUpdate {
				actions = append(actions, &slsa.ControlRecommendedAction{
					Message: "Update the repository source policy",
					Command: "sourcetool policy create --update " + opts.GetRepository().Path,
				})
			}

			printRecommendedActions(actions)
			return nil
		},
	}
	opts.AddFlags(statusCmd)
	parentCmd.AddCommand(statusCmd)
}

// firstSourceLevel returns the first SLSA source level among the verified
// levels, defaulting to level 0 when none is present.
func firstSourceLevel(levels slsa.SourceVerifiedLevels) string {
	for _, level := range levels {
		if slsa.IsSlsaSourceLevel(level) {
			return string(level)
		}
	}
	return string(slsa.SlsaSourceLevel0)
}

// verifiedSourceLevel returns the SLSA source level verified for the latest
// commit of the branch. Without a VSA nothing is verified, so the level is 0
// no matter what the controls and the policy would grant.
func verifiedSourceLevel(levels slsa.SourceVerifiedLevels, tipHasVSA bool) string {
	if !tipHasVSA {
		return string(slsa.SlsaSourceLevel0)
	}
	return firstSourceLevel(levels)
}

// isControlActive returns true when the control is active in the set.
func isControlActive(controls *slsa.ControlSet, name slsa.ControlName) bool {
	c := controls.GetControl(name)
	return c != nil && c.State == slsa.StateActive
}

// eligibleLevel returns the highest level the active controls could support,
// ignoring the repository policy.
//
// The provenance and VSA controls are only active once the latest commit of
// the branch is attested. When the repository is attestable (it has a
// provenance workflow) they count as active, so the level is the one the
// commit is eligible for when attested and does not drop while a commit waits
// for its attestations.
func eligibleLevel(controls *slsa.ControlSet, attestable bool) slsa.SlsaSourceLevel {
	active := controls.GetActiveControls()
	if attestable {
		for _, name := range []slsa.ControlName{slsa.SLSA_SOURCE_SCS_PROVENANCE, slsa.SLSA_SOURCE_SCS_VSA} {
			if active.GetControl(name) == nil {
				active.AddControl(&slsa.Control{Name: name, State: slsa.StateActive})
			}
		}
	}
	return policy.ComputeEligibleSlsaLevel(active)
}

// printMissingVSA explains that no level is verified because the latest
// commit of the branch has no VSA.
func printMissingVSA(eligible slsa.SlsaSourceLevel, attestable bool) {
	if !attestable {
		fmt.Printf(
			"%s The latest commit of the branch has no VSA, so no level is verified for it.\n", w2("⚠️ "),
		)
		return
	}
	fmt.Printf(
		"%s The latest commit of the branch has no VSA yet, so no level is verified for it. The controls are eligible for %s once it is attested.\n",
		w2("⚠️ "), eligible,
	)
}

// printRecommendedActions prints the list of recommended actions, if any
func printRecommendedActions(actions []*slsa.ControlRecommendedAction) {
	if len(actions) == 0 {
		return
	}
	fmt.Println(w2("✨ Recommended actions:"))
	for _, action := range actions {
		fmt.Printf(" - %s\n", action.Message)
		if action.Command != "" {
			fmt.Printf("   > %s\n", action.Command)
		}
		fmt.Println()
	}
}

// printLegacyWorkflows warns about provenance workflows still calling the
// SLSA actions from a deprecated repository.
func printLegacyWorkflows(workflows []*models.ProvenanceWorkflow) {
	for _, wf := range workflows {
		if !wf.IsLegacy() {
			continue
		}
		fmt.Printf(
			"%s The workflow %s calls the SLSA actions from the deprecated %s repository.\n",
			w2("⚠️ "), wf.Path, strings.Join(wf.LegacyActionsRepos, " and "),
		)
	}
}

// printFailingWorkflows warns about provenance workflows whose most recent
// run failed, as no provenance is generated while the workflow fails.
func printFailingWorkflows(workflows []*models.ProvenanceWorkflow) {
	for _, wf := range workflows {
		if !wf.IsFailing() {
			continue
		}
		fmt.Printf("%s The last run of the workflow %s failed", w2("⚠️ "), wf.Path)
		if wf.LastRun.URL != "" {
			fmt.Printf(": %s", wf.LastRun.URL)
		}
		fmt.Println()

		// An out of date workflow is the one cause we can point to
		if wf.RecommendedAction != nil {
			fmt.Println("   The workflow is out of date, updating it may fix the failure.")
		}
	}
}

// printLevelGap explains when the policy-verified level is below the level the
// active controls would otherwise support.
func printLevelGap(eligible slsa.SlsaSourceLevel, verified string, shortfall *policy.PolicyShortfall) {
	if verified == string(eligible) {
		return
	}
	if shortfall != nil {
		fmt.Printf(
			"%s The controls are eligible for %s, but the policy target %s is not met: %s\n",
			w2("⚠️ "), eligible, shortfall.TargetLevel, shortfall.Reason,
		)
		return
	}
	fmt.Printf(
		"%s The controls are eligible for %s, but the policy only verifies %s. Raise the policy target to claim the higher level.\n",
		w2("⚠️ "), eligible, verified,
	)
}
