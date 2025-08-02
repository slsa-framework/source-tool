// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
	"sigs.k8s.io/release-utils/util"

	"github.com/slsa-framework/slsa-source-poc/pkg/policy"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool"
	"github.com/slsa-framework/slsa-source-poc/pkg/sourcetool/models"
)

type policyViewOpts struct {
	repoOptions
}

type policyCreateOpts struct {
	branchOptions
	interactive     bool
	openPullRequest bool
	update          bool
}

func (pco *policyCreateOpts) AddFlags(cmd *cobra.Command) {
	pco.branchOptions.AddFlags(cmd)
	cmd.PersistentFlags().BoolVar(&pco.openPullRequest, "pr", true, "Open a pull request to check-in the policy")
	cmd.PersistentFlags().BoolVar(&pco.interactive, "interactive", true, "confirm before performing changes")
	cmd.PersistentFlags().BoolVar(&pco.update, "update", false, "update if existing policy found")
}

func addPolicy(parentCmd *cobra.Command) {
	policyCmd := &cobra.Command{
		Short: "tools to work with source policies",
		Long: fmt.Sprintf(`
%s %s

The policy subcommands can be used to view, create and update the source
policy for a repository. The policy family has two subcommands:

%s
Shows current repository policy for a repository checjed into the SLSA community
policy repo.

%s
Creates a new policy for a repository and, optionally, check it into the
SLSA community repository.

`, w("sourcetool policy:"), w2("configure SLSA source policies for a repo"),
			w("sourcetool policy view"), w("sourcetool policy create")),
		Use:           "policy",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	addPolicyView(policyCmd)
	addPolicyCreate(policyCmd)
	parentCmd.AddCommand(policyCmd)
}

func addPolicyView(parent *cobra.Command) {
	opts := &policyViewOpts{}
	policyViewCmd := &cobra.Command{
		Short: "view the policy of a repository",
		Long: `The view subcommand retrieves the policy stored in the SLSA community
repository for a repository and displays it.
`,
		Use:           "view owner/repo",
		SilenceUsage:  false,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				if err := opts.ParseSlug(args[0]); err != nil {
					return err
				}
			}

			// Validate early the repository options to provide a more
			// useful message to the user
			if err := opts.Validate(); err != nil {
				return err
			}

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if err := opts.Validate(); err != nil {
				return err
			}

			// At this point options are valid, no help needed.
			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				// sourcetool.WithPolicyRepo(opts.policyRepo),
			)
			if err != nil {
				return err
			}

			pcy, err := srctool.GetRepositoryPolicy(context.Background(), opts.GetRepository())
			if err != nil {
				return err
			}

			if err := displayPolicy(opts.repoOptions, pcy); err != nil {
				return err
			}

			return nil
		},
	}
	opts.AddFlags(policyViewCmd)
	parent.AddCommand(policyViewCmd)
}

// addPolicyCreate adds the create subcreate
func addPolicyCreate(parent *cobra.Command) {
	opts := &policyCreateOpts{}
	policyViewCmd := &cobra.Command{
		Short: "creates a source policy for a repository",
		Long: `The create subcommand inspects the controls in place for a repo
and creates a new policy for it. By default it will create a pull request
in the community source policy repository. If you choose not to, it will
just print the generated policy.

`,
		Use:           "create owner/repo@branch",
		SilenceUsage:  false,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, args []string) error {
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
		RunE: func(cmd *cobra.Command, args []string) (err error) {
			if err := opts.Validate(); err != nil {
				return err
			}

			// At this point options are valid, no help needed.
			cmd.SilenceUsage = true

			authenticator, err := CheckAuth()
			if err != nil {
				return err
			}

			fmt.Println()
			fmt.Println(w(fmt.Sprintf("Creating source policy for %s#%s", opts.GetRepository().GetHttpURL(), opts.GetBranch().Name)))
			// Create a new sourcetool object
			srctool, err := sourcetool.New(
				sourcetool.WithAuthenticator(authenticator),
				// Uncomment when we want to support custom policy repos
				// sourcetool.WithPolicyRepo(opts.policyRepo),
				sourcetool.WithCreatePolicyPR(opts.openPullRequest),
			)
			if err != nil {
				return err
			}

			epcy, err := srctool.GetRepositoryPolicy(context.Background(), opts.GetRepository())
			if err != nil {
				return fmt.Errorf("checking for existing policy: %w", err)
			}

			if epcy != nil && !opts.interactive && !opts.update {
				fmt.Fprintln(os.Stderr, "There is an existing policy in the community repository")
				return nil
			}

			if epcy != nil && !opts.update {
				fmt.Println()
				fmt.Println("There is a policy already published for this repository.")
				fmt.Println("Do you want to update it?")
				fmt.Println()

				_, s, err := util.Ask("Type 'yes' if you want to continue", "yes|no|no", 3)
				if err != nil {
					return err
				}

				if !s {
					fmt.Println("Not changing existing policy.")
					return nil
				}
			}

			// If there is an existing policy, check if something changed.
			var pcy *policy.RepoPolicy
			pcy, err = srctool.CreateBranchPolicy(
				context.Background(), opts.GetRepository(), []*models.Branch{opts.GetBranch()},
			)
			if err != nil {
				return fmt.Errorf("creating new source policy: %w", err)
			}
			if epcy != nil {
				if proto.Equal(pcy, epcy) {
					fmt.Println()
					fmt.Printf("Repository policy has not changed. All done.")
					fmt.Println()
					return nil
				}
			}

			if opts.openPullRequest && opts.interactive {
				if err := ensureOrCreatePolicyFork(srctool); err != nil {
					return err
				}

				fmt.Printf(`

sourcetool is about to perform the following actions on your behalf:

    >  Open a pull request in %s/%s checking in
       a SLSA source policy for the current controls enabled
       in %s/%s.

We will push a branch to your fork of the community repository and 
open the pull request from there.

`, policy.SourcePolicyRepoOwner, policy.SourcePolicyRepo, opts.owner, opts.repository)

				_, s, err := util.Ask("Type 'yes' if you want to continue?", "yes|no|no", 3)
				if err != nil {
					return err
				}

				if !s {
					fmt.Println("Cancelled.")
					return nil
				}
			}

			// Create the policy, this will open the pull request in the community
			// repo if the options say so.
			_, pr, err := srctool.CreateRepositoryPolicy(
				context.Background(), opts.GetRepository(), []*models.Branch{opts.GetBranch()},
			)
			if err != nil {
				return err
			}

			if err := displayPolicy(opts.repoOptions, pcy); err != nil {
				return err
			}

			if opts.openPullRequest && pr != nil {
				fmt.Fprintf(os.Stderr, "\n")
				fmt.Fprintf(os.Stderr, "pull request open: https://github.com/%s/pull/%d\n\n", pr.Repo.Path, pr.Number)
			}

			return nil
		},
	}
	opts.AddFlags(policyViewCmd)
	parent.AddCommand(policyViewCmd)
}

func displayPolicy(opts repoOptions, pcy *policy.RepoPolicy) error {
	if pcy == nil {
		fmt.Println("\n" + w(fmt.Sprintf("✖️  No source policy found for %s/%s", opts.owner, opts.repository)))
		fmt.Println("To create and check-in a policy for the repository run:")
		fmt.Println()
		fmt.Printf("    sourcetool policy create %s/%s\n", opts.owner, opts.repository)
		fmt.Println()
		return nil
	}

	data, err := json.MarshalIndent(pcy, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling policy data: %w", err)
	}

	fmt.Fprint(os.Stderr, w(fmt.Sprintf("\n🛡️  Source policy for %s/%s:\n\n", opts.owner, opts.repository)))
	fmt.Println(string(data))
	fmt.Println()
	return nil
}

// ensureOrCreatePolicyFork checks the user has a fork of the policy repo.
// In case they do not, asks to create a fork in their GitHub account.
func ensureOrCreatePolicyFork(srctool *sourcetool.Tool) error {
	found, err := srctool.CheckPolicyRepoFork()
	if err != nil {
		return fmt.Errorf("checking for policy repo fork: %w", err)
	}
	if found {
		return nil
	}

	fmt.Println()
	fmt.Println()
	fmt.Printf("%s sourcetool could not find a fork of the community source\n", w("Note:"))
	fmt.Printf("policy repository (%s). We need it to\n", srctool.Options.PolicyRepo)
	fmt.Println("create pull requests for your policies.")
	fmt.Println()
	fmt.Println("Would you like to create the fork in your GitHub account now?")
	fmt.Println()

	_, s, err := util.Ask("Type 'yes' if you want to continue?", "yes|no|no", 3)
	if err != nil {
		return err
	}
	if !s {
		return errors.New("no policy repo found and creation declined")
	}

	if err := srctool.CreatePolicyRepoFork(context.Background()); err != nil {
		return err
	}
	return nil
}
