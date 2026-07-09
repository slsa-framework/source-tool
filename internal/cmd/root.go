// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/auth"
)

var githubToken string

// Command group IDs used to organize the subcommands in the help screen.
const (
	cmdGroupVerification  = "verification"
	cmdGroupAttestation   = "attestation"
	cmdGroupAssessment    = "assessment"
	cmdGroupPolicy        = "policy"
	cmdGroupConfiguration = "configuration"
)

// exitError wraps an error together with an exit code so commands can
// signal other failuresdistinct from a generic failure (exit 1).
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func buildRootCommand() *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	rootCmd := &cobra.Command{
		Use:           "sourcetool",
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "A tool to manage SLSA Source in code repositories",
		Long: `
SLSA sourcetool: Manage SLSA Source controls and data

The sourcetool utility lets repository administrators configure and manage
the SLSA Source security controls in repositories. sourcetool can generate
attestations and verify them, check the status of repositories, configure
controls and much more.
`,
	}

	rootCmd.PersistentFlags().StringVar(&githubToken, "github_token", "", "the github token to use for auth")

	// Define command groups for better organization
	rootCmd.AddGroup(
		&cobra.Group{
			ID:    cmdGroupVerification,
			Title: "Verification Commands:",
		},
		&cobra.Group{
			ID:    cmdGroupAttestation,
			Title: "Attestation Commands:",
		},
		&cobra.Group{
			ID:    cmdGroupAssessment,
			Title: "Assessment Commands:",
		},
		&cobra.Group{
			ID:    cmdGroupPolicy,
			Title: "Policy Commands:",
		},
		&cobra.Group{
			ID:    cmdGroupConfiguration,
			Title: "Configuration & Setup Commands:",
		},
	)

	// Verification commands
	addVerify(rootCmd)
	addAudit(rootCmd)

	// Attestation commands
	addAttest(rootCmd)

	// Assessment commands
	addStatus(rootCmd)
	addCheckLevel(rootCmd)
	addCheckLevelProv(rootCmd)
	addCheckTag(rootCmd)
	addProv(rootCmd)

	// Policy commands
	addPolicy(rootCmd)
	addCreatePolicy(rootCmd)

	// Configuration & setup commands
	addSetup(rootCmd)
	addAuth(rootCmd)

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd := buildRootCommand()
	err := rootCmd.Execute()
	if err == nil {
		return
	}

	// Subcommands may send a specific exit code by returning an *exitError.
	// Everything else is a generic failure (exit 1).
	var ee *exitError
	if errors.As(err, &ee) {
		fmt.Println(ee.Error())
		os.Exit(ee.code)
	}

	fmt.Printf("Error: %v\n", err)
	os.Exit(1)
}

func CheckAuth() (*auth.Authenticator, error) {
	authenticator := auth.New()
	user, err := authenticator.WhoAmI()
	if err != nil {
		return nil, fmt.Errorf("checking authentication status: %w", err)
	}

	if user == nil {
		fmt.Println()
		fmt.Println("🚫  " + w("sourcetool is not logged in"))
		fmt.Println()
		fmt.Println("Please log into your GitHub account before using sourcetool. To")
		fmt.Println("log in, run the following command:")
		fmt.Println()
		fmt.Println("  sourcetool auth login")
		fmt.Println()
		return nil, errors.New("source tool is not logged in")
	}
	return authenticator, nil
}
