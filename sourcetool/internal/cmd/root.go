/*
Copyright © 2025 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
)

var githubToken string

func getVerifier(vo *verifierOptions) attest.Verifier {
	options := attest.DefaultVerifierOptions
	if vo.expectedIssuer != "" {
		options.ExpectedIssuer = vo.expectedIssuer
	}
	if vo.expectedSan != "" {
		options.ExpectedSan = vo.expectedSan
	}
	return attest.NewBndVerifier(options)
}

func buildRootCommand() *cobra.Command {
	// rootCmd represents the base command when called without any subcommands
	rootCmd := &cobra.Command{
		Use:   "sourcetool",
		Short: "A tool to manage SLSA Source in code repositories",
		Long: `
SLSA sourcetool: Manage SLSA Source controls and data

The sourcetool utility lets repository administrators configure and manage
the SLSA Source security controls in repositories. sourcetool can generate
attestations and verify them, check the status of repositories, configure
controls and much more.
`,
	}

	rootCmd.PersistentFlags().StringVar(&githubToken, "github_token", "", "the github token to use for auth")

	addCheckLevel(rootCmd)
	addCheckLevelProv(rootCmd)
	addVerifyCommit(rootCmd)
	addStatus(rootCmd)
	addSetup(rootCmd)
	addAudit(rootCmd)
	addProv(rootCmd)
	addCheckTag(rootCmd)
	addCreatePolicy(rootCmd)
	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	rootCmd := buildRootCommand()
	if err := rootCmd.Execute(); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
}
