// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/auth"
)

var o = color.New(color.FgHiRed).SprintFunc()

// statusOptions
type authOptions struct{}

// Validate checks the options
func (ao *authOptions) Validate() error {
	return nil
}

// AddFlags adds the subcommands flags
func (ao *authOptions) AddFlags(cmd *cobra.Command) {}

func addAuth(parentCmd *cobra.Command) {
	authCmd := &cobra.Command{
		Short:         "Manage user authentication",
		Use:           "auth",
		SilenceUsage:  false,
		SilenceErrors: true,
	}
	addWhoAmI(authCmd)
	addLogin(authCmd)
	parentCmd.AddCommand(authCmd)
}

func addLogin(parentCmd *cobra.Command) {
	opts := &authOptions{}
	authCmd := &cobra.Command{
		Short:         "Log the SLSA sourcetool into GitHub",
		Use:           "login",
		SilenceUsage:  false,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.Validate(); err != nil {
				return fmt.Errorf("validating options: %w", err)
			}

			fmt.Println()
			for _, l := range logo {
				fmt.Println("       " + o(l))
			}
			fmt.Println()

			authn := auth.New()
			if err := authn.Authenticate(); err != nil {
				return err
			}
			return nil
		},
	}
	opts.AddFlags(authCmd)
	parentCmd.AddCommand(authCmd)
}

func addWhoAmI(parentCmd *cobra.Command) {
	authCmd := &cobra.Command{
		Short:         "Shows the user currently logged in",
		Use:           "whoami",
		SilenceUsage:  false,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println()

			me, err := auth.New().WhoAmI()
			if err != nil {
				return err
			}

			if me == nil {
				fmt.Println("🟡 sourcetool is not currently logged in")
				fmt.Println("")
				fmt.Println("To authorize the app run:")
				fmt.Println("> sourcetool auth login")
				return nil
			}

			fmt.Printf("        👤 logged in as %s\n\n", me.GetLogin())

			// token, err := auth.ReadToken()
			// if err != nil {
			// 	return err
			// }
			// _, err = git.PlainClone("/tmp/clone", &git.CloneOptions{
			// 	// The intended use of a GitHub personal access token is in replace of your password
			// 	// because access tokens can easily be revoked.
			// 	// https://help.github.com/articles/creating-a-personal-access-token-for-the-command-line/
			// 	Auth: &http.BasicAuth{
			// 		Username: "abc123", // yes, this can be anything except an empty string
			// 		Password: token,
			// 	},
			// 	URL:      "https://github.com/puerco/hades.git",
			// 	Progress: os.Stdout,
			// })

			return err
		},
	}
	parentCmd.AddCommand(authCmd)
}
