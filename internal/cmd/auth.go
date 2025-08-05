// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/slsa-framework/source-tool/pkg/auth"
)

var colorHiRed = color.New(color.FgHiRed).SprintFunc()

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
	authCmd := &cobra.Command{
		Short:         "Log the SLSA sourcetool into GitHub",
		Use:           "login",
		SilenceUsage:  false,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println()
			for _, l := range logo {
				fmt.Println("       " + colorHiRed(l))
			}
			fmt.Println()

			authn := auth.New()

			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
			defer cancel()

			if err := authn.Authenticate(ctx); err != nil {
				return err
			}
			return nil
		},
	}
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
			return nil
		},
	}
	parentCmd.AddCommand(authCmd)
}
