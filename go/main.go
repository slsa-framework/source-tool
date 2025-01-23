package main

import (
	"context"
	"fmt"
	"log"

	"github.com/google/go-github/v68/github"
)

const (
	SlsaSourceLevel1 = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2 = "SLSA_SOURCE_LEVEL_2"
)

// Determines the source level of a repo.
func main() {
	gh_client := github.NewClient(nil)

	ctx := context.Background()

	// TODO: Replace with command line args.
	owner := "TomHennen"
	repo := "slsa-source-poc"
	branch := "main"

	rules, _, err := gh_client.Repositories.GetRulesForBranch(ctx, owner, repo, branch)

	if err != nil {
		log.Fatal(err)
	}

	var deletionRule *github.RepositoryRule
	var nonFastFowardRule *github.RepositoryRule

	for _, rule := range rules {
		switch rule.Type {
		case "deletion":
			deletionRule = rule
		case "non_fast_forward":
			nonFastFowardRule = rule
		default:
			// ignore
		}
	}

	sourceLevel := SlsaSourceLevel1
	if deletionRule != nil && nonFastFowardRule != nil {
		sourceLevel = SlsaSourceLevel2
	}

	fmt.Print(sourceLevel)
}
