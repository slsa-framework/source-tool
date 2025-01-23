package main

import (
	"context"
	"flag"
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

	// TODO: Replace with command line args.
	var owner, repo, branch string
	flag.StringVar(&owner, "owner", "", "The GitHub repository owner - required.")
	flag.StringVar(&repo, "repo", "", "The GitHub repository name - required.")
	flag.StringVar(&branch, "branch", "", "The branch within the repository - required.")
	flag.Parse()

	if owner == "" || repo == "" || branch == "" {
		log.Fatal("Must set owner, repo, and branch flags.")
	}

	gh_client := github.NewClient(nil)
	ctx := context.Background()
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
