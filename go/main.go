package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/go-github/v68/github"
)

const (
	SlsaSourceLevel1 = "SLSA_SOURCE_LEVEL_1"
	SlsaSourceLevel2 = "SLSA_SOURCE_LEVEL_2"
)

// Checks to see if the rule meets our requirements.
func checkRule(ctx context.Context, gh_client *github.Client, owner string, repo string, rule *github.RepositoryRule, minTime time.Time) (bool, error) {
	ruleset, _, err := gh_client.Repositories.GetRuleset(ctx, owner, repo, rule.RulesetID, false)
	if err != nil {
		return false, err
	}

	// We need rules to be 'active' and to have been updated no later than minTime.
	if ruleset.Enforcement != "active" {
		return false, nil
	}

	if minTime.Before(ruleset.UpdatedAt.Time) {
		return false, nil
	}

	return true, nil
}

func determineSourceLevel(ctx context.Context, gh_client *github.Client, owner string, repo string, branch string, minDays int) (string, error) {
	rules, _, err := gh_client.Repositories.GetRulesForBranch(ctx, owner, repo, branch)

	if err != nil {
		return "", err
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

	if deletionRule == nil && nonFastFowardRule == nil {
		// For L2 we need deletion and non-fast-forward rules.
		return SlsaSourceLevel1, nil
	}

	// We'd like to check that the rules have been enabled for the appropriate amount of time
	// (to ensure they weren't disabled).  For now we just require something that's not in
	// the future.
	minTime := time.Now().AddDate(0, 0, -1*minDays)

	deletionGood, err := checkRule(ctx, gh_client, owner, repo, deletionRule, minTime)
	if err != nil {
		return "", err
	}
	nonFFGood, err := checkRule(ctx, gh_client, owner, repo, nonFastFowardRule, minTime)
	if err != nil {
		return "", err
	}

	if deletionGood && nonFFGood {
		return SlsaSourceLevel2, nil
	}

	return SlsaSourceLevel1, nil
}

// Determines the source level of a repo.
func main() {
	var commit, owner, repo, branch, outputVsa string
	var minDays int
	flag.StringVar(&commit, "commit", "", "The commit to check.")
	flag.StringVar(&owner, "owner", "", "The GitHub repository owner - required.")
	flag.StringVar(&repo, "repo", "", "The GitHub repository name - required.")
	flag.StringVar(&branch, "branch", "", "The branch within the repository - required.")
	flag.IntVar(&minDays, "min_days", 1, "The minimum duration that the rules need to have been enabled for.")
	flag.StringVar(&outputVsa, "output_vsa", "", "The path to write a signed VSA with the determined level.")
	flag.Parse()

	if commit == "" || owner == "" || repo == "" || branch == "" {
		log.Fatal("Must set commit, owner, repo, and branch flags.")
	}

	gh_client := github.NewClient(nil)
	ctx := context.Background()

	sourceLevel, err := determineSourceLevel(ctx, gh_client, owner, repo, branch, minDays)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Print(sourceLevel)

	if outputVsa != "" {
		// This will output in the sigstore bundle format.
		signedVsa, err := createSignedSourceVsa(owner, repo, commit, sourceLevel)
		if err != nil {
			log.Fatal(err)
		}
		err = os.WriteFile(outputVsa, []byte(signedVsa), 0644)
		if err != nil {
			log.Fatal(err)
		}
	}
}
