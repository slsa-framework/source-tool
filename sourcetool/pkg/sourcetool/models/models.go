//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
package models

import (
	"context"
	"fmt"
	"strings"
	"time"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	attestation "github.com/in-toto/attestation/go/v1"

	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/attest"
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

// AttestationStorageReader abstracts an attestation storage system where
// sourcetool can read VSAs and provenance attestations.
// For now we only have retrieval functions but this may expand to
// store statements as well if we need to.
//
//counterfeiter:generate . AttestationStorageReader
type AttestationStorageReader interface {
	GetCommitVsa(context.Context, *Branch, *Commit) (*attestation.Statement, *vpb.VerificationSummary, error)
	GetCommitProvenance(context.Context, *Branch, *Commit) (*attestation.Statement, *attest.SourceProvenancePred, error)
}

// VcsBackend abstracts a VCS or VCS hosting system that sourcetool
// can inspect for SLSA controls.
//
//counterfeiter:generate . VcsBackend
type VcsBackend interface {
	GetBranchControls(context.Context, *Repository, *Branch) (*slsa.ControlSetStatus, error)
	GetBranchControlsAtCommit(context.Context, *Repository, *Branch, *Commit) (*slsa.ControlSetStatus, error)
	GetTagControls(context.Context, *Tag) (*slsa.Controls, error)
	ControlConfigurationDescr(*Branch, ControlConfiguration) string
	ConfigureControls(*Repository, []*Branch, []ControlConfiguration) error
	GetLatestCommit(context.Context, *Repository, *Branch) (*Commit, error)
}

type ControlConfiguration string

const (
	CONFIG_POLICY         ControlConfiguration = "CONFIG_POLICY"
	CONFIG_GEN_PROVENANCE ControlConfiguration = "CONFIG_GEN_PROVENANCE"
	CONFIG_BRANCH_RULES   ControlConfiguration = "CONFIG_BRANCH_RULES"
)

type Commit struct {
	SHA    string
	Author string
	Time   *time.Time
}

type Branch struct {
	Name       string
	Repository *Repository
}

func (b *Branch) FullRef() string {
	return fmt.Sprintf("refs/heads/%s", b.Name)
}

type Repository struct {
	Hostname      string
	Path          string
	DefaultBranch string
}

func (r *Repository) GetHttpURL() string {
	if r.Hostname == "" || r.Path == "" {
		return ""
	}
	u := fmt.Sprintf("https://%s/%s", r.Hostname, r.Path)
	if r.Hostname == "github.com" {
		u += ".git"
	}
	return u
}

func (r *Repository) GetSshURL() string {
	if r.Hostname == "" || r.Path == "" {
		return ""
	}
	return fmt.Sprintf("git@%s:%s", r.Hostname, r.Path)
}

// parseRepoPath parses the owner and repo name from the repository path
func (r *Repository) PathAsGitHubOwnerName() (owner, name string, err error) {
	path := strings.TrimPrefix(r.Path, "/")
	path = strings.TrimSuffix(path, "/")
	owner, name, ok := strings.Cut(path, "/")
	if !ok {
		return "", "", fmt.Errorf("repository path not correctly formed: %q", path)
	}

	return owner, name, err
}

type Tag struct {
	Name   string
	Commit *Commit
}

// PullRequest models a GitHub pull request.
// If we need to use this outside of the repo.PullRequestManager and other
// GitHub-specific code we should model a ChangeRequest or similar interface
// to accommodate similar constructs, such as GitLab merge requests.
type PullRequest struct {
	Title  string
	Body   string
	Time   *time.Time
	Head   string
	Base   string // main
	Number int
	Repo   *Repository
}

// Actor abstracts a user. For now it is intended to model both entities
// that interact with a repository but also the user using sourcetool. At
// some point we may split both roles if we need to.
type Actor struct {
	Login string
}

// GetLogin returns the login string of the Actor
func (a *Actor) GetLogin() string {
	return a.Login
}
