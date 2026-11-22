// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate
package models

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	vpb "github.com/in-toto/attestation/go/predicates/vsa/v1"
	attestation "github.com/in-toto/attestation/go/v1"

	"github.com/slsa-framework/source-tool/pkg/provenance"
	"github.com/slsa-framework/source-tool/pkg/slsa"
)

var (
	ErrProtectionAlreadyInPlace = errors.New("controls already in place in the repository")
	ErrRepositoryAccessDenied   = errors.New("access to repository denied")
)

// AttestationStorageReader abstracts an attestation storage system where
// sourcetool can read VSAs and provenance attestations.
// For now we only have retrieval functions but this may expand to
// store statements as well if we need to.
//
//counterfeiter:generate . AttestationStorageReader
type AttestationStorageReader interface {
	GetCommitVsa(context.Context, *Branch, *Commit) (*attestation.Statement, *vpb.VerificationSummary, error)
	GetCommitProvenance(context.Context, *Branch, *Commit) (*attestation.Statement, *provenance.SourceProvenancePred, error)
}

// VcsBackend abstracts a VCS or VCS hosting system that sourcetool
// can inspect for SLSA controls.
//
//counterfeiter:generate . VcsBackend
type VcsBackend interface {
	GetBranchControls(context.Context, *Branch) (*slsa.ControlSet, error)
	GetBranchControlsAtCommit(context.Context, *Branch, *Commit) (*slsa.ControlSet, error)
	GetTagControls(context.Context, *Branch, *Tag) (*slsa.ControlSet, error)
	ControlConfigurationDescr(*Branch, ControlConfiguration) string
	ConfigureControls(*Repository, []*Branch, []ControlConfiguration) error
	GetLatestCommit(context.Context, *Repository, *Branch) (*Commit, error)
	ControlPrecheck(*Repository, []*Branch, ControlConfiguration) (bool, string, ControlPreRemediationFn, error)
	GetPreviousCommit(context.Context, *Branch, *Commit) (*Commit, error)
	GetDefaultBranch(context.Context, *Repository) (*Branch, error)
	GetRevisionCommit(context.Context, *Repository, Revision) (*Commit, error)
	FindProvenanceWorkflows(context.Context, *Branch) ([]*ProvenanceWorkflow, error)
}

type BackendOptions struct {
	AllowMergeCommits bool
	DriverOptions     any
}

// ControlPreRemediation is a function returned by the VCS backends
// when checking for prerequisites that the user may optionally run
type ControlPreRemediationFn func() (string, error)

type ControlConfiguration string

const (
	CONFIG_POLICY         ControlConfiguration = "CONFIG_POLICY"
	CONFIG_GEN_PROVENANCE ControlConfiguration = "CONFIG_GEN_PROVENANCE"
	CONFIG_BRANCH_RULES   ControlConfiguration = "CONFIG_BRANCH_RULES"
	CONFIG_TAG_RULES      ControlConfiguration = "CONFIG_TAG_RULES"
)

// Digest algorithm names used in attestation subjects
const (
	DigestTypeGitCommit = "gitCommit"
	DigestTypeSha1      = "sha1"
)

type Commit struct {
	SHA     string
	Author  string
	Time    *time.Time
	Message string
}

// Both tags and branches must implement the reference interface
var (
	_ Reference = (*Branch)(nil)
	_ Reference = (*Tag)(nil)
	_ Revision  = (*Tag)(nil)
	_ Revision  = (*Commit)(nil)
)

type Revision interface {
	GetCommit() *Commit
}

type Reference interface {
	FullRef() string
	GetRepository() *Repository
	GetName() string
}

func (c *Commit) GetCommit() *Commit {
	return c
}

func (c *Commit) ToResourceDescriptor() *attestation.ResourceDescriptor {
	return &attestation.ResourceDescriptor{
		Digest: map[string]string{
			DigestTypeSha1: c.SHA, DigestTypeGitCommit: c.SHA,
		},
	}
}

type Branch struct {
	Name       string
	Repository *Repository
}

func (b *Branch) GetRepository() *Repository {
	return b.Repository
}

func (b *Branch) GetName() string {
	return b.Name
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
	Name       string
	Commit     *Commit
	Repository *Repository
}

func (t *Tag) GetName() string {
	return t.Name
}

func (t *Tag) GetRepository() *Repository {
	return t.Repository
}

func (t *Tag) GetCommit() *Commit {
	return t.Commit
}

func (t *Tag) FullRef() string {
	if t.Name == "" {
		return ""
	}
	return "refs/tags/" + t.Name
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

// GetHttpURL returns the URL of the pull request. It returns an empty string
// when the pull request does not have enough data to build it.
func (pr *PullRequest) GetHttpURL() string {
	if pr.Repo == nil || pr.Number == 0 {
		return ""
	}
	repoURL := pr.Repo.GetHttpURL()
	if repoURL == "" {
		return ""
	}
	return fmt.Sprintf("%s/pull/%d", repoURL, pr.Number)
}

// Reference returns the pull request URL or, when it cannot be built, its
// number.
func (pr *PullRequest) Reference() string {
	if u := pr.GetHttpURL(); u != "" {
		return u
	}
	return fmt.Sprintf("#%d", pr.Number)
}

// ControlConfigurationResult reports what was done when configuring a control.
type ControlConfigurationResult struct {
	// Config is the control configuration the result refers to.
	Config ControlConfiguration

	// Changed is true when configuring the control modified the repository
	// or opened a pull request. It is false when there was nothing to do.
	Changed bool

	// Message describes the outcome in a sentence that can be shown to users.
	Message string

	// PullRequest is the pull request that configures the control. It is set
	// both when the pull request was opened and when it was already open.
	PullRequest *PullRequest
}

// ControlConfigurationReporter is an optional interface that VCS backends can
// implement to report what they did when configuring the controls. Backends
// that do not implement it are driven through VcsBackend.ConfigureControls
// and produce no results.
type ControlConfigurationReporter interface {
	ConfigureControlsWithResults(*Repository, []*Branch, []ControlConfiguration) ([]*ControlConfigurationResult, error)
}

// ProvenanceWorkflow describes a CI workflow found in a repository that calls
// the SLSA source actions to generate provenance.
type ProvenanceWorkflow struct {
	// Path of the workflow file, relative to the repository root
	Path string

	// LegacyActionsRepos lists the deprecated repositories the workflow still
	// calls the SLSA actions from. When empty, the workflow calls the actions
	// from their current repository.
	LegacyActionsRepos []string

	// RecommendedAction describes how to bring the workflow up to date. It
	// is nil when the workflow does not need any changes.
	RecommendedAction *slsa.ControlRecommendedAction

	// LastRun is the most recent completed run of the workflow in the branch.
	// It is nil when the workflow has not run or when its runs could not
	// be read.
	LastRun *WorkflowRun
}

// IsFailing returns true when the most recent run of the workflow failed.
func (pw *ProvenanceWorkflow) IsFailing() bool {
	return pw.LastRun != nil && pw.LastRun.Failed()
}

// WorkflowRun describes a completed run of a CI workflow.
type WorkflowRun struct {
	// Conclusion is the result of the run as reported by the CI system,
	// for example "success" or "failure".
	Conclusion string

	// URL is the address where the run can be inspected.
	URL string

	// Commit is the digest of the commit the workflow ran on.
	Commit string

	// Time is when the run was created.
	Time *time.Time
}

// Failed returns true when the run finished with an error. Runs that were
// cancelled or skipped are not considered failures.
func (wr *WorkflowRun) Failed() bool {
	switch wr.Conclusion {
	case "failure", "timed_out", "startup_failure":
		return true
	default:
		return false
	}
}

// IsLegacy returns true when the workflow calls the SLSA actions from a
// deprecated repository.
func (pw *ProvenanceWorkflow) IsLegacy() bool {
	return len(pw.LegacyActionsRepos) > 0
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
