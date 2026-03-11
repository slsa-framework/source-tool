// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

package sourcetool

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/carabiner-dev/collector"
	cgithub "github.com/carabiner-dev/collector/repository/github"
	"github.com/carabiner-dev/collector/repository/note"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/slsa-framework/source-tool/pkg/attest"
	"github.com/slsa-framework/source-tool/pkg/auth"
	"github.com/slsa-framework/source-tool/pkg/policy"
	"github.com/slsa-framework/source-tool/pkg/slsa"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/backends/vcs/github"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/models"
	"github.com/slsa-framework/source-tool/pkg/sourcetool/options"
)

var ControlConfigurations = []models.ControlConfiguration{
	models.CONFIG_POLICY, models.CONFIG_GEN_PROVENANCE, models.CONFIG_BRANCH_RULES, models.CONFIG_TAG_RULES,
}

// New initializes a new source tool instance.
func New(funcs ...ConfigFn) (*Tool, error) {
	t := &Tool{
		Options: options.Default,
		impl:    &defaultToolImplementation{},
	}

	for _, f := range funcs {
		if err := f(t); err != nil {
			return nil, err
		}
	}

	t.backend = github.New(&t.Options.BackendOptions)

	// Create the tool's attester
	attester, err := attest.NewAttester(
		attest.WithVerifier(attest.GetDefaultVerifier()),
		attest.WithBackend(t.backend),
		attest.WithGithubCollector(t.Options.InitGHCollector),
		attest.WithNotesCollector(t.Options.InitNotesCollector),
		attest.WithAuthenticator(t.Authenticator),
	)
	if err != nil {
		return nil, fmt.Errorf("creating attester: %w", err)
	}

	t.attester = attester

	return t, nil
}

// Tool is the main object intended to expose sourcetool's functionality as a
// public API. Some of the logic is still implemented on the CLI commands but
// we want to slowly move it to public function under this struct.
type Tool struct {
	Authenticator *auth.Authenticator
	attester      *attest.Attester
	backend       models.VcsBackend
	Options       options.Options
	impl          toolImplementation
}

// GetRepoControls returns the controls that are enabled in a repository branch.
func (t *Tool) GetBranchControls(ctx context.Context, branch *models.Branch) (*slsa.ControlSet, error) {
	if branch.Repository == nil {
		return nil, fmt.Errorf("repositoryu not specified in branch")
	}

	// Get the control status in the branch. Backends are expected to
	// return the full SLSA Source control catalog
	controls, err := t.impl.GetBranchControls(ctx, t.backend, branch)
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	// We also abstract the repository policy as a control to report its status
	status, err := t.impl.GetPolicyStatus(ctx, t.Authenticator, &t.Options, branch.Repository)
	if err != nil {
		return nil, fmt.Errorf("reading policy status: %w", err)
	}

	controls.Controls = append(controls.Controls, status)

	return controls, err
}

// GetRepoControls returns the controls that are enabled in a repository branch.
func (t *Tool) GetBranchControlsAtCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*slsa.ControlSet, error) {
	if branch.Repository == nil {
		return nil, fmt.Errorf("repositoryu not specified in branch")
	}

	// Get the control status in the branch. Backends are expected to
	// return the full SLSA Source control catalog
	controls, err := t.impl.GetBranchControlsAtCommit(ctx, t.backend, branch, commit)
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	// We also abstract the repository policy as a control to report its status
	status, err := t.impl.GetPolicyStatus(ctx, t.Authenticator, &t.Options, branch.Repository)
	if err != nil {
		return nil, fmt.Errorf("reading policy status: %w", err)
	}

	controls.Controls = append(controls.Controls, status)

	return controls, err
}

// OnboardRepository configures a repository to set up the required controls
// to meet SLSA Source L3.
func (t *Tool) OnboardRepository(ctx context.Context, repo *models.Repository, branches []*models.Branch) error {
	if err := t.impl.VerifyOptionsForFullOnboard(t.Authenticator, &t.Options); err != nil {
		return fmt.Errorf("verifying options: %w", err)
	}

	if err := t.backend.ConfigureControls(
		repo, branches, []models.ControlConfiguration{
			models.CONFIG_BRANCH_RULES, models.CONFIG_GEN_PROVENANCE, models.CONFIG_TAG_RULES,
		},
	); err != nil {
		return fmt.Errorf("configuring controls: %w", err)
	}

	return nil
}

// ConfigureControls sets up a control in the repo
func (t *Tool) ConfigureControls(ctx context.Context, repo *models.Repository, branches []*models.Branch, configs []models.ControlConfiguration) error {
	// The policy configuration is not handled by the backend
	if slices.Contains(configs, models.CONFIG_POLICY) {
		if err := t.impl.CheckPolicyFork(&t.Options); err != nil {
			return fmt.Errorf("checking policy repo fork: %w", err)
		}

		// Build the policy here:
		pcy, err := t.CreateBranchPolicy(ctx, repo, branches)
		if err != nil {
			return fmt.Errorf("creating policy for: %w", err)
		}

		if _, err := t.impl.CreatePolicyPR(t.Authenticator, &t.Options, repo, pcy); err != nil {
			return fmt.Errorf("opening the policy pull request: %w", err)
		}
	}

	return t.impl.ConfigureControls(t.backend, repo, branches, configs)
}

// ControlConfigurationDescr returns a description of the controls
func (t *Tool) ControlConfigurationDescr(branch *models.Branch, config models.ControlConfiguration) string {
	return t.backend.ControlConfigurationDescr(branch, config)
}

func (t *Tool) FindPolicyPR(ctx context.Context, repo *models.Repository) (*models.PullRequest, error) {
	policyRepoOwner := policy.SourcePolicyRepoOwner
	policyRepoRepo := policy.SourcePolicyRepo
	o, r, ok := strings.Cut(t.Options.PolicyRepo, "/")
	if ok {
		policyRepoOwner = o
		policyRepoRepo = r
	}

	pr, err := t.impl.SearchPullRequest(ctx, t.Authenticator, &models.Repository{
		Hostname: "github.com",
		Path:     fmt.Sprintf("%s/%s", policyRepoOwner, policyRepoRepo),
	}, fmt.Sprintf("Add %s SLSA Source policy file", repo.Path))
	if err != nil {
		return nil, fmt.Errorf("searching for policy pull request: %w", err)
	}

	return pr, nil
}

// CheckPolicyRepoFork checks that the logged in user has a fork
// of the configured policy repo.
func (t *Tool) CheckPolicyRepoFork(_ context.Context) (bool, error) {
	if err := t.impl.CheckPolicyFork(&t.Options); err != nil {
		if strings.Contains(err.Error(), "404 Not Found") {
			return false, nil
		}
		if strings.Contains(err.Error(), "oes not have a fork of") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// CreateBranchPolicy creates a repository policy
func (t *Tool) CreateBranchPolicy(ctx context.Context, r *models.Repository, branches []*models.Branch) (*policy.RepoPolicy, error) {
	if len(branches) > 1 {
		// Change this once we support merging policies
		return nil, fmt.Errorf("only one branch is supported at a time")
	}
	if branches == nil {
		return nil, errors.New("no branches defined")
	}

	controls, err := t.impl.GetBranchControls(ctx, t.backend, branches[0])
	if err != nil {
		return nil, fmt.Errorf("getting branch controls: %w", err)
	}

	return t.createPolicy(r, branches[0], controls)
}

// This function will be moved to the policy package once we start integrating
// it with the global data models (if we do).
func (t *Tool) createPolicy(r *models.Repository, branch *models.Branch, controls *slsa.ControlSet) (*policy.RepoPolicy, error) {
	// Default to SLSA1 since unset date
	eligibleSince := &time.Time{}
	eligibleLevel := slsa.SlsaSourceLevel1

	var err error
	// Unless there is previous provenance metadata, then we can compute
	// a higher level
	if controls != nil {
		eligibleLevel = policy.ComputeEligibleSlsaLevel(controls.GetActiveControls())
		eligibleSince, err = policy.ComputeEligibleSince(controls.GetActiveControls(), eligibleLevel)
		if err != nil {
			return nil, fmt.Errorf("could not compute eligible_since: %w", err)
		}
	}

	p := &policy.RepoPolicy{
		CanonicalRepo: r.GetHttpURL(),
		ProtectedBranches: []*policy.ProtectedBranch{
			{
				Name:                  branch.Name,
				Since:                 timestamppb.New(*eligibleSince),
				TargetSlsaSourceLevel: string(eligibleLevel),
			},
		},
	}

	// If the controls returned
	tagHygiene := controls.GetActiveControls().GetControl(slsa.SLSA_SOURCE_SCS_PROTECTED_REFS)
	if tagHygiene != nil {
		p.ProtectedTag = &policy.ProtectedTag{
			Since:      timestamppb.New(*tagHygiene.GetSince()),
			TagHygiene: true,
		}
	}
	return p, nil
}

// GetRepositoryPolicy retrieves the policy of repo from the community
func (t *Tool) GetRepositoryPolicy(ctx context.Context, r *models.Repository) (*policy.RepoPolicy, error) {
	pe := policy.NewPolicyEvaluator()
	p, _, err := pe.GetPolicy(ctx, r)
	if err != nil {
		return nil, fmt.Errorf("getting repository policy: %w", err)
	}

	return p, nil
}

// CreateRepositoryPolicy creates a policy for a repository
func (t *Tool) CreateRepositoryPolicy(ctx context.Context, r *models.Repository, branches []*models.Branch) (*policy.RepoPolicy, *models.PullRequest, error) {
	pcy, err := t.CreateBranchPolicy(ctx, r, branches)
	if err != nil {
		return nil, nil, fmt.Errorf("creating policy for: %w", err)
	}

	var pr *models.PullRequest

	// If the option is set, open the pull request
	if t.Options.CreatePolicyPR {
		pr, err = t.impl.CreatePolicyPR(t.Authenticator, &t.Options, r, pcy)
		if err != nil {
			return nil, nil, fmt.Errorf("opening the policy pull request: %w", err)
		}
	}
	return pcy, pr, nil
}

// CreatePolicyRepoFork creates a fork of the policy repository in the user's GitHub org
func (t *Tool) CreatePolicyRepoFork(ctx context.Context) error {
	err := t.impl.CreateRepositoryFork(ctx, t.Authenticator, &models.Repository{
		Path: t.Options.PolicyRepo,
	}, "")
	if err != nil {
		return fmt.Errorf("creating policy repo fork: %w", err)
	}
	return nil
}

// ControlPrecheck performs a prerequisite check before enabling a contrlol
// Backend may optionally return a remediation function to correct the
// prerequisite which the CLI can before attempting to enable the control.
func (t *Tool) ControlPrecheck(
	_ context.Context, r *models.Repository, branches []*models.Branch, config models.ControlConfiguration,
) (ok bool, remediationMessage string, remediateFn models.ControlPreRemediationFn, err error) {
	return t.backend.ControlPrecheck(r, branches, config)
}

// Attester returns an attester object with the tool configuration
func (t *Tool) Attester() *attest.Attester {
	return t.attester
}

// Backend returns the VCS backend
func (t *Tool) Backend() models.VcsBackend {
	return t.backend
}

// GetPreviousCommit returns the previous commit of the passed commit
func (t *Tool) GetPreviousCommit(ctx context.Context, branch *models.Branch, commit *models.Commit) (*models.Commit, error) {
	return t.backend.GetPreviousCommit(ctx, branch, commit)
}

type AttestOptions struct {
	LocalPolicy string
	Sign        bool
	OutputPath  string
	UseStdOut   bool
	Push        bool
}

type AttOpFn func(*AttestOptions) error

func WithLocalPolicy(p string) AttOpFn {
	return func(ao *AttestOptions) error {
		ao.LocalPolicy = p
		return nil
	}
}

func WithSign(s bool) AttOpFn {
	return func(ao *AttestOptions) error {
		ao.Sign = s
		return nil
	}
}

func WithOutputPath(p string) AttOpFn {
	return func(ao *AttestOptions) error {
		ao.OutputPath = p
		return nil
	}
}

func WithUseStdout(s bool) AttOpFn {
	return func(ao *AttestOptions) error {
		ao.UseStdOut = s
		return nil
	}
}

func WithPush(s bool) AttOpFn {
	return func(ao *AttestOptions) error {
		ao.Push = s
		return nil
	}
}

var defaultAttestOptions = AttestOptions{
	Sign:      true,
	UseStdOut: true,
}

// AttestCommit checks the source control system status, the repository policy
// and generates the repository attestations (provenance & VSA).
func (t *Tool) AttestCommit(ctx context.Context, branch *models.Branch, commit *models.Commit, funcs ...AttOpFn) error {
	var agent *collector.Agent
	var err error

	// Initialize the attest options
	opts := defaultAttestOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return err
		}
	}

	// Create the agent if we are pushing
	if opts.Push {
		agent, err = t.getAttestationStore(branch)
		if err != nil {
			return fmt.Errorf("unable to intitializer storate agent: %w", err)
		}
	}

	// Create the provenance attestation
	prov, err := t.Attester().CreateSourceProvenance(ctx, branch, commit)
	if err != nil {
		return err
	}

	// check p against policy
	pe := policy.NewPolicyEvaluator()
	pe.UseLocalPolicy = opts.LocalPolicy
	verifiedLevels, policyPath, err := pe.EvaluateSourceProv(ctx, branch.Repository, branch, prov)
	if err != nil {
		return err
	}

	var vsaData string
	var provenanceData []byte

	// create vsa
	vsaData, err = attest.CreateUnsignedSourceVsa(
		branch, commit, verifiedLevels, policyPath,
	)
	if err != nil {
		return fmt.Errorf("creating VSA: %w", err)
	}

	provenanceData, err = protojson.Marshal(prov)
	if err != nil {
		return fmt.Errorf("generating provenance attestation: %w", err)
	}

	if opts.Sign {
		provenanceDataString, err := attest.Sign(string(provenanceData))
		if err != nil {
			return err
		}
		provenanceData = []byte(provenanceDataString)

		vsaData, err = attest.Sign(vsaData)
		if err != nil {
			return err
		}
	}

	if opts.UseStdOut {
		fmt.Printf("%s\n%s\n", string(provenanceData), vsaData)
	}

	fpath := opts.OutputPath
	if fpath == "" {
		f, err := os.CreateTemp("", "attestations-")
		if err != nil {
			return fmt.Errorf("opening tmp file: %w", err)
		}
		f.Close() //nolint:errcheck,gosec
		fpath = f.Name()
	}

	defer func() {
		if opts.OutputPath == "" {
			os.Remove(fpath) //nolint:errcheck,gosec
		}
	}()

	if err := os.WriteFile(
		fpath, fmt.Appendf(nil, "%s\n%s\n", string(provenanceData), vsaData), os.FileMode(0o600),
	); err != nil {
		return fmt.Errorf("writing attestations: %w", err)
	}

	if opts.Push {
		if err := agent.StoreFromFiles(ctx, []string{fpath}); err != nil {
			return fmt.Errorf("pushing attestations: %w", err)
		}
	}

	if opts.OutputPath != "" {
		err = os.WriteFile(
			opts.OutputPath, fmt.Appendf(nil, "%s\n%s\n", string(provenanceData), vsaData), os.FileMode(0o600),
		)
	}
	return err
}

// getAttestationStore returns a collector with storer reposistories to push
// the generated attestations.
func (t *Tool) getAttestationStore(branch *models.Branch) (*collector.Agent, error) {
	if len(t.Options.StorageLocations) == 0 && !t.Options.InitGHStorer && !t.Options.InitNotesStorer {
		return nil, errors.New("no storage locations defined")
	}

	if t.Authenticator == nil {
		return nil, errors.New("tool has no authenticator configured")
	}

	token, err := t.Authenticator.ReadToken()
	if err != nil {
		return nil, fmt.Errorf("unable to read auth token: %w", err)
	}
	copts := []collector.InitFunction{}
	// Init GitHub storer
	if t.Options.InitGHStorer {
		ghrepo, err := cgithub.New(
			cgithub.WithRepo(branch.Repository.GetHttpURL()),
			cgithub.WithToken(token),
		)
		if err != nil {
			return nil, fmt.Errorf("initializing gitrhub repo: %w", err)
		}
		copts = append(copts, collector.WithRepository(ghrepo))
	}

	// Init commit notes storer
	if t.Options.InitNotesStorer {
		notesrepo, err := note.NewDynamic(
			note.WithLocator(branch.Repository.GetHttpURL()),
			note.WithHttpAuth("github", token),
			note.WithPush(true),
		)
		if err != nil {
			return nil, fmt.Errorf("initializing notes collector: %w", err)
		}
		copts = append(copts, collector.WithRepository(notesrepo))
	}

	// Retrurn the agent with the configured storers
	c, err := collector.New(copts...)
	if err != nil {
		return nil, fmt.Errorf("initializing storage agent: %w", err)
	}

	// Add any additional storage locations
	for _, str := range t.Options.StorageLocations {
		if err := c.AddRepositoryFromString(str); err != nil {
			return nil, fmt.Errorf("initializing repo %q: %w", str, err)
		}
	}
	return c, nil
}
