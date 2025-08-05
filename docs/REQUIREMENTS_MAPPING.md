# SLSA Source PoC - Requirements Mapping

This file describes how this tool comes to a conclusion about what SLSA Source
Level a given commit meets.

It is currently written based on the
[SLSA Source Track v1.2-RC1 requirements](https://slsa.dev/spec/v1.2-rc1/source-requirements)
as of June 21, 2025.

## Organization Requirements

These requirements are primarily for the organization that is producing the
source code. `source-tool` helps organizations meet these
requirements when using GitHub as their Source Control System (SCS).

### [Choose an appropriate source control system](https://slsa.dev/spec/v1.2-rc1/source-requirements#choose-scs)

**Required for: SLSA Source Level 1+**

This requirement is for the organization to select an SCS that can meet their
desired SLSA Source Level. `source-tool` is designed specifically
for organizations using **GitHub**.

### [Protect consumable branches and tags](https://slsa.dev/spec/v1.2-rc1/source-requirements#protect-consumable-branches-and-tags)

**Required for: SLSA Source Level 2+**

The SLSA source tool is designed around this principle.

- **Policy:** Users define a
  [policy file](DESIGN.md#policy)
  to specify which branches are protected and what their target SLSA level is.
  The policy also allows for specifying which tags should be protected.
- **Identity Management:** The tool relies on GitHub's built-in
  [identity management](https://docs.github.com/en/get-started/learning-about-github/types-of-github-accounts#user-accounts)
  to configure which actors can perform sensitive actions.
- **Technical Controls:** The tool enforces technical controls via GitHub's
  [rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository).
  [DESIGN.md](DESIGN.md)
  outlines several controls such as `CONTINUITY_ENFORCED`, `REVIEW_ENFORCED`,
  `TAG_HYGIENE`, and custom `GH_REQUIRED_CHECK_*` controls that map to
  organization-defined checks. These are included in the generated VSAs as
  `ORG_SOURCE_*` properties.

### [Safe Expunging Process](https://slsa.dev/spec/v1.2-rc1/source-requirements#safe-expunging-process)

**Required for: SLSA Source Level 2+**

The SLSA source tool does not provide a technical enforcement mechanism
for a safe expunging process. However, it recommends a process based on GitHub's
features:

- **Bypass List:** Organizations can use the
  [bypass list](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository#granting-bypass-permissions-for-your-branch-or-tag-ruleset)
  feature of rulesets to allow a specific, trusted role (e.g., 'safe-expunging')
  to perform these operations.
- **Dedicated Accounts:** The accounts associated with this role should be used
  exclusively for this purpose and not for day-to-day development.

**Gap:** There is no technical enforcement to ensure that the bypass list is
used only for safe expunging. This relies on organizational process.

## Source Control System Requirements

These requirements are for the Source Control System itself. `source-tool`
leverages GitHub's capabilities to meet these requirements.

### [Repositories are uniquely identifiable](https://slsa.dev/spec/v1.2-rc1/source-requirements#repository-ids)

**Required for: SLSA Source Level 1+**

The tool works with **GitHub repositories**, which are uniquely identified by
their URL (e.g., `https://github.com/slsa-framework/source-tool`).

### [Revisions are immutable and uniquely identifiable](https://slsa.dev/spec/v1.2-rc1/source-requirements#revision-ids)

**Required for: SLSA Source Level 1+**

The tool attests to **git commits**, which are inherently immutable and uniquely
identified by their commit hash.

### [Source Verification Summary Attestations](https://slsa.dev/spec/v1.2-rc1/source-requirements#source-summary)

**Required for: SLSA Source Level 1+**

The SLSA Source tool generates
[Verification Summary Attestations (VSAs)](DESIGN.md#verification-summary-attestations-vsa)
for each commit on a protected branch. These VSAs indicate the SLSA Source Level
of the revision. The tool uses its generated
[source provenance](#source-provenance) to issue these VSAs for Level 3 and
above. The VSAs are stored in `git notes`, making them accessible to anyone who
can access the revision.

### [Protected Branches](https://slsa.dev/spec/v1.2-rc1/source-requirements#branches)

**Required for: SLSA Source Level 2+**

The tool requires users to specify protected branches in the
[policy file](DESIGN.md#policy).
The tool's logic for determining SLSA levels is then applied to these branches.

### [History](https://slsa.dev/spec/v1.2-rc1/source-requirements#history)

**Required for: SLSA Source Level 2+**

The tool relies on GitHub's branch protection rules to preserve the history of
protected branches. Specifically, the `CONTINUITY_ENFORCED` control checks for
the `deletion` and `non_fast_forward` rules to be active. This prevents
tampering with the history of protected branches.

### [Enforced change management process](https://slsa.dev/spec/v1.2-rc1/source-requirements#enforced-change-management-process)

**Required for: SLSA Source Level 2+**

`source-tool` tool enforces the change management process through a
combination of its policy file and GitHub's rulesets.

- The tool checks for the enforcement of specific rules on protected branches.
- The policy file can specify required status checks (e.g., unit tests), which
  are then included in the generated provenance as
  `GH_REQUIRED_CHECK_<check name>` and the VSA as the corresponding
  `ORG_SOURCE_*` properties.
- The tool allows for the distribution of additional attestations by storing
  them in `git notes` alongside the VSA and source provenance.

### [Continuity](https://slsa.dev/spec/v1.2-rc1/source-requirements#continuity)

**Required for: SLSA Source Level 2+**

Continuity is a core concept in the `source-tool` design.

- The `CONTINUITY_ENFORCED` control ensures that history protection rules are
  continuously enforced.
- The
  [provenance-based approach](DESIGN.md#provenance-based)
  is designed to track continuity of controls from one commit to the next. If a
  prior commit's provenance shows the same level of control, the start time of
  that control is carried forward. This ensures that there are no gaps in
  control enforcement.

### [Protected Tags](https://slsa.dev/spec/v1.2-rc1/source-requirements#protected-tags)

**Required for: SLSA Source Level 2+**

The tool has a `TAG_HYGIENE` control which checks that the repository has rules
to prevent the update or deletion of tags. The policy file can be configured to
require this for a given SLSA level.

**Gap:** The tool does not yet support protecting only a subset of tags; the
`tag_hygiene` setting applies to all tags. This is tracked in
[issue #129](https://github.com/slsa-framework/source-tool/issues/129).

### [Identity Management](https://slsa.dev/spec/v1.2-rc1/source-requirements#identity-management)

**Required for: SLSA Source Level 2+**

The tool relies on **GitHub's built-in user management** and authentication
system. The actors who perform actions are identified and authorized based on
their GitHub user accounts.

### [Source Provenance](https://slsa.dev/spec/v1.2-rc1/source-requirements#source-provenance)

**Required for: SLSA Source Level 3+**

For Level 3, `source-tool` creates **source provenance attestations** for each
push to a protected branch. The
[design document](DESIGN.md#source-provenance)
specifies the format of these attestations, which include the actor, the current
and previous commits, the controls in place, and timestamps.

This provenance is generated contemporaneously with the branch update by a
reusable GitHub Actions workflow.

The provenance attestations are stored in git notes, making them accessible to
anyone who can access the revision.

### [Two party review](https://slsa.dev/spec/v1.2-rc1/source-requirements#two-party-review)

**Required for: SLSA Source Level 4**

For Level 4, `source-tool` has a `REVIEW_ENFORCED` control. This control checks
that the repository is configured to:

- Require Pull Requests.
- Require at least one approval.
- Dismiss stale approvals when new commits are pushed.
- Require review from Code Owners.
- Require approval of the most recent reviewable push.

These checks are intended to meet the two-party review requirement.
