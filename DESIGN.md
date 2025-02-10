# Design

Document the design of this proof-of-concept implementation of the SLSA Source Track
using GitHub's existing functionality.

## Basics

* Users create a [policy](#policy) for the repo & branches they want to protect,
  indicating their desired SLSA level. 
* Users call the .github/workflows/create_slsa_source_vsa.yml reusable workflow on any
  `push` changes to protected branches.
* The create_slsa_source_vsa workflow evaluates their controls, the current commit, and,
  in some cases, prior attestations, to determine the SLSA Source level of the current
  commit.
* A VSA, and potentially other attestations, are created within the workflow, and
  are stored in [git notes](https://git-scm.com/docs/git-notes) for the current commit.
* Downstream users can get the VSA for the revision they're consuming by getting the
  git notes for that revision.

## Approaches
There are two main approaches taken in this proof-of-concept:

1. A 'control only' approach that leverages GitHub's existing controls and APIs, and
maintains **no** state between commits.  This approach creates VSAs for each commit,
but does not reference them in the future.  The highest possible level that can be
achieved with this approach is SLSA_SOURCE_LEVEL_2.

2. A 'provenance based' approach that, in addition to creating a VSA for each commit,
creates a more detailed source provenance attestation that is referenced when computing
the SLSA Source Level of subsequent commits.

### Control-Only

In the control-only approach the `sourcetool` fetches the rulesets that are _currently_
enabled on the source repository.

If all of the following are true:

1. The commit was just made (enforced by the reusable workflow) OR the
   [list repositories activity](https://docs.github.com/en/rest/repos/repos?apiVersion=2022-11-28#list-repository-activities)
   indicates the commit was pushed while the existing ruleset was active.
2. The rulesets have both `deletion` and `non_fast_forward` rules actively enforced.
3. The [policy](#policy) has set a target level of `SLSA_SOURCE_LEVEL_2` for the branch AND
   the rulesets have been enforced no later than the `Since` time recorded in the policy

Then the revision will be declared `SLSA_SOURCE_LEVEL_2`.

If any of the above conditions are not met the revision will be declared
`SLSA_SOURCE_LEVEL_1`.

The declared level will then be stored in a source VSA, signed by the reusable workflow,
and stored in the associated git note.

#### Caveats

The security of the control only approach rests on:

1. Our trust in the `create_slsa_source_vsa` to only execute for commits that have just
   been pushed to a protected branch.
   TODO: This has not yet been implemmented!
2. Our trust in GitHub APIs to return trustworthy information.
3. That the 'bypass' list in the rules is not so large as to be meaningless.

The usability of the control-only approach is that if the user changes _any_ aspect of
their rules (even making them more strict), the `sourcetool` will determine the control
has only been in effect since the most recent change.  Thus a branch that has had controls
enabled for years, might suddenly appear as though controls were only recently adopted.

Users will need to update their [policy](#policy) to reflect the date of the most recent
change.  This could be addressed by updates to GitHub's API, but it can also be addressed
by the adoption of the [provenance-based](#provenance-based) approach.

### Provenance-Based

In the provenance based approach the reusable `create_slsa_source_vsa` workflow fetches
any attestations from the commit _prior_ to the current commit within the current context.

These attestations are provided to the `sourcetool` which then:

1. Computes the level the current commit is eligible for based on the same approach taken
   by [control-only](#control-only).  Sets the control start time to ~now.
2. Checks to see if [source provenance](#source-provenance) for the prior commit is
   available in the bundle of attestations provided by `create_slsa_source_vsa`.
3. If source provenance is available, checks if the previous provenance met the same level
   as the current commit.  If so, it updates the control start time to the start time
   recorded in the previous provenance.
4. Checks the [policy](#policy) to see if the control start time is at least as old as the
   `Since` time recorded in the policy.

The declared level will then be stored in a source VSA and a new source provenance.
Both will be signed by the reusable workflow and stored in the associated git note.

The can be thought of as a memoized recursive algorithm like:

```python
def getSourceProvenance(commit, attestations, controlStatus):
    prevCommit = getPrevCommit(commit)
    if prevCommit == null

```

## Source Provenance

## Policy

Use of `since` to prevent folks from disabling controls, making changes, and reenabling the
controls.

## Attestation Storage

## Security