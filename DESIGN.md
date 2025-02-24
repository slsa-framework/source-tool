# Design

Document the design of this proof-of-concept implementation of the SLSA Source Track
using GitHub's existing functionality.

## Basics

* Users create a [policy](#policy) for the repo & branches they want to protect,
  indicating their desired SLSA level. 
* Users call the .github/workflows/slsa_with_provenance.yml reusable workflow on any
  `push` changes to protected branches.
* The slsa_with_provenance workflow gets the attestations, if any, for the prior
  commit.
* The slsa_with_provenance workflow evaluates their controls, the current commit, and
  prior attestations, to determine the SLSA Source level of the current commit.
* A VSA, 'source provenance', are created within the workflow, and
  are stored in [git notes](https://git-scm.com/docs/git-notes) for the current commit.
* Downstream users can get the VSA for the revision they're consuming by getting the
  git notes for that revision.

## SLSA Requirements

For detailed information on how this tool meets the SLSA requirements see
[POLICY.md](./POLICY.md).

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

In the control-only approach the `sourcetool` with the `checklevel` command fetches the
rulesets that are _currently_ enabled on the source repository.

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

1. Our trust in the reusable workflow to only execute for commits that have just
   been pushed to a protected branch.
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

In the provenance based approach the reusable workflow fetches any attestations from the
commit prior to the current commit.

These attestations are provided to the `sourcetool` `checklevelprov` command which then:

1. Computes the level the current commit is eligible for based on the same approach taken
   by [control-only](#control-only).  Sets the control start time to ~now (it does _not_
   use the start time reported by the
   [Get Rules for Branch](https://docs.github.com/rest/repos/rules#get-rules-for-a-branch)
   API).
2. Checks to see if [source provenance](#source-provenance) for the prior commit is
   available in the bundle of attestations provided by reusable workflow.
3. If source provenance is available, checks if the previous provenance met the same level
   as the current commit.  If so, it updates the control start time to the start time
   recorded in the previous provenance.
4. Checks the [policy](#policy) to see if the control start time is at least as old as the
   `Since` time recorded in the policy.

The declared level will then be stored in a source VSA and a new source provenance.
Both will be signed by the reusable workflow and stored in the associated git note.

The can be thought of as a memoized recursive algorithm that would look something like:

```python
def getSourceLevel(commit, policy):
    controlLevel = determineControlLevel(commit, policy)
    prevCommit = getPrevCommit(commit)
    # We stop recursing if there are no more commits, or if
    # the previous commit occurred prior when the policy went
    # into effect.
    if prevCommit == null or isCommitBeforePolicyStart(prevCommit, policy):
        # Base case
        return controlLevel
    # We know the current commit has controlLevel, but we want
    # to make sure prior commits had at least that level too.
    return MIN(controlLevel, getSourceLevel(prevCommit, policy))
```

#### Auditing

While the reusable workflow only ever checks the attestations for the prior commit,
'offline' auditors might wish to evaluate the entire chain of provenance from the most
recent commit, all the way back to the first commit made under the existing policy.

## Source Provenance

Source provenance indicates:

1. The commit the data applies to
2. The commit prior to this one
3. When each of some set of controls (properties) started being enforced.
4. The actor that pushed the commit.
5. The branch the commit was pushed to.
6. When the commit was pushed.
7. The activity type that triggered the push.
8. The uri of the repo the activity occurred in.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "digest": {
        "gitCommit": "6efc0a710cb413aa4aa2d53ad75411a599fb2db1"
      }
    }
  ],
  "predicateType": "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1",
  "predicate": {
    "activity_type": "pr_merge",
    "actor": "TomHennen",
    "branch": "refs/heads/main",
    "created_on": "2025-02-24T16:14:11.497058337Z",
    "prev_commit": "a552404f404933e685daa6f1d189127cef49aa90",
    "properties": {
      "SLSA_SOURCE_LEVEL_3": {
        "since": "2025-02-24T15:24:23.245811209Z"
      }
    },
    "repo_uri": "https://github.com/slsa-framework/slsa-source-poc"
  }
}
```

## Policy

This PoC uses user supplied 'policy' files (stored in a public git repo outside of user
control) to indicate what controls _ought_ to be enforced and when that enforcement should
start.

This is used to prevent users from disabling controls, making changes, and reenabling the
controls.  Now, if a user wanted to do so they'd also have to update their 'Since' date
in their policy, and have that change submitted to the policy repo.  The updated date
would then not cover the uncontrolled changes they made.

This amounts to public declaration of SLSA adoption and allows backsliding to be detected.

```json
{
  "canonical_repo": "https://github.com/slsa-framework/slsa-source-poc",
  "protected_branches": [
    {
      "Name": "main",
      "Since": "2025-02-28T15:09:27.845Z",
      "target_slsa_source_level": "SLSA_SOURCE_LEVEL_2"
    }
  ]
}
```

## Attestation Storage

Attestations are stored on commits using [git notes](https://git-scm.com/docs/git-notes)
where each line of the note is a separate signed attestation. (E.g. the note is an
[in-toto bundle](https://github.com/in-toto/attestation/blob/main/spec/v1/bundle.md)).

## Reusable workflow

This PoC relies heavily on the security properties of GitHub Actions reusable workflows.
It assumes callers cannot influence the decisions it makes beyond the limited inputs
they provide when calling it.

Specifically, the reusable workflow provides the following guarantees:

1. It serves as the identity used to sign attestations, allowing us to know the
   attestations were produced by _this_ workflow, and not by the user.
2. It provides the previous commit to the `sourcetool` establishing the link
   between it and the current commit.  E.g. it allows us to trust that the
   current commit listed in the source provenance is a direct descendant of
   the listed previous commit.  This allows us to establish continuity.
3. It lets us ensure the provenance was created contemporaneously with the
   introduction of the current commit to the current branch.

## Open Issues

### Dealing with reliability

This tool currently assumes that if a previous provenance cannot be found that
it should assume this is the first time it's run and bootstrap a new provenance
with a new start time.

If this new provenance conflicts with an existing policy then the evaluation
will result in a failed verification or a level 1 verification because it
assumes a missing provenance indicates a control was disabled or evaded.

However, especially as changes are being made, the tool or reusable workflow
may fail, resulting in a missing provenance.  This does not necessarily mean
the control was evaded, but it is hard to distinguish the two cases.

One way to handle this might be to put more trust in the control duration
provided by the GitHub APIs.  This would allow _some_ gaps in provenance to be
filled as long as the controls weren't modified during that period.
Unfortunately, this does not seem especially satisfying.  For now the tool
is quite strict and will interpret any gap as a control gap, requiring the
policy to be updated.
