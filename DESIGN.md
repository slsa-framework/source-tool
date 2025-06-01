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
[REQUIREMENTS_MAPPING.md](./REQUIREMENTS_MAPPING.md).

## Approach

This tool leverages GitHub's existing controls and APIs to determine what restrictions
are placed on the creation or update of branches and tags. It combines those controls
with provenance and VSAs which it generates when updates occur and with
[policy](#policy) which allows repositories to express their requirements for changes
to the repository.

The tool can be run in a 'control only' mode where it does not use provenance and as
a result can only reach Source Level 2.  This mode is only meant for demonstration
purposes and may be deprecated.

### Control-Only

TODO: Should we cut this section and feature?

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

In the provenance based approach the tool fetches any attestations from the commit prior
to the current commit and then:

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

## Controls

The tool can be configured to validate that a number of controls are (and have
remained) in place.

Each control name will be listed in the provenance `controls` field.

### CONTINUITY_ENFORCED

CONTINUITY_ENFORCED maps to the SLSA Source Track
[Branch Continuity](https://slsa.dev/spec/draft/source-requirements#branch-continuity:~:text=%E2%9C%93-,Branch%20Continuity,-It%20MUST%20NOT)
requirement.

This control is met if the commit was created or pushed when rulesets that have both
`deletion` and `non_fast_forward` rules actively enforced.

### PROVENANCE_AVAILABLE

PROVENANCE_AVAILABLE maps to the SLSA Source Track
[Source Provenance](https://slsa.dev/spec/draft/source-requirements#branch-continuity:~:text=%E2%9C%93-,Source%20Provenance,-Source%20Provenance%20are)
requirement.

This control is met if the commit has provenance associated with it.
 
### REVIEW_ENFORCED

REVIEW_ENFORCED maps to the SLSA Source Track
[Two party review](https://slsa.dev/spec/draft/source-requirements#branch-continuity:~:text=%E2%9C%93-,Two%20party%20review,-Changes%20in%20protected)
requirement.

This control is met if the repo:

1. Is configured to require the use of Pull Requests.
2. That the pull requests rule configures:
    * Required approvals = 1
    * "Dismiss stale pull request approvals when new commits are pushed"
    * "Require review from Code Owners"
    * "Require approval of the most recent reviewable push"

TODO: Provide a preconfigured ruleset under rulesets/

TODO: Update the policy to either require tag_immutability be set explicitly
or make it implicit if the policy is Level 3+.

### TAG_HYGIENE

TAG_HYGIENE maps to the SLSA Source Track
[Tag Hygiene](https://slsa.dev/spec/draft/source-requirements#branch-continuity:~:text=%E2%9C%93-,Tag%20Hygiene,-If%20the%20SCS)
requirement.

It checks that the repo enables the follow rules to ~ALL tags:

1. Doesn't allow tag updates
2. Doesn't allow tag deletions
3. Doesn't allow tag fast-forwards

Importing [rulesets/tag_hygiene.json](rulesets/tag_hygiene.json)
to a repos rulesets will enable the repo controls. The `tag_hygiene`
field in the policy then needs to be enabled too.

TODO: In the future this tool could be updated to allow some subset of tags
to be updated (e.g. `latest`, `nightly`), but that feature is not yet
supported. Tracked
[here](https://github.com/slsa-framework/slsa-source-poc/issues/129).

The tag hygiene control is evaluated for _both_ branch updates and tag updates.

### GH_REQUIRED_CHECK_*

Controls that start with `GH_REQUIRED_CHECK_` map to the
[Enforced change management process](https://slsa.dev/spec/draft/source-requirements#source-control-system:~:text=%E2%9C%93-,Enforced%20change%20management%20process,-The%20SCS%20MUST)
requirement.

It indicates that the repository has enabled the "Require status checks to
pass" rule for the indicated 'check'.

E.g. if the control `GH_REQUIRED_CHECK_unit-tests` appears in the provenance
then that means the repository has configured a ruleset to require the check
`unit-tests` to have been run by GitHub Actions prior to merge.

Currently this tool _only_ reports checks that come from GitHub Actions.
Other checks will not be recorded in the provenance.

TODO: Update the policy to support requiring these checks and to embed an
org specified property in the VSA.

#### Branch Updates

This control gets evaluated when protected branches are being updated. That
may seem strange (no tags were involved!), but the SLSA Source Track
requirements include Tag Hygiene as a requirement for Level 3. As a result
if we want to certify a given commit on a protected branch as Level 3,
then we need to ensure the _repository_ adheres to tag hygiene requirements.

#### Tag Updates

TODO: Update the policy to either require tag_hygiene be set explicitly or
make it implicit if the policy is Level 3+.

TODO: We should probably figure out if we want to issue tag prov or VSAs
if Tag Hygiene isn't enabled.

This control also gets evaluated when tags are updated.  When a tag is
updated, if policy sets 'tag_hygiene', the tool will require the control
is enabled.  If so, it will create [Tag Provenance](#tag-provenance) for
the tag and it will _copy_ the `verifiedLevels` from VSAs previously
issued for the commit being tagged into a new VSA that includes this
tag in `source_refs`.

## Provenance

### Source Provenance

Source provenance covers changes to a branch.  It indicates:

1. The commit the data applies to
2. The commit prior to this one
3. The set of controls that are enabled and when they started being enforced.
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
        "gitCommit": "473686ea1a02748311a0180af9b28a43e5513764"
      }
    }
  ],
  "predicateType": "https://github.com/slsa-framework/slsa-source-poc/source-provenance/v1-draft",
  "predicate": {
    "activity_type": "pr_merge",
    "actor": "TomHennen",
    "branch": "refs/heads/main",
    "controls": [
      {
        "name": "CONTINUITY_ENFORCED",
        "since": "2025-01-26T02:23:18.106Z"
      },
      {
        "name": "GH_REQUIRED_CHECK_test",
        "since": "2025-05-31T21:44:18.816Z"
      },
      {
        "name": "TAG_HYGIENE",
        "since": "2025-02-25T17:27:49.445Z"
      },
      {
        "name": "PROVENANCE_AVAILABLE",
        "since": "2025-03-02T20:14:30.184665988Z"
      }
    ],
    "created_on": "2025-05-31T21:52:36.665624162Z",
    "prev_commit": "a224aa2d55884ef0cef78ccb498c3561ca240808",
    "repo_uri": "https://github.com/slsa-framework/slsa-source-poc"
  }
}
```

### Tag Provenance

Tag provenance records a tag creation event.  It indicates:

1. The name of the tag created.
2. The commit the data applies to
3. The set of tag related controls that are enabled and when they started being enforced.
4. The actor that pushed the tag
5. When the tag was created.
6. A summary of the VSAs that also covered this commit.
   Including: the references the VSA refers to and the `verifiedLevels` in the VSAs
7. The uri of the repo the activity occurred in.

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "digest": {
        "gitCommit": "c0511064260c55fd85ab158e1d97cea3eeaa38cc"
      }
    }
  ],
  "predicateType": "https://github.com/slsa-framework/slsa-source-poc/tag-provenance/v1-draft",
  "predicate": {
    "actor": "TomHennen",
    "controls": [
      {
        "name": "TAG_HYGIENE",
        "since": "2025-03-23T18:08:42.375Z"
      }
    ],
    "created_on": "2025-05-29T20:36:17.486702367Z",
    "repo_uri": "https://github.com/TomHennen/Concordance",
    "tag": "refs/tags/v1.1.5",
    "vsa_summaries": [
      {
        "source_refs": [
          "refs/heads/master"
        ],
        "verifiedLevels": [
          "SLSA_SOURCE_LEVEL_3",
          "TAG_HYGIENE"
        ]
      }
    ]
  }
}
```

## Policy

This PoC uses user supplied 'policy' files (stored in
[a public git repo](https://github.com/slsa-framework/slsa-source-poc/tree/main/policy/github.com)
outside of user control) to indicate what controls _ought_ to be enforced and when that
enforcement should start.

This is used to prevent users from disabling controls, making changes, and reenabling the
controls.  Now, if a user wanted to do so they'd also have to update the 'Since' dates
in their policy, and have that change submitted to the policy repo.  The updated date
would then not cover the uncontrolled changes they made.

This amounts to public declaration of SLSA adoption and allows backsliding to be detected.

```json
{
  "canonical_repo": "https://github.com/slsa-framework/slsa-source-poc",
  "protected_branches": [
    {
      "Name": "main",
      "Since": "2025-03-28T15:09:27.845Z",
      "target_slsa_source_level": "SLSA_SOURCE_LEVEL_3",
      "org_status_check_controls": [
        {
          "check_name": "test",
          "property_name": "ORG_SOURCE_TESTED",
          "Since": "2025-05-31T22:44:18.816Z"
        }
      ]
    }
  ]
}
```

### Org Specified Properties

Policies also allow users to specify that the GitHub repo must have a rule requiring
certain 'checks' to be run by GitHub Actions.  In the above policy example
the organization must have their repo configured to require the 'test' status check
have been run by GitHub Actions.  As seen in this example:

![required status check example](media/require_status_checks.png)

## Verification Summary Attestations (VSA)

Example VSA

```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "digest": {
        "gitCommit": "932eb09d23b8574a5c1c3780afec1a93ebaa3e92"
      },
      "annotations": {
        "source_refs": [
          "refs/heads/main"
        ]
      }
    }
  ],
  "predicateType": "https://slsa.dev/verification_summary/v1",
  "predicate": {
    "policy": {
      "uri": "https://github.com/slsa-framework/slsa-source-poc/blob/main/policy/github.com/slsa-framework/slsa-source-poc/source-policy.json"
    },
    "resourceUri": "git+https://github.com/slsa-framework/slsa-source-poc",
    "timeVerified": "2025-06-01T15:19:28.226795439Z",
    "verificationResult": "PASSED",
    "verifiedLevels": [
      "SLSA_SOURCE_LEVEL_3",
      "ORG_SOURCE_TESTED"
    ],
    "verifier": {
      "id": "https://github.com/slsa-framework/slsa-source-poc"
    }
  }
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
2. It lets us ensure the provenance was created contemporaneously with the
   introduction of the current commit to the current branch.
3. It provides the `actor` used in the [Tag Provenance](#tag-provenance) since
   that information is not otherwise available via GitHub APIs.

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
