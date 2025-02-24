# SLSA Source PoC - Policy

This file desribes how this tool comes to a conclusion about what SLSA Source Level a given commit meets.

It is currently written based on https://slsa.dev/spec/draft/source-requirements as of 2024-01-06

## Organization Requirements

Open question: does our tooling even need to care about these things?  Should VSA creation
take this into account (it seems like it could depending on how the open questions below
are answered).

### Use Modern Tools

Level 1+: git is one of the modern tools, since this tool only works with git this requirement is met.

### Canonical location

Open question: It's unclear how this should be checked by tooling. One thought is that this
requirement may be in the wrong spot.  Instead perhaps what we're looking for is that given
packages distributed further downstream should indicate which source repos are canonical.
They could do this using SLSA _build_ provenance.

TODO: Now enabling people to set a canonical location in a policy file.  Not yet requried for Level 1.

### Distribute summary attestations

This tool stores summary attestations as `git notes`.

To display attestations:

1. Clone the repo in question
2. `git fetch origin "refs/notes/*:refs/notes/*"`
3. `git notes show <COMMIT> | jq -r .payload | base64 --decode | jq`

NOTE: This **does not** verify the signature at all.  That work is TBD.

### Distribute provenance attestations

Level 1: N/A

Level 2: N/A

Level 3:

This tool stores provenance attestations (with summary attestations) as `git notes`.

To display attestations:

1. Clone the repo in question
2. `git fetch origin "refs/notes/*:refs/notes/*"`
3. `git notes show <COMMIT> | jq -r .payload | base64 --decode | jq`

## Source Control System Requirements

### Revisions are immutable and uniquely identifiable

Level 1+: This tool only attests to git revisions (commits), and those are inherently immutable and
uniquely identifiable.

### Repository IDs	

Level 1+: This tool currently only supports GitHub repositories and those are uniquely identified
by the repository URL (e.g. `https://github.com/slsa-framework/slsa-source-poc`).

### Revision IDs	

Level 1+: This tool only attests to git revisions (commits) and those have immutability inherently
enforced.

Open question: Is this duplicative of "Revisions are immutable and uniquely identifiable"

### Source Summary Attestations

Level 1+: This is the tool that is generating these summary attestations.

This tool stores summary attestations (with provenance attestations) as `git notes`.

To display attestations:

1. Clone the repo in question
2. `git fetch origin "refs/notes/*:refs/notes/*"`
3. `git notes show <COMMIT> | jq -r .payload | base64 --decode | jq`

Open question: Is this duplicative of "Distribute summary attestations"

### Branches

Level 1: N/A

Level 2+: For a commit on a branch to qualify as Level 2+ it must be explicitly indicated in the corresponding policy file.
This is taken as an indication that it is meant for consumption.

### Continuity

Level 1: N/A

Level 2: Repos are eligible for Level 2 if they have enabled the "Restrict Deletions" (`deletion`) and "Block force pushes" (`non_fast_forward`) rules for the branch in question.

Open Question: should we look for anything else?

Level 3: Open question: should we rely on the provenance attestations that are generated?

### Identity Management

Level 1: N/A

Level 2+: Open question: How can we check that GitHub identities are what's used? Implicit?

### Strong Authentication	

Level 1: N/A

Level 2: N/A

Level 3: Open question: How can we check that multi-factor is required?

### Source Provenance	

Level 1: N/A

Level 2: N/A

Level 3:
This tool creates 'source provenance' attestations for each push to a protected branch.  It records, at least

* The actor that did the push
* The current commit
* The previous commit
* The SLSA source level the current commit meets
* The time the branch began meeting that level's requirements

### Enforced change management process

Level 1: N/A

Level 2: N/A

Level 3: Open question: Do we just say "we assume folks are using branch protection
rules in GitHub" and leave it at that?
