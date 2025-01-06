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

### Distribute summary attestations

Open question: This tool doesn't yet distribute attestations. We need to figure that out.
If we use [gitsign](https://github.com/sigstore/gitsign) then our storage will come 'for
free' and we just need to document it.

### Distribute provenance attestations

Level 1: N/A

Level 2: N/A

Level 3: Open question: however if we use gitsign this may come for free?

## Source Control System Requirements

### Revisions are immutable and uniquely identifiable

Level 1+: This tool only attests to git revisions (commits), and those are inherantly immutable and
uniquely identifiable.

### Repository IDs	

Level 1+: This tool currently only supports GitHub repositories and those are uniquely identified
by the repository URL (e.g. `https://github.com/slsa-framework/slsa-source-poc`).

### Revision IDs	

Level 1+: This tool only attests to git revisions (commits) and those have immutability inherantly
enforced.

Open question: Is this duplicative of "Revisions are immutable and uniquely identifiable"

### Source Summary Attestations

Level 1+: This is the tool that is generating these summary attestations.

Open question: How these attestations are stored will determine if it meets the
distrubtion requirements.

Open question: Is this duplicative of "Distribute summary attestations"

### Branches

Level 1: N/A

Level 2+: Open question.

### Continuity

Level 1: N/A

Level 2: Open question: perhaps we just check if branch protection is enabled?

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

Level 3: Open question: What attestations should we create?  When?

### Enforced change management process

Level 1: N/A

Level 2: N/A

Level 3: Open question: Do we just say "we assume folks are using branch protection
rules in GitHub" and leave it at that?
