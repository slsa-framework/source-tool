# slsa-source-poc

A proof-of-concept for how the SLSA Source Track could be implemented.

The code in this repository should not be relied upon for production purposes.

Status: in development

## Policy & Design

[POLICY.md](POLICY.md) defines the rationale behind labeling a given commit at a particular SLSA level.

[DESIGN.md](DESIGN.md) explains how the system works.

## SLSA Source VSAs

[compute_slsa_source.yml](.github/workflows/compute_slsa_source.yml) is a reusable workflow that
is calculates a SLSA source level and produces 'source provenance' and a 'verification summary'
for the revision (commit) that was just pushed.

[local_attest.yml](.github/workflows/local_attest.yml) is a local workflow that invokes compute_slsa_source.yml.

[slsa_with_provenance](actions/slsa_with_provenance/action.yml) is a GitHub Action that does most
of the work.

[get_note](actions/get_note/action.yml) is a GitHub Action that gets a git note from a commit.

[store_note](actions/store_note/action.yml) is a GitHub Action that stores a git note for
a commit.
