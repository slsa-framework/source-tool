# slsa-source-poc

A proof-of-concept for how the SLSA Source Track could be implemented.

The code in this repository should not be relied upon for production purposes.

Status: in development

## SLSA Source VSAs

[create_slsa_source_vsa.yml](.github/workflows/create_slsa_source_vsa.yml) is a reusable workflow that is meant to
create a VSA attesting to the SLSA Source Level of a given commit.

[local_attest.yml](.github/workflows/local_attest.yml) is a local workflow that invokes create_slsa_source_vsa.yml.

[vsa_creator](actions/vsa_creator/action.yml) is a GitHub Action that does most of the work of creating the VSA.
