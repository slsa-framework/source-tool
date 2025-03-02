# Getting Started

These instructions assume you want to achieve the highest SLSA Source Level.
If not you may have to modify the steps somewhat.

## Enable Controls

First, enable continuity controls within the target GitHub repo.

1. Go to the GitHub repo
2. Click the 'Settings' option
3. Click 'Rules -> Rulesets'
4. Click 'New Ruleset -> Import a ruleset'
5. Upload [rulesets/source_level_3_basic.json](rulesets/source_level_3_basic.json)
6. Click 'Create'

## Enable Source PoC workflow

Now, enable a workflow that will evaluate the SLSA level, create provenance, etc...

1. Create a clean checkout of the target repo
2. Create a new file named `./github/workflows/compute_slsa_source.yml`
3. Add the following content

```yaml
name: SLSA Source
on:
  push:
    branches: [ "main" ]

jobs:
  # Whenever new source is pushed recompute the slsa source information.
  check-change:
    permissions:
      contents: write # needed for storing the vsa in the repo.
      id-token: write
    uses: slsa-framework/slsa-source-poc/.github/workflows/compute_slsa_source.yml@main

```

4. Submit the change to your main branch

## Validate Source PoC workflow

Let's verify that everything is working

1. Go to the GitHub repo
2. Click the 'Actions' option
3. Find the most recent run of `SLSA Source` (it should have a green check mark)
4. Click into it
5. You should see the summary listing "SLSA Source Properties": `[SLSA_SOURCE_LEVEL_1]`

## Create a policy file

TODO
