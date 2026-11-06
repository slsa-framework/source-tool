# source tool

A tool that helps users implement the SLSA Source Track.

Status: in development

## Design

[REQUIREMENTS_MAPPING.md](docs/REQUIREMENTS_MAPPING.md) defines the rationale for how
this tool meets the SLSA Source Requirements.

[DESIGN.md](docs/DESIGN.md) explains more specifically how the system works.

[GETTING_STARTED.md](GETTING_STARTED.md) explains how to get started using the tool.

## Related repositories

[slsa-framework/actions](https://github.com/slsa-framework/actions) the GitHub
Actions used with source-tool to implement SLSA Source Track requirements within
GitHub projects: the `compute_slsa_source.yml` reusable workflow that
`sourcetool setup` installs, and the `verify/source` action. (The older
[source-actions](https://github.com/slsa-framework/source-actions) repository is
superseded by it.)

[source-policies](https://github.com/slsa-framework/source-policies) stores each GitHub
project's 'policy' which details the SLSA Source Level and other controls implemented
by that repository.
