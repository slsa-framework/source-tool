# 🛑 Deprecation Notice 🛑

This directory is deprecated. To check in new source policies please open a
pull request in the new community repository at
[github.com/slsa-framework/source-policies](https://github.com/slsa-framework/source-policies).

The contents of this directory will be removed in the near future.

---

# Policy

This folder stores 'policies' for individual repos.

It is a place for repo owners to publicly declare

* Which branches are meant for consumption.
* When SLSA protections were enabled without allowing
  those protections to be disabled without it affecting the
  determined SLSA level.

The policies present in this folder will be used by the
slsa-source-poc's GitHub action to determine if the
declared policy is met.

## Creating a policy

To create a new policy for a repo:

1. Fork github.com/slsa-framework/slsa-source-poc
2. Clone it
3. Create a new working branch, e.g.
   `$ git switch -c new_policy`
4. Run the source tool's `createpolicy` command specifying the owning org, repo, and branch you want to protect.
   e.g. if your GitHub repo is `github.com/foo/bar` and you want to protect the main branch run
   `$ go run github.com/slsa-framework/slsa-source-poc/sourcetool createpolicy --owner foo --repo bar --branch main`
5. Commit & push the change
   ```
   $ git commit -asm "My first policy"
   $ git push
   ```
6. Send a PR with the change to github.com/slsa-framework/slsa-source-poc

**TODO**: See if we can make this easier.
