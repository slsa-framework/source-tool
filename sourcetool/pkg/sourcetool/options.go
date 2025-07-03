package sourcetool

import "github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/sourcetool/options"

func WithRepo(repo string) options.Fn {
	return func(o *options.Options) error {
		// TODO(puerco): Validate repo string
		o.Repo = repo
		return nil
	}
}

func WithOwner(repo string) options.Fn {
	return func(o *options.Options) error {
		// TODO(puerco): Validate org string
		o.Owner = repo
		return nil
	}
}

func WithBranch(branch string) options.Fn {
	return func(o *options.Options) error {
		o.Branch = branch
		return nil
	}
}

func WithCommit(commit string) options.Fn {
	return func(o *options.Options) error {
		o.Commit = commit
		return nil
	}
}

func WithEnforce(enforce bool) options.Fn {
	return func(o *options.Options) error {
		o.Enforce = enforce
		return nil
	}
}

func WithUserForkOrg(org string) options.Fn {
	return func(o *options.Options) error {
		o.UserForkOrg = org
		return nil
	}
}

func WithPolicyRepo(slug string) options.Fn {
	return func(o *options.Options) error {
		o.PolicyRepo = slug
		return nil
	}
}
