package sourcetool

import (
	"github.com/slsa-framework/slsa-source-poc/sourcetool/pkg/slsa"
)

// New initializes a new source tool instance.
func New(funcs ...ooFn) (*Tool, error) {
	opts := DefaultOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	return &Tool{
		Options: opts,
		impl:    &defaultToolImplementation{},
	}, nil
}

// Tool is the main object intended to expose sourcetool's functionality as a
// public API. Some of the logic is still implemented on the CLI commands but
// we want to slowly move it to public function under this struct.
type Tool struct {
	Options Options
	impl    toolImplementation
}

// GetRepoControls returns the controls that are enabled in a repository.
func (t *Tool) GetRepoControls(funcs ...ooFn) (slsa.Controls, error) {
	opts := t.Options
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}

	return t.impl.GetActiveControls(&opts)
}
