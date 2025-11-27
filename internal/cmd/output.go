// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

const (
	OutputFormatText = "text"
	OutputFormatJSON = "json"
)

// outputOptions provides common output formatting options
type outputOptions struct {
	format string
}

// AddFlags adds output-related flags to the command
func (oo *outputOptions) AddFlags(cmd *cobra.Command) {
	oo.format = OutputFormatText
	cmd.PersistentFlags().StringVar(&oo.format, "format", OutputFormatText, "Output format: 'text' (default) or 'json'")
}

// Validate checks that the output format is valid
func (oo *outputOptions) Validate() error {
	if oo.format != OutputFormatText && oo.format != OutputFormatJSON {
		return fmt.Errorf("output format must be 'text' or 'json', got: %s", oo.format)
	}
	return nil
}

// getWriter returns the writer to use for output (currently always os.Stdout)
func (oo *outputOptions) getWriter() io.Writer {
	return os.Stdout
}

func (oo *outputOptions) outputFormatIsJSON() bool {
	return oo.format == OutputFormatJSON
}

func (oo *outputOptions) writeJSON(v interface{}) error {
	encoder := json.NewEncoder(oo.getWriter())
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func (oo *outputOptions) writeTextf(format string, a ...interface{}) {
	//nolint:errcheck // writeTextf is a convenience method that intentionally ignores errors
	fmt.Fprintf(oo.getWriter(), format, a...)
}

// writeResult writes the result in the appropriate format (JSON or text)
// For text output, it uses the String() method if the value implements fmt.Stringer
func (oo *outputOptions) writeResult(v interface{}) error {
	if oo.outputFormatIsJSON() {
		return oo.writeJSON(v)
	}

	// For text output, use String() method if available
	if stringer, ok := v.(fmt.Stringer); ok {
		//nolint:errcheck // writeResult is a convenience method that intentionally ignores errors
		fmt.Fprint(oo.getWriter(), stringer.String())
		return nil
	}

	// Fallback: format with %v
	//nolint:errcheck // writeResult is a convenience method that intentionally ignores errors
	fmt.Fprintf(oo.getWriter(), "%v\n", v)
	return nil
}
