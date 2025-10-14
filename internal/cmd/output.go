// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
)

type OutputFormat int

const (
	OutputFormatText OutputFormat = 1
	OutputFormatJSON OutputFormat = 2
)

// String is used both by fmt.Print and by Cobra in help text
func (e *OutputFormat) String() string {
	switch *e {
	case OutputFormatText:
		return "text"
	case OutputFormatJSON:
		return "json"
	}
	return "error"
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *OutputFormat) Set(v string) error {
	switch v {
	case "text":
		*e = OutputFormatText
		return nil
	case "json":
		*e = OutputFormatJSON
		return nil
	default:
		return errors.New(`must be one of "text" or "json"`)
	}
}

// Type is only used in help text
func (e *OutputFormat) Type() string {
	return "OutputFormat"
}

// outputOptions provides common output formatting options
type outputOptions struct {
	format OutputFormat
	writer io.Writer
}

func (oo *outputOptions) init() {
	if oo.writer == nil {
		oo.writer = os.Stdout
	}
}

func (oo *outputOptions) isJSON() bool {
	return oo.format == OutputFormatJSON
}

func (oo *outputOptions) writeJSON(v interface{}) error {
	oo.init()
	encoder := json.NewEncoder(oo.writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(v)
}

func (oo *outputOptions) writeTextf(format string, a ...interface{}) {
	oo.init()
	//nolint:errcheck // writeTextf is a convenience method that intentionally ignores errors
	fmt.Fprintf(oo.writer, format, a...)
}

// writeResult writes the result in the appropriate format (JSON or text)
// For text output, it uses the String() method if the value implements fmt.Stringer
func (oo *outputOptions) writeResult(v interface{}) error {
	oo.init()

	if oo.isJSON() {
		return oo.writeJSON(v)
	}

	// For text output, use String() method if available
	if stringer, ok := v.(fmt.Stringer); ok {
		//nolint:errcheck // writeResult is a convenience method that intentionally ignores errors
		fmt.Fprint(oo.writer, stringer.String())
		return nil
	}

	// Fallback: format with %v
	//nolint:errcheck // writeResult is a convenience method that intentionally ignores errors
	fmt.Fprintf(oo.writer, "%v\n", v)
	return nil
}
