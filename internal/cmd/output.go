// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	OutputFormatText = "text"
	OutputFormatJSON = "json"
)

// outputOptions provides common output formatting options
type outputOptions struct {
	format string
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
