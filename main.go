// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/slsa-framework/source-tool/internal/cmd"
)

func main() {
	// To enable debug logging
	// Add this line slog.SetLogLoggerLevel(slog.LevelDebug)
	cmd.Execute()
}
