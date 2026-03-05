// SPDX-FileCopyrightText: Copyright 2025 The SLSA Authors
// SPDX-License-Identifier: Apache-2.0

package attest

import (
	"fmt"
	"log/slog"
)

func Debugf(format string, args ...any) {
	//nolint:gosec // G706 This is feneral purpose logger
	slog.Debug(fmt.Sprintf(format, args...))
}
