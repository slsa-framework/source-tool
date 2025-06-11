package attest

import (
	"fmt"
	"log/slog"
)

func Debugf(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...))
}
