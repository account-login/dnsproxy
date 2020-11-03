package dnsproxy

import (
	"context"
	"github.com/account-login/ctxlog"
	"io"
)

func safeClose(ctx context.Context, closer io.Closer) {
	if err := closer.Close(); err != nil {
		ctxlog.Errorf(ctx, "close() error: %v", err)
	}
}
