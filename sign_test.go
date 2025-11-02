package duoclient

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	ctx := t.Context()

	if value := os.Getenv("DEBUG"); value == "1" || value == "true" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	t.Run("Should generate valid authorization signature", func(t *testing.T) {
		// Example from: https://duo.com/docs/authapi#authentication
		output, err := Sign(ctx, "POST", "https://api-XXXXXXXX.duosecurity.com/auth/v2/auth?device=auto&factor=push&hostname=wks01&ipaddr=10.2.3.4&username=narroway", "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep", "DIWJ8X6AEYOR5OMC6TQ1", "Tue, 21 Aug 2012 17:29:18 -0000")
		require.NoError(t, err)
		assert.Equal(t, "RElXSjhYNkFFWU9SNU9NQzZUUTE6NGUxMzY2MGVmMGEwZTQ5MWFhNzg2ZGNhZmM2MDgwMjU0NzFkOTg5Nw==", output)
	})
}
