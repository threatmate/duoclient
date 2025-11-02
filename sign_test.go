package duoclient

import (
	"encoding/base64"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	if value := os.Getenv("DEBUG"); value == "1" || value == "true" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	t.Run("Should generate valid authorization signature", func(t *testing.T) {
		method := "POST"
		host := "api-XXXXXXXX.duosecurity.com"
		path := "/auth/v2/auth"
		params := url.Values{
			"username": {"testuser"},
			"factor":   {"push"},
		}
		integrationKey := "DIWJ8X6AEYOR5OMC6TQ1"
		secretKey := "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"

		result, err := Sign(method, host, path, params, secretKey, integrationKey)
		require.NoError(t, err)

		_, err = time.Parse(http.TimeFormat, result.Date)
		require.NoError(t, err)

		decoded, err := base64.StdEncoding.DecodeString(result.AuthHeader)
		require.NoError(t, err)

		parts := strings.Split(string(decoded), ":")
		require.Len(t, parts, 2)
		require.Equal(t, integrationKey, parts[0])
		require.Len(t, parts[1], 40)
	})
}
