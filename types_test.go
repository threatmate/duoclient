package duoclient

import (
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetUsersResponse(t *testing.T) {
	if value := os.Getenv("DEBUG"); value == "1" || value == "true" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	t.Run("Should unmarshal response with metadata", func(t *testing.T) {
		jsonStr := `{
			"stat": "OK",
			"response": [{
				"user_id": "DU123",
				"username": "testuser",
				"email": "test@example.com"
			}],
			"metadata": {
				"total_objects": 150,
				"next_offset": 100
			}
		}`

		var response GetUsersResponse
		err := unmarshalJSON([]byte(jsonStr), &response)
		require.NoError(t, err)

		assert.Equal(t, "OK", response.Stat)
		assert.Len(t, response.Response, 1)
		assert.Equal(t, "DU123", response.Response[0].UserID)
		assert.Equal(t, 150, response.Metadata.TotalObjects)
		assert.NotNil(t, response.Metadata.NextOffset)
		assert.Equal(t, 100, *response.Metadata.NextOffset)
	})

	t.Run("Should unmarshal response without metadata", func(t *testing.T) {
		jsonStr := `{
			"stat": "OK",
			"response": [{
				"user_id": "DU123",
				"username": "testuser"
			}]
		}`

		var response GetUsersResponse
		err := unmarshalJSON([]byte(jsonStr), &response)
		require.NoError(t, err)

		assert.Equal(t, "OK", response.Stat)
		assert.Len(t, response.Response, 1)
		assert.Nil(t, response.Metadata.NextOffset)
	})
}
