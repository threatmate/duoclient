package duoclient

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPaginationLogic(t *testing.T) {
	if value := os.Getenv("DEBUG"); value == "1" || value == "true" {
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug})))
	}

	ctx := context.Background()

	t.Run("Should handle single page of results", func(t *testing.T) {
		server := createMockServer(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "100", r.URL.Query().Get("limit"))
			assert.Equal(t, "0", r.URL.Query().Get("offset"))

			response := GetUsersResponse{
				Stat: "OK",
				Response: []User{
					{UserID: "U1", Username: "user1"},
					{UserID: "U2", Username: "user2"},
				},
				Metadata: Metadata{
					TotalObjects: 2,
				},
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		config := Config{
			IntegrationKey: "test-key",
			SecretKey:      "test-secret",
			BaseURL:        server.URL,
		}
		client := New(config)

		users, err := client.GetUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("Should handle multiple pages of results", func(t *testing.T) {
		callCount := 0
		server := createMockServer(func(w http.ResponseWriter, r *http.Request) {
			offset := r.URL.Query().Get("offset")

			switch offset {
			case "0":
				callCount++
				nextOffset := 100
				response := GetUsersResponse{
					Stat:     "OK",
					Response: createUsers(0, 100),
					Metadata: Metadata{
						TotalObjects: 150,
						NextOffset:   &nextOffset,
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			case "100":
				callCount++
				response := GetUsersResponse{
					Stat:     "OK",
					Response: createUsers(100, 50),
					Metadata: Metadata{
						TotalObjects: 150,
					},
				}

				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(response)
			default:
				t.Fatalf("Unexpected offset: %s", offset)
			}
		})
		defer server.Close()

		config := Config{
			IntegrationKey: "test-key",
			SecretKey:      "test-secret",
			BaseURL:        server.URL,
		}
		client := New(config)

		users, err := client.GetUsers(ctx)
		require.NoError(t, err)
		assert.Len(t, users, 150)
		assert.Equal(t, 2, callCount, "Should make exactly 2 API calls")
	})
}

func createMockServer(handler http.HandlerFunc) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/v1/users", handler)
	server := httptest.NewServer(mux)
	return server
}

func createUsers(start, count int) []User {
	users := make([]User, count)
	for i := 0; i < count; i++ {
		users[i] = User{
			UserID:   fmt.Sprintf("U%d", start+i+1),
			Username: fmt.Sprintf("user%d", start+i+1),
		}
	}
	return users
}

func unmarshalJSON(data []byte, v interface{}) error {
	return json.Unmarshal(data, v)
}
