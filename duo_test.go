package duo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	t.Run("Should generate valid authorization signature", func(t *testing.T) {
		method := "POST"
		host := "api-XXXXXXXX.duosecurity.com"
		path := "/auth/v2/auth"
		params := map[string]string{
			"username": "testuser",
			"factor":   "push",
		}
		integrationKey := "DIWJ8X6AEYOR5OMC6TQ1"
		secretKey := "Zh5eGmUq9zpfQnyUIu5OL9iWoMMv5ZNmk3zLJ4Ep"

		result, err := sign(method, host, path, params, secretKey, integrationKey)
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

func TestGetUsersResponse(t *testing.T) {
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

func TestPaginationLogic(t *testing.T) {
	ctx := context.Background()

	t.Run("Should handle single page of results", func(t *testing.T) {
		server := createMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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
			json.NewEncoder(w).Encode(response)
		})
		defer server.Close()

		creds := Credentials{
			IntegrationKey: "test-key",
			SecretKey:      "test-secret",
			APIHostname:    server.URL,
		}

		users, err := GetUsers(ctx, &creds)
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("Should handle multiple pages of results", func(t *testing.T) {
		callCount := 0
		server := createMockServer(t, func(w http.ResponseWriter, r *http.Request) {
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
				json.NewEncoder(w).Encode(response)
			default:
				t.Fatalf("Unexpected offset: %s", offset)
			}
		})
		defer server.Close()

		creds := Credentials{
			IntegrationKey: "test-key",
			SecretKey:      "test-secret",
			APIHostname:    server.URL,
		}

		users, err := GetUsers(ctx, &creds)
		require.NoError(t, err)
		assert.Len(t, users, 150)
		assert.Equal(t, 2, callCount, "Should make exactly 2 API calls")
	})
}

func createMockServer(t *testing.T, handler http.HandlerFunc) *httptest.Server {
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
