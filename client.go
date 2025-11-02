package duoclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/threatmate/restapiclient"
)

// Config is the configuration for the Duo client.
type Config struct {
	IntegrationKey string // Duo integration key.
	SecretKey      string // Duo secret key.
	BaseURL        string // Base URL to Duo API (e.g., https://api-XXXXXXXX.duosecurity.com; if the protocol is omitted, https:// is assumed).
}

// Client is a Duo API client.
type Client struct {
	config Config                // Configuration for the Duo client.
	client *restapiclient.Client // REST API client for making HTTP requests.
}

// New creates a new Duo API client with the given configuration.
func New(config Config) *Client {
	baseURL := config.BaseURL
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		baseURL = "https://" + baseURL
	}

	return &Client{
		config: config,
		client: restapiclient.New(baseURL),
	}
}

// HTTPClient returns the underlying HTTP client used to make requests.
func (c *Client) HTTPClient() *http.Client {
	return c.client.HTTPClient()
}

// Do performs an HTTP request to the Duo API with the given method, path, input, and output.
func (c *Client) Do(ctx context.Context, method string, path string, input any, output any) error {
	fullURL := strings.TrimRight(c.config.BaseURL, "/") + "/" + strings.TrimLeft(path, "/")
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return fmt.Errorf("error parsing URL: %w", err)
	}

	signResult, err := Sign(method, parsedURL.Host, parsedURL.Path, parsedURL.Query(), c.config.SecretKey, c.config.IntegrationKey)
	if err != nil {
		return fmt.Errorf("error signing request: %w", err)
	}

	err = c.client.Do(ctx, method, path, input, output, restapiclient.OptionHeader("Date", signResult.Date), restapiclient.OptionHeader("Authorization", "Basic "+signResult.AuthHeader))
	if err != nil {
		return fmt.Errorf("error performing request: %w", err)
	}

	return nil
}

// GetUsers retrieves all users from the Duo API, handling pagination as needed.
func (c *Client) GetUsers(ctx context.Context) ([]User, error) {
	var allUsers []User
	limit := 100
	offset := 0

	for {
		result, err := c.GetUsersPage(ctx, limit, offset)
		if err != nil {
			return nil, err
		}

		allUsers = append(allUsers, result.Response...)

		if result.Metadata.NextOffset == nil {
			// No more pages
			break
		}

		offset = *result.Metadata.NextOffset
	}

	return allUsers, nil
}

// GetUsersPage retrieves a single page of users from the Duo API with the specified limit and offset.
func (c *Client) GetUsersPage(ctx context.Context, limit, offset int) (*GetUsersResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", fmt.Sprintf("%d", offset))

	path := "/admin/v1/users?" + params.Encode()

	var result GetUsersResponse
	err := c.Do(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("error getting users: %w", err)
	}

	if result.Stat != "OK" {
		return nil, fmt.Errorf("duo API returned error status: %s", result.Stat)
	}

	return &result, nil
}
