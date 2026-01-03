package duoclient

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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
	if !strings.HasPrefix(config.BaseURL, "http://") && !strings.HasPrefix(config.BaseURL, "https://") {
		config.BaseURL = "https://" + config.BaseURL
	}

	return &Client{
		config: config,
		client: restapiclient.New(config.BaseURL),
	}
}

// HTTPClient returns the underlying HTTP client used to make requests.
func (c *Client) HTTPClient() *http.Client {
	return c.client.HTTPClient()
}

// Do performs an HTTP request to the Duo API with the given method, path, input, and output.
func (c *Client) Do(ctx context.Context, method string, path string, input any, output any) error {
	dateHeader := time.Now().UTC().Format(http.TimeFormat)

	// TODO: If this is a POST request, then we're supposed to also include the body form parameters in the signature,
	// TODO: *in place of* the URL query parameters.
	// TODO: If we ever need to do POST requests with body parameters, implement that here.  Basically, we'll just need to check
	// TODO: the type of the input parameter, and if it's form data, then tack that onto the URL as if it where query parameters (for signing purposes only).

	authorizationToken, err := Sign(ctx, method, strings.TrimRight(c.config.BaseURL, "/")+"/"+strings.TrimLeft(path, "/"), c.config.SecretKey, c.config.IntegrationKey, dateHeader)
	if err != nil {
		return fmt.Errorf("error signing request: %w", err)
	}

	err = c.client.Do(ctx, method, path, input, output,
		restapiclient.OptionHeader("Date", dateHeader),
		restapiclient.OptionHeader("Authorization", "Basic "+authorizationToken),
	)
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

// GetGroups retrieves all groups from the Duo API, handling pagination as needed.
func (c *Client) GetGroups(ctx context.Context) ([]Group, error) {
	var allGroups []Group
	limit := 100
	offset := 0

	for {
		result, err := c.GetGroupsPage(ctx, limit, offset)
		if err != nil {
			return nil, err
		}

		allGroups = append(allGroups, result.Response...)

		if result.Metadata.NextOffset == nil {
			// No more pages
			break
		}

		offset = *result.Metadata.NextOffset
	}

	return allGroups, nil
}

// GetGroupsPage retrieves a single page of users from the Duo API with the specified limit and offset.
func (c *Client) GetGroupsPage(ctx context.Context, limit, offset int) (*GetGroupsResponse, error) {
	params := url.Values{}
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("offset", fmt.Sprintf("%d", offset))

	path := "/admin/v1/groups?" + params.Encode()

	var result GetGroupsResponse
	err := c.Do(ctx, http.MethodGet, path, nil, &result)
	if err != nil {
		return nil, fmt.Errorf("error getting groups: %w", err)
	}

	if result.Stat != "OK" {
		return nil, fmt.Errorf("duo API returned error status: %s", result.Stat)
	}

	return &result, nil
}
