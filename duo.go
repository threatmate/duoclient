package duo

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/tekkamanendless/httperror"
)

const (
	StatusActive          = "active"
	StatusBypass          = "bypass"
	StatusDisabled        = "disabled"
	StatusLockedOut       = "locked out"
	StatusPendingDeletion = "pending deletion"
)

type User struct {
	UserID           string  `json:"user_id"`
	Username         string  `json:"username"`
	RealName         string  `json:"realname"`
	Email            string  `json:"email"`
	Status           string  `json:"status"`
	IsEnrolled       bool    `json:"is_enrolled"`
	EnableAutoPrompt bool    `json:"enable_auto_prompt"`
	LastLogin        float64 `json:"last_login"`
	Phones           []Phone `json:"phones"`
	Groups           []Group `json:"groups"`
}

type Phone struct {
	PhoneID          string   `json:"phone_id"`
	Number           string   `json:"number"`
	Activated        bool     `json:"activated"`
	Capabilities     []string `json:"capabilities"`
	Encrypted        string   `json:"encrypted"`
	Extension        string   `json:"extension"`
	Fingerprint      string   `json:"fingerprint"`
	LastSeen         string   `json:"last_seen"`
	Model            string   `json:"model"`
	Name             string   `json:"name"`
	Platform         string   `json:"platform"`
	Screenlock       string   `json:"screenlock"`
	SMSPasscodesSent bool     `json:"sms_passcodes_sent"`
	Tampered         string   `json:"tampered"`
	Type             string   `json:"type"`
}

type Group struct {
	GroupID          string `json:"group_id"`
	Name             string `json:"name"`
	Description      string `json:"desc"`
	Status           string `json:"status"`
	MobileOTPEnabled bool   `json:"mobile_otp_enabled"`
	PushEnabled      bool   `json:"push_enabled"`
	SMSEnabled       bool   `json:"sms_enabled"`
	VoiceEnabled     bool   `json:"voice_enabled"`
}

type GetUsersResponse struct {
	Response []User   `json:"response"`
	Stat     string   `json:"stat"`
	Metadata Metadata `json:"metadata,omitempty"`
}

type Metadata struct {
	TotalObjects int  `json:"total_objects"`
	NextOffset   *int `json:"next_offset,omitempty"`
	PrevOffset   *int `json:"prev_offset,omitempty"`
}

type Credentials struct {
	IntegrationKey string
	SecretKey      string
	APIHostname    string
}

type SignResult struct {
	Date       string
	AuthHeader string
}

// sign creates an authorization signature for Duo API requests using the HMAC-SHA1 algorithm.
// See: https://duo.com/docs/authapi#authentication for the signing algorithm details.
// method: HTTP method (GET, POST, etc.)
// host: Duo API hostname
// path: API endpoint path
// params: Query parameters
// secretKey: Duo secret key
// integrationKey: Duo integration key
func sign(method, host, path string, params map[string]string, secretKey, integrationKey string) (SignResult, error) {
	date := time.Now().UTC().Format(http.TimeFormat)

	canon := []string{date, strings.ToUpper(method), strings.ToLower(string(host)), path}

	var args []string
	for key, value := range params {
		args = append(args, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(value)))
	}
	sort.Strings(args)
	canon = append(canon, strings.Join(args, "&"))

	canonicalString := strings.Join(canon, "\n")

	mac := hmac.New(sha1.New, []byte(secretKey))
	_, err := mac.Write([]byte(canonicalString))
	if err != nil {
		return SignResult{}, fmt.Errorf("error writing to HMAC: %w", err)
	}
	signature := mac.Sum(nil)

	auth := fmt.Sprintf("%s:%s", integrationKey, hex.EncodeToString(signature))
	authHeader := base64.StdEncoding.EncodeToString([]byte(auth))

	return SignResult{Date: date, AuthHeader: authHeader}, nil
}

func GetUsers(ctx context.Context, creds *Credentials) ([]User, error) {
	var allUsers []User
	limit := 100
	offset := 0

	for {
		result, err := getUsersPage(ctx, creds, limit, offset)
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

func getUsersPage(ctx context.Context, creds *Credentials, limit, offset int) (*GetUsersResponse, error) {
	path := "/admin/v1/users"

	params := map[string]string{
		"limit":  fmt.Sprintf("%d", limit),
		"offset": fmt.Sprintf("%d", offset),
	}

	apiURL := creds.APIHostname
	if !strings.HasPrefix(apiURL, "http://") && !strings.HasPrefix(apiURL, "https://") {
		apiURL = "https://" + apiURL
	}

	u, err := url.Parse(fmt.Sprintf("%s%s", apiURL, path))
	if err != nil {
		return nil, fmt.Errorf("error parsing URL: %w", err)
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}

	signResult, err := sign("GET", creds.APIHostname, path, params, creds.SecretKey, creds.IntegrationKey)
	if err != nil {
		return nil, fmt.Errorf("error signing request: %w", err)
	}

	req.Header.Set("Date", signResult.Date)
	req.Header.Set("Authorization", "Basic "+signResult.AuthHeader)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: %s", httperror.ErrorFromStatus(resp.StatusCode), string(body))
	}

	var result GetUsersResponse
	err = json.Unmarshal(body, &result)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal duo API response: %w", err)
	}

	if result.Stat != "OK" {
		return nil, fmt.Errorf("duo API returned error status: %s", result.Stat)
	}

	return &result, nil
}
