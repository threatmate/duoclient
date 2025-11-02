package duoclient

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/url"
	"sort"
	"strings"
)

// Sign creates an authorization signature for Duo API requests using the HMAC-SHA1 algorithm.
// See: https://duo.com/docs/authapi#authentication for the signing algorithm details.
// method: HTTP method (GET, POST, etc.)
// host: Duo API hostname
// path: API endpoint path
// params: Query parameters
// secretKey: Duo secret key
// integrationKey: Duo integration key
func Sign(ctx context.Context, method string, fullURL string, secretKey string, integrationKey string, dateHeader string) (string, error) {
	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return "", fmt.Errorf("error parsing URL: %w", err)
	}

	canon := []string{dateHeader, strings.ToUpper(method), strings.ToLower(parsedURL.Host), parsedURL.Path}

	var args []string
	for key, values := range parsedURL.Query() {
		for _, value := range values {
			args = append(args, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(value)))
		}
	}
	sort.Strings(args)
	canon = append(canon, strings.Join(args, "&"))

	canonicalString := strings.Join(canon, "\n")
	slog.DebugContext(ctx, "Duo API canonical string", "string", canonicalString)

	mac := hmac.New(sha1.New, []byte(secretKey))
	_, err = mac.Write([]byte(canonicalString))
	if err != nil {
		return "", fmt.Errorf("error writing to HMAC: %w", err)
	}
	signature := mac.Sum(nil)

	auth := fmt.Sprintf("%s:%s", integrationKey, hex.EncodeToString(signature))
	authHeader := base64.StdEncoding.EncodeToString([]byte(auth))

	return authHeader, nil
}
