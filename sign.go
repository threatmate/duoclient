package duoclient

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// SignResult contains the results of the signing operation.
type SignResult struct {
	Date       string
	AuthHeader string
}

// Sign creates an authorization signature for Duo API requests using the HMAC-SHA1 algorithm.
// See: https://duo.com/docs/authapi#authentication for the signing algorithm details.
// method: HTTP method (GET, POST, etc.)
// host: Duo API hostname
// path: API endpoint path
// params: Query parameters
// secretKey: Duo secret key
// integrationKey: Duo integration key
func Sign(method, host, path string, params url.Values, secretKey, integrationKey string) (SignResult, error) {
	date := time.Now().UTC().Format(http.TimeFormat)

	canon := []string{date, strings.ToUpper(method), strings.ToLower(string(host)), path}

	var args []string
	for key, values := range params {
		for _, value := range values {
			args = append(args, fmt.Sprintf("%s=%s", url.QueryEscape(key), url.QueryEscape(value)))
		}
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
