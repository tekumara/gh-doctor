package util

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

func NewClient(hostname string, authToken string) (*api.RESTClient, error) {
	// if authToken is empty string then GH_TOKEN, GITHUB_TOKEN etc. env vars are tried before
	// asking the gh cli for a token
	return api.NewRESTClient(api.ClientOptions{AuthToken: authToken, Host: hostname, Timeout: 2 * time.Second})
}

func FetchAuthenticatedUser(client *api.RESTClient) (string, error) {
	var response struct {
		Login string
	}

	err := client.Get("user", &response)
	return response.Login, err
}

// Get scopes available to the auth token.
func FetchScopes(client *api.RESTClient) (string, error) {
	// Adapted from https://github.com/cli/cli/blob/20baccfa85d15963eb1ab4f750da0da37b0af7f5/pkg/cmd/auth/shared/oauth_scopes.go#L35
	resp, err := client.Request(http.MethodGet, "", nil)
	if err != nil {
		return "", err
	}

	defer func() {
		// Ensure the response body is fully read and closed
		// before we reconnect, so that we reuse the same TCPconnection.
		// see https://www.reddit.com/r/golang/comments/13fphyz/comment/jjynmj7/
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()

	return resp.Header.Get("X-Oauth-Scopes"), nil
}

type SshKey struct {
	ID        int
	Key       string
	Title     string
	CreatedAt time.Time `json:"created_at"`
}

// Return keys for the authenticated user
func UserKeys(client *api.RESTClient) ([]SshKey, error) {
	var keys []SshKey
	err := client.Get("user/keys?per_page=100", &keys)
	return keys, err
}

func DeleteKey(client *api.RESTClient, keyId int) error {
	err := client.Delete(fmt.Sprintf("user/keys/%d", keyId), nil)
	return err
}

// idempotently upload ssh key
// adapted from https://github.com/cli/cli/blob/f11f0966959080169dfa7604d8a1a3a60170f417/pkg/cmd/ssh-key/add/http.go#L17
func UploadKey(client *api.RESTClient, keyFile io.Reader, title string) error {

	keyBytes, err := io.ReadAll(keyFile)
	if err != nil {
		return err
	}

	keyString := string(keyBytes)
	splitKey := strings.Fields(keyString)
	if len(splitKey) < 2 {
		return errors.New("key is not in a valid format")
	}

	keyToCompare := splitKey[0] + " " + splitKey[1]

	keys, err := UserKeys(client)
	if err != nil {
		return err
	}

	for _, k := range keys {
		if k.Key == keyToCompare {
			fmt.Print(fmt.Sprintf("✓ Key %s already added to github user\n", title))
			return nil
		}
	}

	payload := map[string]string{
		"title": title,
		"key":   keyString,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	err = client.Post("user/keys", bytes.NewBuffer(payloadBytes), nil)
	if err != nil {
		return err
	}

	fmt.Print(fmt.Sprintf("✓ Key %s added to github user\n", title))
	return nil
}
