package util

import (
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cli/go-gh/v2/pkg/api"
)

func NewClient(hostname string) (*api.RESTClient, error) {
	return api.NewRESTClient(api.ClientOptions{Host: hostname, Timeout: 2 * time.Second})
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
