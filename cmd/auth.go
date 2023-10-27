package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/cli/go-gh/v2"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"
	"github.com/tekumara/gh-doctor/internal"
)

type AuthOptions struct {
	Hostname         string
	AdditionalScopes []string
	Refresh          bool
}

var authOpts = &AuthOptions{}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Ensure a working gh auth token.",
	Long: `Ensure a working gh auth token.

Creates a token if needed with any additional scopes if specified.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ensureAuth(authOpts)
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.Flags().StringVarP(&authOpts.Hostname, "hostname", "h", githubCom, "Github hostname")
	authCmd.Flags().StringSliceVarP(&authOpts.AdditionalScopes, "scopes", "s", nil, "Additional authentication scopes to add if missing")
	authCmd.Flags().BoolVarP(&authOpts.Refresh, "refresh", "r", false, "Refresh existing token (if any) with minimum scopes + additional scopes")
}

func newClient(hostname string) (*api.RESTClient, error) {
	return api.NewRESTClient(api.ClientOptions{Host: hostname, Timeout: 2 * time.Second})
}

func ensureAuth(opts *AuthOptions) error {

	client, err := newClient(opts.Hostname)

	if err != nil || opts.Refresh {
		if err != nil && !strings.Contains(err.Error(), "authentication token not found") {
			return err
		}
		if err = ghAuthLogin(opts.Hostname, opts.AdditionalScopes); err != nil {
			return err
		}
		// get the client again now we have authed
		client, err = newClient(opts.Hostname)
		if err != nil {
			return err
		}
	}

	scopes, err := fetchScopes(client)
	if err != nil {
		return err
	}

	scopesSlice := strings.Split(strings.ReplaceAll(scopes, " ", ""), ",")
	missing := slices.Missing(scopesSlice, opts.AdditionalScopes)

	if missing != nil {
		fmt.Printf("ℹ Requesting missing scopes %s\n", strings.Join(missing, ", "))
		// mimic behaviour of gh auth refresh, ie: create a new token with existing scopes + the missing ones
		if err = ghAuthLogin(opts.Hostname, append(scopesSlice, missing...)); err != nil {
			return err
		}
		// get a new client using the new token
		client, err = newClient(opts.Hostname)
		if err != nil {
			return err
		}
		scopes, err = fetchScopes(client)
		if err != nil {
			return err
		}
	}

	username, err := fetchAuthenticatedUser(client)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Authenticated to %s as %s using token with scopes %s\n", opts.Hostname, username, scopes)
	return nil
}

func ghAuthLogin(hostname string, scopes []string) error {
	env := []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1"}
	args := []string{"auth", "login", "-h", hostname}
	for _, s := range scopes {
		args = append(args, "-s", s)
	}
	err := execGh(env, args...)
	return err
}

func fetchAuthenticatedUser(client *api.RESTClient) (string, error) {
	var response struct {
		Login string
	}

	err := client.Get("user", &response)
	return response.Login, err
}

// Get scopes available to the auth token.
func fetchScopes(client *api.RESTClient) (string, error) {
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

// Invoke a gh command in a subprocess with its stdin, stdout, and stderr streams connected to
// those of the parent process. This is suitable for running gh commands with interactive prompts.
// Adapted from https://github.com/cli/go-gh/blob/47a83eeb1778d8e60e98e356b9e5d6178a567f31/gh.go#L41
// to support env vars.
func execGh(env []string, args ...string) error {
	ghExe, err := gh.Path()
	if err != nil {
		return err
	}
	cmd := exec.Command(ghExe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if env != nil {
		// append this processes's env vars so gh can locate its config, state and data dirs
		// as per https://github.com/cli/go-gh/blob/47a83eeb1778d8e60e98e356b9e5d6178a567f31/pkg/config/config.go#L236
		env = append(env, os.Environ()...)
		cmd.Env = env
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh execution failed: %w", err)
	}
	return nil
}
