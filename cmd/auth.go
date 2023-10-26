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
)

type AuthOptions struct {
	Hostname string
}

var authOpts = &AuthOptions{}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Ensure a working gh auth token.",
	Long: `Test the gh auth token has the correct scopes.

Creates a token if needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ensureAuth(authOpts)
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.Flags().StringVarP(&authOpts.Hostname, "hostname", "h", githubCom, "Github hostname")
}

func ensureAuth(opts *AuthOptions) error {

	client, err := api.NewRESTClient(api.ClientOptions{Host: opts.Hostname, Timeout: 2 * time.Second})

	if err != nil {
		if !strings.Contains(err.Error(), "authentication token not found") {
			return err
		}
		if err = ghAuthLogin(opts.Hostname); err != nil {
			return err
		}
		// get the client again now we have authed
		client, err = api.NewRESTClient(api.ClientOptions{Host: opts.Hostname, Timeout: 2 * time.Second})
		if err != nil {
			return err
		}
	}

	err = ensureScopes(client, opts.Hostname)

	return err
}

// # request scopes needed to manage ssh keys
// GH_PROMPT_DISABLED=1 gh auth login -h "$github_host" -p ssh -s admin:public_key -s admin:ssh_signing_key
func ghAuthLogin(hostname string) error {
	noPrompt := []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1"}
	err := execGh(noPrompt, "auth", "login", "-h", hostname)
	return err
}

func ensureScopes(client *api.RESTClient, hostname string) error {
	username, err := fetchAuthenticatedUser(client)
	if err != nil {
		return err
	}

	scopes, err := fetchScopes(client)
	if err != nil {
		return err
	}
	// TODO: check scopes

	fmt.Printf("✓ Authenticated to %s as %s using gh token with scopes %s\n", hostname, username, scopes)
	return nil
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
		cmd.Env = env
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh execution failed: %w", err)
	}
	return nil
}
