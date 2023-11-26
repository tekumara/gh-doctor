package cmd

import (
	"fmt"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"
	"github.com/tekumara/gh-doctor/internal/util"
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

Verify the auth token works and has any required scopes.

If a new token is needed the auth flow is triggered.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return ensureAuth(authOpts)
	},
}

func init() {
	rootCmd.AddCommand(authCmd)
	authCmd.Flags().StringVarP(&authOpts.Hostname, "hostname", "h", githubCom, "Github hostname")
	authCmd.Flags().StringSliceVarP(&authOpts.AdditionalScopes, "scopes", "s", nil, "Required scopes. A new token is requested if these are missing.")
	authCmd.Flags().BoolVarP(&authOpts.Refresh, "refresh", "r", false, `Refresh existing token with minimum scopes + required scopes.
Does not revoke the old token.`)
}

func ensureAuth(opts *AuthOptions) error {

	client, err := util.NewClient(opts.Hostname)

	if opts.Refresh {
		fmt.Println("! To revoke old tokens remove the Github CLI OAuth App via https://github.com/settings/connections/applications/178c6fc778ccc68e1d6a")
	}

	if err != nil || opts.Refresh {
		if err != nil && !strings.Contains(err.Error(), "authentication token not found") {
			return err
		}
		if err = ghAuthLogin(opts.Hostname, opts.AdditionalScopes); err != nil {
			return err
		}
		// get the client again now we have authed
		client, err = util.NewClient(opts.Hostname)
		if err != nil {
			return err
		}
	}

	scopes, err := util.FetchScopes(client)
	if err != nil {
		if httpErr, ok := err.(*api.HTTPError); !ok || httpErr.StatusCode != 401 {
			return err
		}

		// we have bad (eg: revoked) credentials, so login
		fmt.Println("ℹ Refreshing token because its invalid.")
		if err = ghAuthLogin(opts.Hostname, opts.AdditionalScopes); err != nil {
			return err
		}
		// get the client again now we have authed
		client, err = util.NewClient(opts.Hostname)
		if err != nil {
			return err
		}
	}

	scopesSlice := strings.Split(strings.ReplaceAll(scopes, " ", ""), ",")
	missing := util.Missing(scopesSlice, opts.AdditionalScopes)

	if missing != nil {
		fmt.Printf("ℹ Requesting new token with missing scopes %s\n", strings.Join(missing, ", "))
		// mimic behaviour of gh auth refresh, ie: create a new token with existing scopes + the missing ones
		if err = ghAuthLogin(opts.Hostname, append(scopesSlice, missing...)); err != nil {
			return err
		}
		// get a new client using the new token
		client, err = util.NewClient(opts.Hostname)
		if err != nil {
			return err
		}
		scopes, err = util.FetchScopes(client)
		if err != nil {
			return err
		}
	}

	username, err := util.FetchAuthenticatedUser(client)
	if err != nil {
		return err
	}

	fmt.Printf("✓ Authenticated to %s as %s using token with scopes %s\n", opts.Hostname, username, scopes)
	return nil
}

func ghAuthLogin(hostname string, scopes []string) error {
	args := []string{"auth", "login", "-h", hostname}

	// include workflow scope so commits in .github/workflows can be pushed
	// this is automatically added when using interactive mode, the git_protocol is https
	// and the github credential helper is used see
	// https://github.com/cli/cli/blob/06e438b4b4a63ce1ad7486fb7e93091e35906451/pkg/cmd/auth/shared/git_credential.go#L31
	scopes = append(scopes, "workflow")
	for _, s := range scopes {
		args = append(args, "-s", s)
	}
	err := util.ExecGhInteractive(args...)
	return err
}
