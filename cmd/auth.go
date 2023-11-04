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

func ensureAuth(opts *AuthOptions) error {

	client, err := util.NewClient(opts.Hostname)

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
		fmt.Printf("ℹ Requesting missing scopes %s\n", strings.Join(missing, ", "))
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
	for _, s := range scopes {
		args = append(args, "-s", s)
	}
	err := util.ExecGh(args...)
	return err
}

