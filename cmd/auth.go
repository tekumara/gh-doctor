package cmd

import (
	"fmt"
	"time"

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

//# request scopes needed to manage ssh keys
//GH_PROMPT_DISABLED=1 gh auth login -h "$github_host" -p ssh -s admin:public_key -s admin:ssh_signing_key

func ensureAuth(opts *AuthOptions) error {

	client, err := api.NewRESTClient(api.ClientOptions{Host: opts.Hostname, Timeout: 2 * time.Second})
	if err != nil {
		return err
	}
	err = ensureGhAuth(client, opts.Hostname)

	return err
}

func ensureGhAuth(client *api.RESTClient, hostname string) error {
	username, err := getAuthenticatedUser(client)
	if err != nil {
		//addMsg("%s %s: api call failed: %s", cs.Red("X"), hostname, err)
		return err
	}

	fmt.Printf("✓ Authenticated to %s as %s using gh token\n", hostname, username)
	return nil
}

func getAuthenticatedUser(client *api.RESTClient) (string, error) {
	var response struct {
		Login string
	}

	err := client.Get("user", &response)
	return response.Login, err
}
