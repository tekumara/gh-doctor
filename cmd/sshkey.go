package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/agent"
)

type SshKeyOptions struct {
	Hostname string
	KeyFile  string
}

var opts = &SshKeyOptions{}

var sshkeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Ensure a working ssh key.",
	Long:  `Tests the ssh key is working, creating and adding one to your Github user if needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if opts.KeyFile == "~/.ssh/[hostname]" {
			opts.KeyFile = "~/.ssh/" + opts.Hostname
		}
		return ensure(opts)
	},
}

func init() {
	rootCmd.AddCommand(sshkeyCmd)
	sshkeyCmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "github.com", "Github hostname")
	sshkeyCmd.Flags().StringVarP(&opts.KeyFile, "keyfile", "k", "~/.ssh/[hostname]", "key file")
}

func ensure(opts *SshKeyOptions) error {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		// no ssh agent
		fmt.Println("SSH_AUTH_SOCK is not set. SSH agent won't be used.")
	} else {
		// in case ssh-agent has loaded incorrect keys, lets start afresh
		if err := removeSshAgentIdentities(sshAuthSock); err != nil {
			return err
		}
	}

	// TODO: support rotation

	authed, err := ensureSshAuth(opts.Hostname)
	if err != nil {
		return err
	}
	if authed {
		return nil
	}

	if err := ensureKeyFileExists(opts.KeyFile, opts.Hostname); err != nil {
		return err
	}

	client, err := api.NewRESTClient(api.ClientOptions{Host: opts.Hostname})
	if err != nil {
		return err
	}
	ensureGhAuth(client, opts.Hostname)

	return nil
}

func removeSshAgentIdentities(sshAuthSock string) error {
	// Connect to the SSH agent using the SSH_AUTH_SOCK socket
	agentConn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return fmt.Errorf("failed to connect to the SSH agent: %v", err)
	}
	defer agentConn.Close()
	sshAgent := agent.NewClient(agentConn)

	identities, err := sshAgent.List()
	if err != nil {
		return fmt.Errorf("failed to list SSH agent identities: %v", err)
	}

	if len(identities) == 0 {
		fmt.Println("ℹ No identities present in SSH agent.")
	} else {
		fmt.Println("ℹ Removing existing identities from SSH agent.")
		sshAgent.RemoveAll()
	}

	return nil
}

var regexSshSuccess = regexp.MustCompile(`Hi (.*)! You've successfully authenticated`)

// Authenticate to github using ssh.
// Returns
// true, nil = success
// false, nil = permission denied
// false, error = timeout, can't resolve hostname etc.
func ensureSshAuth(hostname string) (bool, error) {

	// exec ssh rather than using the golang ssh client to mimic git and ensure we are using ~/.ssh/config
	cmd := exec.Command("ssh", "-T", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=2", "git@"+hostname)

	out, err := cmd.CombinedOutput()
	sout := string(out)

	if strings.Contains(sout, "Permission denied") {
		fmt.Printf("X Cannot authenticate to %s via ssh\n", hostname)
		return false, nil
	}

	matches := regexSshSuccess.FindStringSubmatch(sout)
	if len(matches) > 0 {
		username := matches[1]
		fmt.Printf("✓ Authenticated to %s as %s via ssh\n", hostname, username)
		return true, nil
	}

	fmt.Println(sout)
	return false, err
}

func ensureKeyFileExists(keyFile string, hostname string) error {

	if strings.HasPrefix(keyFile, "~/") {
		dirname, _ := os.UserHomeDir()
		keyFile = filepath.Join(dirname, keyFile[2:])
	}

	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// create new key file
		fmt.Printf("Creating key file %s\n", keyFile)
		fmt.Println("Please specify a passphrase!")

		localHostname, err := os.Hostname()
		if err != nil {
			return err
		}
		comment := fmt.Sprintf("%s (%s)", hostname, localHostname)

		// TODO: enforce passphrase
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-C", comment, "-f", keyFile)
		out, err := cmd.Output()
		fmt.Println(string(out))
		return err

	} else {
		// display fingerprint of existing key for easy debugging
		fmt.Printf("✓ Key file %s: ", keyFile)

		cmd := exec.Command("ssh-keygen", "-lf", keyFile)
		out, err := cmd.Output()
		fmt.Print(string(out))
		return err
	}
}

//# request scopes needed to manage ssh keys
//GH_PROMPT_DISABLED=1 gh auth login -h "$github_host" -p ssh -s admin:public_key -s admin:ssh_signing_key

func ensureGhAuth(client *api.RESTClient, hostname string) error {
	username, err := GetAuthenticatedUser(client)
	if err != nil {
		//addMsg("%s %s: api call failed: %s", cs.Red("X"), hostname, err)
		return err
	}

	fmt.Printf("✓ Authenticated to %s as %s using gh token\n", hostname, username)
	return nil
}

func GetAuthenticatedUser(client *api.RESTClient) (string, error) {
	var response struct {
		Login string
	}

	err := client.Get("user", &response)
	return response.Login, err
}
