package cmd

//TODO: rename gh-doctor to gh-ensure

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/spf13/cobra"
	slices "github.com/tekumara/gh-doctor/internal"
	"golang.org/x/crypto/ssh/agent"
)

type SshOptions struct {
	Hostname string
	KeyFile  string
	Rotate   bool
}

var sshOpts = &SshOptions{}

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Ensure ssh is working.",
	Long: `Ensure ssh is working.

Creates and adds a ssh key to your Github user if needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if sshOpts.KeyFile == "~/.ssh/[hostname]" {
			sshOpts.KeyFile = "~/.ssh/" + sshOpts.Hostname
		}
		return ensureSsh(sshOpts)
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.Flags().StringVarP(&sshOpts.Hostname, "hostname", "h", githubCom, "Github hostname")
	sshCmd.Flags().StringVarP(&sshOpts.KeyFile, "keyfile", "k", "~/.ssh/[hostname]", "key file")
	sshCmd.Flags().BoolVarP(&sshOpts.Rotate, "rotate", "r", false, "Rotate existing key (if any)")
}

func ensureSsh(opts *SshOptions) error {
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

	if !opts.Rotate {
		authed, err := ensureSshAuth(opts.Hostname)
		if err != nil {
			return err
		}
		// if authed exit early
		if authed {
			return nil
		}
	}

	client, err := api.NewRESTClient(api.ClientOptions{Host: opts.Hostname})
	if err != nil {
		if strings.Contains(err.Error(), "authentication token not found") {
			hostFlag := ""
			if opts.Hostname != githubCom {
				hostFlag = fmt.Sprintf(" -h %s ", opts.Hostname)
			}
			return fmt.Errorf("%w\n  Please run: gh doctor auth %s-s admin:public_key", err, hostFlag)
		}

		return err
	}
	if err = ensureScopes(client, opts.Hostname); err != nil {
		return err
	}

	// TODO: delete file if exists and rotating

	if err := ensureKeyFileExists(opts.KeyFile, opts.Hostname); err != nil {
		return err
	}

	return nil
}

func removeSshAgentIdentities(sshAuthSock string) error {
	// Connect to the SSH agent using the SSH_AUTH_SOCK socket
	agentConn, err := net.Dial("unix", sshAuthSock)
	if err != nil {
		return fmt.Errorf("failed to connect to the SSH agent: %w", err)
	}
	defer agentConn.Close()
	sshAgent := agent.NewClient(agentConn)

	identities, err := sshAgent.List()
	if err != nil {
		return fmt.Errorf("failed to list SSH agent identities: %w", err)
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
var regexAcceptedKey = regexp.MustCompile(`Server accepts key: ([\S]+) `)

// Authenticate to github using ssh.
// Returns
// true, nil = success
// false, nil = permission denied
// false, error = timeout, can't resolve hostname etc.
func ensureSshAuth(hostname string) (bool, error) {

	// exec ssh rather than using the golang ssh client to mimic git and ensure we are using ~/.ssh/config
	cmd := exec.Command("ssh", "-v", "-T", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=2", "git@"+hostname)

	// verbose debug logs are sent to stderr
	out, err := cmd.CombinedOutput()
	sout := string(out)

	if strings.Contains(sout, "Permission denied") {
		return false, nil
	}

	successMatch := regexSshSuccess.FindStringSubmatch(sout)
	if len(successMatch) > 0 {

		keyMatches := regexAcceptedKey.FindString(sout)
		if len(keyMatches) > 0 {
			fmt.Printf("ℹ %s\n", keyMatches)
		}

		username := successMatch[1]
		fmt.Printf("✓ Authenticated to %s as %s using ssh\n", hostname, username)
		return true, nil
	}

	if _, ok := err.(*exec.ExitError); ok {
		// ssh failed with a non-zero exit status,
		// return error with ssh output as the message
		return false, errors.New(sout)
	}

	return false, err
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

	missing := slices.Missing(strings.Split(scopes, ","), []string{"admin:public_key"})

	// TODO: remove this and just let it die?
	if missing != nil {
		return fmt.Errorf("cannot set ssh key because %s is missing scopes %s", username, strings.Join(missing, ","))
	}

	fmt.Printf("✓ Authenticated to %s as %s using token with scopes %s\n", hostname, username, scopes)
	return nil
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
		// prompt appears on stderr
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
