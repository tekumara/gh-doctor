package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

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
	
	// authed, err := authGitHub(opts.Hostname)
	// if err != nil {
	// 	return err
	// }
	// if authed {
	// 	return nil
	// }

	fmt.Println()
	if err := ensureKeyFileExists(opts.KeyFile, opts.Hostname); err != nil {
		return err
	}

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
		fmt.Println("No identities loaded into SSH agent.")
	} else {
		fmt.Println("Removing these existing identities:")
		for _, identity := range identities {
			fmt.Printf("%s %s (%s)\n", fingerprintSHA256(identity.Blob), identity.Comment, identity.Format)
		}
	}

	sshAgent.RemoveAll()

	return nil
}

// Unpadded base64 encoding of sha256 hash of the public key.
// Adapted from https://github.com/golang/crypto/blob/cf8dcb0f7d1e4e345ca9df755538650a5e9eb47c/ssh/keys.go#L1713
func fingerprintSHA256(blob []byte) string {
	sha256sum := sha256.Sum256(blob)
	hash := base64.StdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + hash
}

// Authenticate to github using ssh.
// Returns
// true, nil = success
// false, nil = permission denied
// false, error = timeout, can't resolve hostname etc.
func authGitHub(hostname string) (bool, error) {

	fmt.Printf("Authenticating to %s...\n\n", hostname)

	// exec ssh rather than using the golang ssh client to mimic git and ensure we are using ~/.ssh/config
	cmd := exec.Command("ssh", "-T", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=2", "git@"+hostname)

	out, err := cmd.CombinedOutput()
	sout := string(out)
	fmt.Println(sout)

	if strings.Contains(sout, "Permission denied") {
		return false, nil
	}
	if strings.Contains(sout, "successfully authenticated") {
		return true, nil
	}
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
		fmt.Printf("%s: ", keyFile)

		cmd := exec.Command("ssh-keygen", "-lf", keyFile)
		out, err := cmd.Output()
		fmt.Println(string(out))
		return err
	}
}
