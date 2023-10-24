package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net"
	"os"
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
		return ensure(opts)
	},
}

func init() {
	rootCmd.AddCommand(sshkeyCmd)
	sshkeyCmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "github.com", "Github hostname")
}

func ensure(opts *SshKeyOptions) error {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		// no ssh agent
		fmt.Println("SSH_AUTH_SOCK is not set. SSH agent won't be used.")
	} else {
		err := resetSshAgent(sshAuthSock)
		if err != nil {
			return err
		}
	}
	return nil
}

func resetSshAgent(sshAuthSock string) error {
	// in case ssh-agent has loaded incorrect keys, lets start afresh

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
			fmt.Printf("%s %s %s\n", identity.Comment, fingerprintSHA256(identity.Blob), identity.Format)
		}
	}

	sshAgent.RemoveAll()

	return nil
}

func fingerprintSHA256(blob []byte) string {
	sha256sum := sha256.Sum256(blob)
	hash := base64.StdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + strings.TrimRight(hash, "=")
}
