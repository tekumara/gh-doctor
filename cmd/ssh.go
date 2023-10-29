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
	"github.com/kevinburke/ssh_config"
	"github.com/spf13/cobra"
	"github.com/tekumara/gh-doctor/internal/util"
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

	_, err := api.NewRESTClient(api.ClientOptions{Host: opts.Hostname})
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

	// TODO: delete file if exists and rotating

	keyFile := expand(opts.KeyFile)

	if err := ensureKeyFileExists(keyFile, opts.Hostname); err != nil {
		return err
	}

	if err := addKey(keyFile+".pub", opts.Hostname); err != nil {
		return err
	}

	if err := updateSshConfig(keyFile, opts.Hostname); err != nil {
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

// expand ~ to home dir
func expand(keyFile string) string {
	if strings.HasPrefix(keyFile, "~/") {
		dirname, _ := os.UserHomeDir()
		return filepath.Join(dirname, keyFile[2:])
	}
	return keyFile
}

func ensureKeyFileExists(keyFile string, hostname string) error {
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
		// prompt appears on stderr
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

func addKey(keyFile string, hostname string) error {
	args := []string{"ssh-key", "add", keyFile}
	err := util.ExecGh(args...)
	return err
}

func updateSshConfig(keyFile string, hostname string) error {
	// open ~/.ssh/config creating it if it doesn't exist
	sshConfigPath := filepath.Join(os.Getenv("HOME"), ".ssh", "config")
	f, err := os.OpenFile(sshConfigPath, os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	// read ~/.ssh/config
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return err
	}

	host, identifyFileNode := findHostAndKey(cfg, hostname, "IdentityFile")

	var newSshConfig, msg string
	if identifyFileNode != nil {
		if identifyFileNode.Value == keyFile {
			msg = fmt.Sprintf("✓ Host %s in ~/.ssh/config already configured\n", hostname)
		} else {
			identifyFileNode.Value = keyFile
			msg = fmt.Sprintf("✓ Updated Host %s in ~/.ssh/config to use key file\n", hostname)
			newSshConfig = cfg.String()
		}
	} else if host != nil && identifyFileNode == nil {
		identifyFileNode = &ssh_config.KV{Key: "IdentityFile", Value: keyFile}
		host.Nodes = append(host.Nodes, identifyFileNode)
		newSshConfig = cfg.String()
		msg = fmt.Sprintf("✓ Added IdentityFile to Host %s in ~/.ssh/config\n", hostname)
	} else { // host == nil
		// add new node ourselves as strings rather than a new Node so we can
		// print indentation see https://github.com/kevinburke/ssh_config/issues/12
		newSshConfig = fmt.Sprintf(`%s
Host %s
  IdentityFile %s`, cfg.String(), hostname, keyFile)
		msg = fmt.Sprintf("✓ Added Host %s to ~/.ssh/config\n", hostname)
	}

	_, err = f.Seek(0, 0)
	if err != nil {
		return err
	}

	_, err = f.WriteString(newSshConfig)
	if err != nil {
		return err
	}

	fmt.Print(msg)
	return err
}

func findHostAndKey(cfg *ssh_config.Config, hostname string, key string) (*ssh_config.Host, *ssh_config.KV) {
	var host *ssh_config.Host
outer:
	for _, h := range cfg.Hosts {
		for _, p := range h.Patterns {
			if p.String() == hostname {
				if len(h.Patterns) > 1 {
					patterns := ""
					for _, p2 := range h.Patterns {
						patterns = patterns + p2.String() + " "
					}
					fmt.Printf("ℹ Host %sin ~/.ssh/config ignored because it includes other hosts\n", patterns)
					break
				} else {
					host = h
					break outer
				}
			}
		}
	}

	var identifyFileNode *ssh_config.KV
	if host != nil {
		lkey := strings.ToLower(key)
		for _, n := range host.Nodes {
			switch n := n.(type) {
			case *ssh_config.KV:
				// keys are case insensitive per the spec
				if strings.ToLower(n.Key) == lkey {
					identifyFileNode = n
				}
			default:
				continue
			}
		}
	}

	return host, identifyFileNode

}
