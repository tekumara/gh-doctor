package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/kevinburke/ssh_config"
	"github.com/spf13/cobra"
	"github.com/tekumara/gh-doctor/internal/util"
	"golang.org/x/crypto/ssh/agent"
)

type SSHOptions struct {
	Hostname       string
	UseGhToken     bool
	KeyFile        string
	Rotate         bool
	UseDoctorToken bool
	ConfigureSSO   bool
}

var sshOpts = &SSHOptions{}

var sshCmd = &cobra.Command{
	Use:   "ssh",
	Short: "Ensure ssh works.",
	Long: `Ensure ssh works.

Verify ssh and if needed:
 * Fetch a token using the gh-doctor OAuth app with scope to create SSH keys.
   This token is used once and not stored anywhere.
 * Create a private ssh key file.
 * Add the GitHub host to ~/.ssh/config.
 * Upload the ssh key to your GitHub user account (manually or using an OAuth app).

Example entry added to ~/.ssh/config:

Host github.com
  AddKeysToAgent yes
  UseKeychain yes  # (macOS only)
  IdentityFile ~/.ssh/github.com

During verification any SSH agent identities are removed in case incorrect keys were loaded.
 `,
	RunE: func(_ *cobra.Command, _ []string) error {
		if sshOpts.KeyFile == "~/.ssh/[hostname]" {
			sshOpts.KeyFile = "~/.ssh/" + sshOpts.Hostname
		}
		return ensureSSH(sshOpts)
	},
}

func init() {
	rootCmd.AddCommand(sshCmd)
	sshCmd.Flags().BoolVarP(&sshOpts.UseDoctorToken, "doctoken", "d", false, "Use the GitHub Doctor OAuth app to upload the key")
	sshCmd.Flags().BoolVarP(&sshOpts.UseGhToken, "ghtoken", "g", false, "Use GH_TOKEN env var then GitHub CLI OAuth app to upload the key")
	sshCmd.Flags().StringVarP(&sshOpts.Hostname, "hostname", "h", githubCom, "GitHub hostname")
	sshCmd.Flags().StringVarP(&sshOpts.KeyFile, "keyfile", "k", "~/.ssh/[hostname]", "Private key file")
	sshCmd.Flags().BoolVarP(&sshOpts.Rotate, "rotate", "r", false, "Rotate existing key (if any)")
	sshCmd.Flags().BoolVarP(&sshOpts.ConfigureSSO, "sso", "s", false, "Prompt to authorise the key for organisations using SAML SSO")
}

// osName is a variable that can be overridden in tests to mock the OS
var osName = runtime.GOOS

func hostFlag(opts *SSHOptions) string {
	hostFlag := ""
	if opts.Hostname != githubCom {
		hostFlag = fmt.Sprintf("-h %s ", opts.Hostname)
	}
	return hostFlag
}

func ensureSSH(opts *SSHOptions) error {
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		// no ssh agent
		fmt.Println("SSH_AUTH_SOCK is not set. SSH agent won't be used.")
	} else {
		// in case ssh-agent has loaded incorrect keys, lets start afresh
		if err := removeSSHAgentIdentities(sshAuthSock); err != nil {
			return err
		}
	}

	if !opts.Rotate {
		authed, err := ensureSSHAuth(opts.Hostname)
		if err != nil {
			return err
		}
		// if authed exit early
		if authed {
			return nil
		}
	}

	var client *api.RESTClient
	if opts.UseDoctorToken || opts.UseGhToken {
		var err error
		client, err = ghClient(opts)
		if err != nil {
			return err
		}
	}

	keyFile := expand(opts.KeyFile)

	if opts.Rotate {
		if client != nil {
			if err := ensureKeyDeletedFromGitHub(keyFile, client); err != nil {
				return err
			}
		}

		// TODO: overwrite rather than delete
		if err := os.Remove(keyFile); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(keyFile + ".pub"); err != nil && !os.IsNotExist(err) {
			return err
		}
		fmt.Println("ℹ Deleted existing key.")
	}

	localHostname, err := os.Hostname()
	if err != nil {
		return err
	}
	comment := fmt.Sprintf("%s (%s)", opts.Hostname, localHostname)

	if err := ensureKeyFileExists(keyFile, comment); err != nil {
		return err
	}

	if client != nil {
		if err := addKey(client, keyFile+".pub", comment); err != nil {
			return err
		}
		if opts.ConfigureSSO {
			if err := configureSSOPrompt(opts.Hostname); err != nil {
				return err
			}
		}
	} else {
		if err := manualPrompt(opts.Hostname, keyFile+".pub", comment, opts.ConfigureSSO); err != nil {
			return err
		}
	}

	if err := updateSSHConfig("~/.ssh/config", keyFile, opts.Hostname); err != nil {
		return err
	}

	authed, err := ensureSSHAuth(opts.Hostname)
	if err != nil {
		return err
	}
	if !authed {
		return fmt.Errorf("permission denied trying ssh -vT git@%s", opts.Hostname)
	}

	return nil
}

func ghClient(opts *SSHOptions) (*api.RESTClient, error) {
	var accessToken string
	if !opts.UseGhToken {
		ctx := context.Background()
		token, err := util.FetchToken(ctx)
		if err != nil {
			return nil, err
		}
		accessToken = token.AccessToken
	}

	client, err := util.NewClient(opts.Hostname, accessToken)
	if err != nil {
		if strings.Contains(err.Error(), "authentication token not found") {
			return nil, fmt.Errorf("%w\n  Please run: gh auth login %s-s admin:public_key", err, hostFlag(opts))
		}

		return nil, err
	}
	username, err := util.FetchAuthenticatedUser(client)
	if err != nil {
		return nil, err
	}

	fmt.Printf("✓ Authenticated to %s as %s using token\n", opts.Hostname, username)

	if opts.UseGhToken {
		scopes, err := util.FetchScopes(client)
		if err != nil {
			if httpErr, ok := err.(*api.HTTPError); !ok || httpErr.StatusCode != 401 {
				return nil, err
			}
			// we have bad (eg: revoked) credentials
			return nil, fmt.Errorf("%w\n  Invalid token", err)
		}

		scopesSlice := strings.Split(strings.ReplaceAll(scopes, " ", ""), ",")
		missing := util.Missing(scopesSlice, []string{"admin:public_key"})
		if missing != nil {
			return nil, fmt.Errorf("token is missing the scope admin:public_key\nPlease run: gh auth refresh %s-s admin:public_key", hostFlag(opts))
		}
	}
	return client, nil
}

func removeSSHAgentIdentities(sshAuthSock string) error {
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
		err = sshAgent.RemoveAll()
		if err != nil {
			return err
		}
	}

	return nil
}

var regexSSHSuccess = regexp.MustCompile(`Hi (.*)!`)
var regexAcceptedKey = regexp.MustCompile(`Server accepts key: .*`)

// Authenticate to github using ssh.
// Returns
// true, nil = success
// false, nil = permission denied
// false, error = timeout, can't resolve hostname etc.
func ensureSSHAuth(hostname string) (bool, error) {

	// exec ssh rather than using the golang ssh client to mimic git and use the user's ssh config
	cmd := exec.Command("ssh", "-v", "-T", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=2", "git@"+hostname)

	// verbose debug logs are sent to stderr
	out, err := cmd.CombinedOutput()
	sout := string(out)

	if strings.Contains(sout, "Permission denied") {
		return false, nil
	}

	successMatch := regexSSHSuccess.FindStringSubmatch(sout)
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

func ensureKeyDeletedFromGitHub(keyFile string, client *api.RESTClient) error {
	pubKey, err := loadPublicKey(keyFile + ".pub")
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	keys, err := util.UserKeys(client)
	if err != nil {
		return err
	}
	for _, key := range keys {
		if key.Key == pubKey {
			if err := util.DeleteKey(client, key.ID); err != nil {
				return err
			}
		}
	}
	return nil
}

func loadPublicKey(pubKeyFile string) (string, error) {
	bytes, err := os.ReadFile(pubKeyFile)
	if err != nil {
		return "", err
	}
	parts := strings.Fields(string(bytes))
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid public key %s", pubKeyFile)
	}
	// return public key without comment
	pubKey := parts[0] + " " + parts[1]

	return pubKey, nil
}

func ensureKeyFileExists(keyFile string, comment string) error {
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		// create new key file
		fmt.Printf("Creating key file %s\n", keyFile)
		fmt.Println("Please specify a passphrase!")

		// TODO: enforce passphrase
		cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-C", comment, "-f", keyFile)
		// prompt appears on stderr
		out, err := cmd.Output()
		fmt.Println(string(out))
		return err
	}
	// display fingerprint of existing key for easy debugging
	fmt.Printf("✓ Key file %s: ", keyFile)

	cmd := exec.Command("ssh-keygen", "-lf", keyFile)
	out, err := cmd.Output()
	fmt.Print(string(out))
	return err
}

func addKey(client *api.RESTClient, keyFile string, title string) error {
	f, err := os.Open(keyFile)
	if err != nil {
		return err
	}
	defer f.Close()

	err = util.UploadKey(client, f, title)
	return err
}

const configureSSOInstruction = `Next to the newly added key click "Configure SSO" and authorize your Single sign-on organisations`

func manualPrompt(hostname string, keyFile string, title string, configureSSO bool) error {
	f, err := os.Open(keyFile)
	if err != nil {
		return err
	}
	defer f.Close()
	keyBytes, err := io.ReadAll(f)
	if err != nil {
		return err
	}

	keyString := string(keyBytes)

	if err = clipboard.WriteAll(keyString); err != nil {
		return err
	}

	var urlSettingsSSHNew = fmt.Sprintf("https://%s/settings/ssh/new", hostname)

	var configureSSOInstructionIndexed string
	var nextInstructionIndex int
	if configureSSO {
		configureSSOInstructionIndexed = `
5. ` + configureSSOInstruction
		nextInstructionIndex = 6
	} else {
		nextInstructionIndex = 5
	}

	fmt.Printf(`
Add new SSH Key (manual instructions)
-------------------------------------

1. Press Enter to open %s
2. In the "Title" field, add a descriptive label for the new key, eg: %s
3. In the "Key" field, paste the following public key (this has been copied to your clipboard):

%s
4. Click "Add SSH key"%s
%d. Delete any old SSH keys
%d. Return here and press Enter to continue
`, urlSettingsSSHNew, title, keyString, configureSSOInstructionIndexed, nextInstructionIndex, nextInstructionIndex+1)
	// wait for Enter Key
	if _, err = fmt.Scanln(); err != nil {
		return err
	}
	if err := openBrowser(urlSettingsSSHNew); err != nil {
		fmt.Printf("Warning: failed to open browser automatically: %v\n", err)
		fmt.Printf("Please open the above URL manually in your browser.\n")
	}
	_, err = fmt.Scanln() // wait for Enter Key
	return err
}

func configureSSOPrompt(hostname string) error {
	var urlSettingsKeys = fmt.Sprintf("https://%s/settings/keys", hostname)

	fmt.Printf(`
Authorise SSH Key for SSO (manual instructions)
-----------------------------------------------

1. Press Enter to open %s
2. %s
3. Return here and press Enter to continue
`, urlSettingsKeys, configureSSOInstruction)
	// wait for Enter Key
	if _, err := fmt.Scanln(); err != nil {
		return err
	}
	if err := openBrowser(urlSettingsKeys); err != nil {
		fmt.Printf("Warning: failed to open browser automatically: %v\n", err)
		fmt.Printf("Please open the above URL manually in your browser.\n")
	}
	_, err := fmt.Scanln() // wait for Enter Key
	return err
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd.Run()
}

// upsert ssh config with host to use keyfile
// when adding a new host, set AddKeysToAgent and UseKeychain to yes (macOS only)
// as per https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent
func updateSSHConfig(sshConfigPath string, keyFile string, hostname string) error {
	// open ssh config, creating it if it doesn't exist
	f, err := os.OpenFile(expand(sshConfigPath), os.O_CREATE|os.O_RDWR, 0666)
	if err != nil {
		return err
	}
	defer f.Close()

	// read ssh config
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return err
	}

	host, identifyFileNode := findHostAndKey(sshConfigPath, cfg, hostname, "IdentityFile")

	var newSSHConfig, msg string
	if identifyFileNode != nil {
		if identifyFileNode.Value == keyFile {
			msg = fmt.Sprintf("✓ Host %s in %s already configured\n", hostname, sshConfigPath)
		} else {
			identifyFileNode.Value = keyFile
			msg = fmt.Sprintf("✓ Updated Host %s in %s to use key file\n", hostname, sshConfigPath)
			newSSHConfig = cfg.String()
		}
	} else if host != nil {
		identifyFileNode = &ssh_config.KV{Key: "IdentityFile", Value: keyFile}
		// prepend to preserve comments/whitespace between hosts
		host.Nodes = append([]ssh_config.Node{identifyFileNode}, host.Nodes...)
		newSSHConfig = cfg.String()
		msg = fmt.Sprintf("✓ Added IdentityFile to Host %s in %s\n", hostname, sshConfigPath)
	} else { // host == nil
		// add new node ourselves as strings rather than a new Node so we can
		// control indentation see https://github.com/kevinburke/ssh_config/issues/12
		// and separation
		var separator string
		if cfg.String() == "" {
			// new ssh config
			separator = ""
		} else {
			// separator new host from previous hosts
			separator = "\n"
		}
		// UseKeychain is macOS-specific and not supported on Windows/Linux
		useKeychainLine := ""
		if osName == "darwin" {
			useKeychainLine = "  UseKeychain yes\n"
		}
		newSSHConfig = fmt.Sprintf(`%s%sHost %s
  AddKeysToAgent yes
%s  IdentityFile %s
`, cfg.String(), separator, hostname, useKeychainLine, keyFile)
		msg = fmt.Sprintf("✓ Added Host %s to %s\n", hostname, sshConfigPath)
	}

	if newSSHConfig != "" {
		_, err = f.Seek(0, 0)
		if err != nil {
			return err
		}

		_, err = f.WriteString(newSSHConfig)
		if err != nil {
			return err
		}

		// newSshConfig may be smaller than the existing file contents
		// so truncate to the new size
		err = f.Truncate(int64(len(newSSHConfig)))
		if err != nil {
			return err
		}
	}

	fmt.Print(msg)
	return nil
}

func findHostAndKey(sshConfigPath string, cfg *ssh_config.Config, hostname string, key string) (*ssh_config.Host, *ssh_config.KV) {
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
					fmt.Printf("ℹ Host %sin %s ignored because it includes other hosts\n", patterns, sshConfigPath)
					break
				}
				host = h
				break outer
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
