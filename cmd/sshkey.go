package cmd

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cli/safeexec"
	"github.com/spf13/cobra"
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
	fmt.Println("sshkey called")
	err := resetSshAgent()
	if err != nil {
		return err
	}
	return nil
}

// printf "\nRemoving these existing identities:\n"
// ssh-add -l
// ssh-add -D
// printf "\n"

func resetSshAgent() error {
	// in case ssh-agent has loaded incorrect keys, lets start afresh

	sshAdd, err := safeexec.LookPath("ssh-add")
	if err != nil {
		return err
	}

	fmt.Println("Removing these existing identities")

	cmd := exec.Command(sshAdd, "-l")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() != 1 {
				return err
			}
			// exit status = 1 can mean no keys loaded, so we ignore this
		}
		return err
	}

	cmd = exec.Command(sshAdd, "-D")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if err != nil {
		return err
	}

	fmt.Println()

	return nil
}
