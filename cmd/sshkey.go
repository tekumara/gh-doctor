package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var opts struct {
	Hostname string
	KeyFile string
}

var sshkeyCmd = &cobra.Command{
	Use:   "ssh-key",
	Short: "Ensure a working ssh key.",
	Long: `Tests the ssh key is working, creating one if it doesn't`,
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println("sshkey called")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(sshkeyCmd)
	sshkeyCmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "github.com", "Github hostname")
}
