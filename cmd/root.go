package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gh-doctor",
	Short: "Set up ssh and gh auth tokens.",
	Long: `Github Doctor

Set up ssh and gh auth tokens.

Commands are idempotent so they can be run in scripts.`,
}

func Execute(version string) {
	rootCmd.Version = version
	err := rootCmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, "X Error:", err.Error())
		os.Exit(1)
	}
}

func init() {
	// don't use -h shorthand for help because we use it for hostname elsewhere
	rootCmd.PersistentFlags().Bool("help", false, "Show help for command")
	// don't display usage on error
	rootCmd.SilenceUsage = true
	// we handle errors
	rootCmd.SilenceErrors = true
}
