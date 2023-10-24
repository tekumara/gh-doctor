package cmd

import (
	"os"

	"github.com/spf13/cobra"
)



// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "gh-doctor",
	Short: "Diagnose github configuration.",
	Long: `Github Doctor.

Diagnose github configuration.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	// Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// don't use -h shorthand for help because we use it for hostname elsewhere
	rootCmd.PersistentFlags().Bool("help", false, "Show help for command")
	// don't display usage on error
	rootCmd.SilenceUsage = true
	//rootCmd.SilenceErrors = true
}


