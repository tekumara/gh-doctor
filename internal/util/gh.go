package util

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/cli/go-gh/v2"
)

// GH_PROMPT_DISABLED ensures the minimal amount of prompting eg: during gh auth login
// GH_NO_UPDATE_NOTIFIER prevents notification of a new gh release
var ghEnv = []string{"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1"}

func ExecGhInteractive(args ...string) error {
	return execGh(nil, args...)
}

func ExecGhInteractiveWithEnv(env []string, args ...string) error {
	return execGh(env, args...)
}

// Invoke a gh command in a subprocess with its stdin, stdout, and stderr streams connected to
// those of the parent process. This is suitable for running gh commands with interactive prompts.
// Adapted from https://github.com/cli/go-gh/blob/47a83eeb1778d8e60e98e356b9e5d6178a567f31/gh.go#L41
func execGh(env []string, args ...string) error {
	ghExe, err := gh.Path()
	if err != nil {
		return err
	}
	cmd := exec.Command(ghExe, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	env = append(ghEnv, env...)
	// append this processes's env vars so gh can locate its config, state and data dirs
	// as per https://github.com/cli/go-gh/blob/47a83eeb1778d8e60e98e356b9e5d6178a567f31/pkg/config/config.go#L236
	cmd.Env = append(env, os.Environ()...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gh execution failed: %w", err)
	}
	return nil
}
