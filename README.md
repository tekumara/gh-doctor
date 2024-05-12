# GitHub Doctor

[GitHub CLI](https://github.com/cli/cli) extension to set up new or rotate existing GitHub ssh keys.

Commands are idempotent so they can be re-run which is useful in scripts.

## Example

To ensure ssh is working:

```shell
# ensure ssh works, creating a new key if needed
gh doctor ssh
```

On a fresh machine this will create a token and set up ssh config and create and upload keys. Run this again to verify the existing token and ssh key.

## gh doctor ssh

```
Ensure ssh works.

Verify ssh and if needed:
 * Fetch a token using the Github Doctor OAuth app with scope to create SSH keys.
   This token is used once and not stored anywhere.
 * Create a private ssh key file.
 * Add the GitHub host to ~/.ssh/config.
 * Upload the ssh key to your GitHub user account.

Example entry added to ~/.ssh/config:

Host github.com
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/github.com

During verification any SSH agent identities are removed in case incorrect keys were loaded.

Usage:
  gh-doctor ssh [flags]

Flags:
  -g, --ghtoken           Use GH_TOKEN env var then GitHub CLI for token. Useful for GHES hosts without the GitHub Doctor OAuth app.
  -h, --hostname string   GitHub hostname (default "github.com")
  -k, --keyfile string    Private key file (default "~/.ssh/[hostname]")
  -r, --rotate            Rotate existing key (if any)

Global Flags:
      --help   Show help for command
```
