# GitHub Doctor

GitHub Doctor creates SSH keys and uploads them to your account. It can also rotate existing keys.

Commands are idempotent and can be re-run. This makes GitHub Doctor easy to use in scripts.

## Install

Using homebrew:

```sh
 brew install tekumara/tap/gh-doctor
```

As a [GitHub CLI](https://github.com/cli/cli) extension:

```sh
gh extension install tekumara/gh-doctor
```

## Usage

To ensure SSH is working, creating a new key if needed:

```sh
gh-doctor ssh
```

Or via the GitHub CLI extension:

```sh
gh doctor ssh
```

On a fresh machine this will:

1. Fetch an OAuth token for the Github Doctor OAuth app. Will open a browser window to authenticate. This token is used once and and not stored anywhere.
1. [Create a new SSH key and configure your SSH config](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).
1. [Upload the key to your account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).

Run this again to verify the SSH key. Because the key exists it will be verified rather than creating a new key. To rotate an existing key use the `-r` flag.

## Help

```
❯ gh-doctor ssh --help
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
