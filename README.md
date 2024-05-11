# Github Doctor

[Github CLI](https://github.com/cli/cli) extension to set up new or rotate existing github ssh keys.

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
 * create a private ssh key file
 * add the github host to ~/.ssh/config
 * upload the ssh key to your Github user account

Example entry added to ~/.ssh/config:

Host github.com
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/github.com

Usage:
  gh doctor ssh [flags]

Flags:
  -h, --hostname string   Github hostname (default "github.com")
  -k, --keyfile string    Private key file (default "~/.ssh/[hostname]")
  -r, --rotate            Rotate existing key (if any)

Global Flags:
      --help   Show help for command
```
