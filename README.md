# Github Doctor

A [Github CLI extension](https://github.com/cli/cli) to set up github ssh keys and auth tokens. Or rotate existing credentials.

Commands are idempotent so they can be re-run which is useful in scripts.

## Example

To ensure ssh is working:

```shell
# ensure auth token exists with scope to add ssh key
gh doctor auth -s admin:public_key

# ensure ssh works, creating a new key if needed
gh doctor ssh
```

On a fresh machine this will create a token and set up ssh keys. Run this again to verify the existing token and ssh key.

## gh doctor auth

```
Ensure a working gh auth token.

Verify the auth token works and has any required scopes.

If a new token is needed the auth flow is triggered.

Usage:
  gh doctor auth [flags]

Flags:
  -h, --hostname string   Github hostname (default "github.com")
  -r, --refresh           Refresh existing token with minimum scopes + required scopes.
                          Does not revoke the old token.
  -s, --scopes strings    Required scopes. A new token is requested if these are missing.

Global Flags:
      --help   Show help for command
```

## gh doctor ssh

```
Ensure ssh works.

Verify ssh and if needed:
 * create a private ssh key file
 * configure ~/.ssh/config
 * upload the ssh key to your Github user account

Usage:
  gh doctor ssh [flags]

Flags:
  -h, --hostname string   Github hostname (default "github.com")
  -k, --keyfile string    Private key file (default "~/.ssh/[hostname]")
  -r, --rotate            Rotate existing key (if any)

Global Flags:
      --help   Show help for command
```
