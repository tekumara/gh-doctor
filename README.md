# GitHub Doctor

GitHub Doctor creates SSH keys and optionally uploads them to your account. It can also rotate existing keys.

Commands are idempotent and can be re-run, making GitHub Doctor easy to use in scripts and useful for repairing misconfigurations.

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

To ensure SSH is working, creating a new key if needed, and uploading it to GitHub:

```sh
gh-doctor ssh -d
```

Or via the GitHub CLI extension:

```sh
gh doctor ssh -d
```

On a fresh machine this:

1. Fetches an OAuth token for the gh-doctor OAuth app. Opens a browser window to authenticate. This token is used once and not stored anywhere.
1. [Creates a new SSH key and configures your SSH config](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).
1. [Uploads the key to your account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account).

Example on a machine called beebop:

```
❯ gh-doctor ssh -d
ℹ Removing existing identities from SSH agent.
Please complete authentication in your browser...
https://github.com/login/oauth/authorize?client_id=Ov23liukLtggLaIpvb2o&code_challenge=O3YS8ZSA2_mZDPie&code_challenge_method=S256&redirect_uri=http%3A%2F%2F127.0.0.1%3A55254&response_type=code&scope=admin%3Apublic_key&state=4WAZT_6psyuBE
✓ Authenticated to github.com as tekumara using token
Creating key file /Users/tekumara/.ssh/github.com
Please specify a passphrase!
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Generating public/private ed25519 key pair.
Your identification has been saved in /Users/tekumara/.ssh/github.com
Your public key has been saved in /Users/tekumara/.ssh/github.com.pub
The key fingerprint is:
SHA256:F9pcXNW/NPP4tSATn2hxuPVr5Tx5LjrWKiCU86XugK8 github.com (beebop)
The key's randomart image is:
+--[ED25519 256]--+
|              ..o|
|           . .  .|
|       .  . +   .|
|      +  +.* o +.|
|     . oSo+ O +.=|
|     .. +. * +.o+|
|    . .o .. o..+*|
|     . .. . o o*=|
|    E....  oo+.o+|
+----[SHA256]-----+

✓ Key github.com (beebop) uploaded
✓ Added Host github.com to ~/.ssh/config
ℹ Server accepts key: /Users/tekumara/.ssh/github.com ED25519 SHA256:F9pcXNW/NPP4tSATn2hxuPVr5Tx5LjrWKiCU86XugK8 explicit
✓ Authenticated to github.com as tekumara using ssh
```

Run again to verify the SSH key. Because the key exists it will be verified rather than creating a new key. To rotate an existing key use the `-r` flag.

## Help

```
❯ gh-doctor ssh --help
Ensure ssh works.

Verify ssh and if needed:
 * Fetch a token using the gh-doctor OAuth app with scope to create SSH keys.
   This token is used once and not stored anywhere.
 * Create a private ssh key file.
 * Add the GitHub host to ~/.ssh/config.
 * Upload the ssh key to your GitHub user account (manually or using an OAuth app).

Example entry added to ~/.ssh/config:

Host github.com
  AddKeysToAgent yes
  UseKeychain yes
  IdentityFile ~/.ssh/github.com

During verification any SSH agent identities are removed in case incorrect keys were loaded.

Usage:
  gh-doctor ssh [flags]

Flags:
  -d, --doctoken          Use the GitHub Doctor OAuth app to upload the key
  -g, --ghtoken           Use GH_TOKEN env var then GitHub CLI OAuth app to upload the key
  -h, --hostname string   GitHub hostname (default "github.com")
  -k, --keyfile string    Private key file (default "~/.ssh/[hostname]")
  -r, --rotate            Rotate existing key (if any)
  -s, --sso               Prompt to authorise the key for organisations using SAML SSO

Global Flags:
      --help   Show help for command
```

## Uploading the key

### Manual upload

By default gh-doctor will prompt you to manually upload the key. This does not require gh-doctor to authenticate to GitHub using a token. It is guaranteed to create SSH keys that work for github.com, Github Enterprise Server (GHES) hosts, and any organisation.

### OAuth app (-d)

This uses the gh-doctor OAuth app to obtain an OAuth token with the `admin:public_key` scope. This token is used to upload the SSH key.

The token is used once and not stored anywhere.

By default [access via third-party applications](https://docs.github.com/en/organizations/managing-oauth-access-to-your-organizations-data/about-oauth-app-access-restrictions) to organisation resources is restricted. For your SSH key to work with organisation repos, you must request the gh-doctor OAuth app be [approved for use in your organisation](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-your-membership-in-organizations/requesting-organization-approval-for-oauth-apps).

Because of this, the gh-doctor OAuth app is most useful for github.com personal repos.

### GitHub CLI app (-g)

This will use any token in the GH_TOKEN environment variable, falling back to obtaining one from the [GitHub's official cli tool](https://github.com/cli/cli) (which must be installed separately). This token is used to upload the SSH key and must have the `admin:public_key` scope.

Unlike the gh-doctor OAuth app, this works by default for GHES and organisation resources because the GitHub CLI is considered an [internal OAuth app](https://docs.github.com/en/apps/oauth-apps/using-oauth-apps/internal-oauth-apps) and does not require approval for use.

NB: GitHub can only generate [long-lived OAuth tokens](https://github.com/cli/cli/issues/5924). The GitHub CLI persists these in the keychain, but `gh auth token` will [return the token in plaintext](https://github.com/cli/cli/issues/8237) bypassing any keychain security. It is therefore less secure that using a gh-doctor OAuth app token which is never stored. However, this is moot if you are already using the GitHub CLI.

### Organisations that use SAML single sign-on

If your organisation uses SAML single sign-on [authorise your SSH key](https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-an-ssh-key-for-use-with-saml-single-sign-on) for use with the organisation.

## Troubleshooting

### I can authenticate but can't pull or push an organisation repo

This happens when:

- your organisation uses SAML single sign-on and the [key hasn't been authorised](https://docs.github.com/en/enterprise-cloud@latest/authentication/authenticating-with-saml-single-sign-on/authorizing-an-ssh-key-for-use-with-saml-single-sign-on)
- you use a gh-doctor OAuth token to upload the key and the gh-doctor OAuth app has not been [approved for use in your organisation](https://docs.github.com/en/account-and-profile/setting-up-and-managing-your-personal-account-on-github/managing-your-membership-in-organizations/requesting-organization-approval-for-oauth-apps)

## FAQ

### How does GitHub Doctor compare to the GitHub CLI?

The GitHub CLI (gh) can [add an existing ssh key](https://cli.github.com/manual/gh_ssh-key_add) to your account. However:

- gh doesn't modify your ssh config, or load the key into the ssh agent as per the [GitHub docs](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent).
- gh doesn't diagnose and fix misconfigurations. Nor does it run idempotently.
- gh-doctor tokens are never persisted. GitHub can only generate [long-lived OAuth tokens](https://github.com/cli/cli/issues/5924) which don't expire. gh persists these tokens in the keychain, but `gh auth token` will [return the token in plaintext](https://github.com/cli/cli/issues/8237) bypassing any keychain security. gh-doctor tokens are only used once in-memory.
