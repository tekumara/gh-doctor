#!/usr/bin/env bash

set -euo pipefail

echo "install https://github.com/Link-/gh-token"
tmp_dir=$(mktemp -d) && pushd "$tmp_dir"

version=2.0.1
case "$(uname -sm)" in
    "Linux aarch64") sha256=b65e0e6b23e6798fad336cd453741c2f68ad2fe9b4aa6d069e1474b004806ecb && arch=arm64 ;;
    "Linux x86_64")  sha256=f76e8cb35f0b04b59073a486cc952e50fa9f1c930a25619ea9abcf44a13165c4 && arch=amd64 ;;
    *) echo "error: unknown arch $(uname -sm)" && exit 42;;
esac

curl -fsSLo gh-token "https://github.com/Link-/gh-token/releases/download/v${version}/linux-${arch}"
sha256sum gh-token
echo "$sha256  gh-token"  | sha256sum --check

install gh-token /usr/local/bin
popd && rm -rf "$tmp_dir"

app_token=$(gh token generate --token-only \
    --key <(echo "$APP_PRIVATE_KEY") \
    --app-id "$APP_ID" \
    --installation-id 5566778)
echo "APP_TOKEN=$app_token" >> $GITHUB_ENV
