#!/usr/bin/env bash
set -euo pipefail
command -v openssl >/dev/null || { echo "OpenSSL is required" >&2; exit 1; }
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
openssl genpkey -algorithm ED25519 -out "$tmpdir/private.pem"
openssl pkey -in "$tmpdir/private.pem" -pubout -out "$tmpdir/public.pem"
echo "Add these two lines to your local .env (never commit or share it):"
printf "SENTINEL_SIGNING_PRIVATE_KEY_B64="; base64 -w0 "$tmpdir/private.pem"; echo
printf "SENTINEL_SIGNING_PUBLIC_KEY_B64="; base64 -w0 "$tmpdir/public.pem"; echo
