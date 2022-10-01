#!/usr/bin/env bash

set -euxo pipefail
shopt -s nullglob globstar

# Example usage: ./save-cert-from-server.bash self-signed.badssl.com der

SERVER_NAME=$1
FORMAT=$2

openssl s_client -connect "$SERVER_NAME":443 -servername "$SERVER_NAME" | openssl x509 -inform pem -outform "$FORMAT" -out "$SERVER_NAME"."$FORMAT".cert
