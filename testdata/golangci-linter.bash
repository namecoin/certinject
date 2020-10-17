#!/bin/bash

set -euo pipefail
shopt -s nullglob globstar

golangci_linter_version=v1.31.0

# fetch golangci-lint program

curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b "$(go env GOPATH)"/bin ${golangci_linter_version}

# run linters

echo ----- Shell -----

# Run shellcheck on all shell scripts
# The .travis directory is currently unused (relic from ncdns).  It will be
# re-introduced later.  For now, we don't try to lint it, since it's inactive.
ALL_SHELL="$(grep -r --files-with-matches --exclude-dir=.git --exclude-dir=.travis '#!.*/bin/.*sh' ./)"
for I in $ALL_SHELL
do
    shellcheck "${I}"
done

echo "Shell checks passed."

echo ----- Windows -----
GOOS=windows go generate ./...
# NSS support is unmaintained; don't bother us with complaints about it.
GOOS=windows "$(go env GOPATH)"/bin/golangci-lint run --enable-all \
  --color always \
  --skip-files "file.go" \
  --skip-files "nss.go" \
  --disable gochecknoglobals,gomnd \
  -v "$@" \
  ./...

echo ----- Linux -----
GOOS=linux go generate ./...
GOOS=linux "$(go env GOPATH)"/bin/golangci-lint run --enable-all \
  --color always \
  --skip-files "file.go" \
  --skip-files "nss.go" \
  --disable gochecknoglobals,gomnd \
  -v "$@" \
  ./...

