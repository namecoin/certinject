#!/bin/bash

golangci_linter_version=v1.27.0

# fetch golangci-lint program

curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin ${golangci_linter_version}

# run linters

echo ----- Windows -----
GOOS=windows $(go env GOPATH)/bin/golangci-lint run --no-config --enable-all \
  --color always \
  --disable gochecknoglobals,gomnd \
  -v $@ \
  ./...

echo ----- Linux -----
GOOS=linux $(go env GOPATH)/bin/golangci-lint run --no-config --enable-all \
  --color always \
  --disable gochecknoglobals,gomnd \
  -v $@ \
  ./...

