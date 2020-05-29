#!/bin/bash
set -ex

# workaround for go1.10's no module support, we copy this run's source code into namecoin/certinject
if [ "$TRAVIS_REPO_SLUG" != "namecoin/certinject" ] && [ "$TRAVIS_GO_VERSION" = "1.10.x" ]; then
  mkdir $GOPATH/src/github.com/namecoin && \
  cp -av . $GOPATH/src/github.com/namecoin/certinject && \
  cd $GOPATH/src/github.com/namecoin/certinject
fi

echo Fetching dependencies
go get -v -u -t ./...

echo Building certinject.exe
go build -o certinject.exe ./cmd/certinject

if [ "$TRAVIS_OS_NAME" = "windows" ]; then
echo Running powershell tests
powershell -ExecutionPolicy Unrestricted -File "testdata/ci-failtest.ps1"
fi

echo Testing config parsing
./certinject.exe -conf testdata/test.conf

echo Running go test suite
go test -v ./...
