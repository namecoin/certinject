#!/bin/bash
set -ex

# set GOPATH if empty (travis sets it, but useful for humans)
if [ -z "$GOPATH" ]; then
GOPATH=$(go env GOPATH)
export GOPATH
fi

# workaround for go1.10's no module support, we copy this run's source code
# into $GOPATH/src/github.com/namecoin/certinject to avoid downloading our master branch.
#
# this only affects forks running travis runs. ( Pull requests and autobuilds
# will clone into: PWD=/c/Users/travis/gopath/src/github.com/namecoin/certinject )
if [ "$TRAVIS_GO_VERSION" = "1.10.x" ] && [ ! -d "$GOPATH"/src/github.com/namecoin/certinject ]; then
  mkdir "$GOPATH"/src/github.com/namecoin && \
  cp -av "$PWD" "$GOPATH"/src/github.com/namecoin/certinject && \
  cd "$GOPATH"/src/github.com/namecoin/certinject
fi

echo Generating Go source code
go generate ./...

echo Fetching dependencies
go get -v -t ./...

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
