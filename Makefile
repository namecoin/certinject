# Copyright 2020 Namecoin Developers, GPLv3+

buildflags = -v -ldflags '-w -s' -tags netgo,osusergo
GOBIN := $(PWD)/bin
export GOBIN

# ./certinject or ./certinject.exe (on windows)
default: *.go cmd/certinject/*.go
	go get -v -d ./cmd/certinject
	go generate ./...
	go install $(buildflags) ./cmd/certinject

# cross compile
bin/certinject.exe: *.go cmd/certinject/*.go
	env GOOS=windows GOARCH=amd64 go generate ./...
	env GOOS=windows GOARCH=amd64 go build $(buildflags) -o $@ ./cmd/certinject
	strip $@
bin/certinject-linux-amd64: *.go cmd/certinject/*.go
	env GOOS=linux GOARCH=amd64 go generate ./...
	env GOOS=linux GOARCH=amd64 go build $(buildflags) -o $@ ./cmd/certinject
	strip $@
bin/certinject-osx-amd64: *.go cmd/certinject/*.go
	env GOOS=darwin GOARCH=amd64 go generate ./...
	env GOOS=darwin GOARCH=amd64 go build $(buildflags) -o $@ ./cmd/certinject
all: bin/certinject.exe bin/certinject-linux-amd64 bin/certinject-osx-amd64
clean:
	rm -rvf ./bin
test:
	go get -v -d -t ./...
	go generate ./...
	go test ./...
PHONY += all
PHONY += clean
PHONY += default
PHONY += test
