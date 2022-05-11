# certinject

certinject is a library for injecting certificates into various trust stores.  It currently supports CryptoAPI (most Windows software) and NSS (most GNU/Linux software as well as some cross-platform software such as Firefox).

## Why use certinject instead of Windows certutil?

* certinject can inject certs without Administrator privileges.
* certinject can set the Extended Key Usage (AKA Enhanced Key Usage) and Name Constraints properties on injected certs.  Setting the properties and injecting the cert are a single atomic operation.

## Building

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands without Go modules (works on any platform with Bash; only Go 1.15-1.16.x; will not work on Go 1.17+):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `export GO111MODULE=off` to disable Go modules.

3. Run `go get -d -t -u github.com/namecoin/certinject/...`. The certinject source code will be
   retrieved automatically.

4. Run `go generate github.com/namecoin/certinject/...`. Some intermediate Go code will be
   generated.

5. Run `go get -t github.com/namecoin/certinject/...`. The certinject source code will be built.
   The binary of the command-line tool `certinject` will be placed in `$GOPATH/bin`

Option B: Using Go build commands with Go modules (works on any platform with Bash; Go 1.15+:

1. Clone certinject via Git.

2. Run the following in the certinject directory to set up Go modules:
   
   ~~~
   go mod init github.com/namecoin/certinject
   go mod tidy
   go generate ./...
   go mod tidy
   ~~~

3. Run `go install ./...`.  certinject will be built. The binaries will be at `$GOPATH/bin/certinject`.

Option C: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

## Configuration

TODO.

## Maintenance Status

NSS support is currently unmaintained.  We may accept patches for it, but we are unlikely to fix NSS-related bugs ourselves.  All other functionality is maintained.

## Licence

Copyright (C) 2017-2020 Namecoin Developers.

certinject is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

certinject is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with certinject.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
