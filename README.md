# certinject

certinject is a library for injecting certificates into various trust stores.  It currently supports CryptoAPI (most Windows software) and NSS (most GNU/Linux software as well as some cross-platform software such as Firefox).

## Building

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands (works on any platform with Bash):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `go get -t -u github.com/namecoin/certinject/...`. The certinject source code will be
   retrieved automatically and built.

Option B: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

## Configuration

TODO.

## Licence

© 2017-2020 Namecoin Developers.  Licenced under the GPLv3 or later.
