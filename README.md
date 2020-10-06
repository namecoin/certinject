# certinject

certinject is a library for injecting certificates into various trust stores.  It currently supports CryptoAPI (most Windows software) and NSS (most GNU/Linux software as well as some cross-platform software such as Firefox).

## Building

Prerequisites:

1. Ensure you have the Go tools installed.

Option A: Using Go build commands (works on any platform with Bash):

1. Ensure you have the GOPATH environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `go get -d -t -u github.com/namecoin/certinject/...`. The certinject source code will be
   retrieved automatically.

3. Run `go generate github.com/namecoin/certinject/...`. Some intermediate Go code will be
   generated.

4. Run `go get -t github.com/namecoin/certinject/...`. The certinject source code will be built.
   The binary of the command-line tool `certinject` will be placed in `$GOPATH/bin`

Option B: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

## Configuration

TODO.

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
