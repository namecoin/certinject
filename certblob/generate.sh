#!/usr/bin/env bash

set -euo pipefail
shopt -s nullglob globstar

# wincrypt.h was downloaded from the following URL:
# https://raw.githubusercontent.com/mingw-w64/mingw-w64/2059ac24b9433da7917502ea8fb9e7b9531a2251/mingw-w64-headers/include/wincrypt.h
# Note that wincrypt.h only has property ID's from Windows Vista.
# wincrypt.h is implemented from MinGW-w64 and has property ID's up to 127.
# The MinGW's version of certenroll.h is an alternative, but it lacks several of the property IDs found in the MinGW's version of wincrypt.h.
# Since MinGW's header has more property IDs (127), it is preferred rather than ReactOS's header (84).

{
  printf 'package certblob\n\n'

  echo "const ("

  INITIALISM_SED_PROGRAM='s/(Ctl|Crl|Aia|Ca|Efs|Guid|Id|Ie30|Md5|Ocsp|Sha1|Url)([^a-z]|$)/\U\1\2/g'
  grep -E $'^#define CERT_.*PROP_ID +[0-9A-Z_]+($|\r)' wincrypt.h | sed 's/#define /\t/' | sed 's/_PROP_ID /_PROP_ID = /' | sed -E 's/(\s+|_)([A-Z])([A-Z]+)/\1\2\L\3/g' | sed 's/_//g' | sed -E 's/PropId( =|$)/PropID\1/g' | sed -E "$INITIALISM_SED_PROGRAM" | sed -E "$INITIALISM_SED_PROGRAM"

  echo ")"
} > propids.go

gofmt -w propids.go
