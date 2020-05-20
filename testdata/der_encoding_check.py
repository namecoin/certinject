#!/bin/env python3
from asn1crypto.x509 import Certificate
import sys
if len(sys.argv) != 2:
    print("usage:", sys.argv[0], "certificate-file")
    quit(111)
with open(sys.argv[1], "rb") as f:
    try:
        cert = Certificate.load(f.read())
    except:
        print("not a DER encoded certificate:", sys.argv[1])
        quit(111)
print("DER encoded certificate:", sys.argv[1])
