Write-Host "----- Running TLS handshake tests -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "system" "-logical_store" "Root"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "system" "-logical_store" "AuthRoot"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "enterprise" "-logical_store" "Root"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "group-policy" "-logical_store" "Root"
If (!$?) {
  exit 222
}

# enterprise/AuthRoot and group-policy/AuthRoot are *not* trusted by CryptoAPI.

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-disallowed-tests.ps1" "-physical_store" "system"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-disallowed-tests.ps1" "-physical_store" "enterprise"
If (!$?) {
  exit 222
}

# group-policy/Disallowed doesn't seem to work reliably.  Maybe because they
# expect you to use a Disallowed CTL instead?  Need to investigate further.

# all done
Write-Host "----- All TLS handshake tests passed -----"
exit 0
