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

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "enterprise" "-logical_store" "AuthRoot"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "group-policy" "-logical_store" "Root"
If (!$?) {
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/ci-trusted-tests.ps1" "-physical_store" "group-policy" "-logical_store" "AuthRoot"
If (!$?) {
  exit 222
}

# all done
Write-Host "----- All TLS handshake tests passed -----"
exit 0
