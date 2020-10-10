param (
  $physical_store
)

$logical_store = "Disallowed"

Write-Host "----- Running TLS handshake tests for $physical_store/$logical_store -----"

Write-Host "----- Publicly trusted TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting intermediate CA PEM certificate into $physical_store/$logical_store -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/lets-encrypt-intermediate.ca.pem.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Cleanup $physical_store/$logical_store via certutil -----"
$root_cn = "Let's Encrypt Authority X3"
If ( "system" -eq $physical_store ) {
  & "certutil" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}
If ( "enterprise" -eq $physical_store ) {
  & "certutil" "-enterprise" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}
If ( "group-policy" -eq $physical_store ) {
  & "certutil" "-grouppolicy" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}

# all done
Write-Host "----- All TLS handshake tests for $physical_store/$logical_store passed -----"
exit 0
