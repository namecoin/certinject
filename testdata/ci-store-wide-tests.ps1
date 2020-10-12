$physical_store = "system"
$logical_store = "AuthRoot"

Write-Host "----- Running TLS handshake tests for store-wide $physical_store/$logical_store -----"

Write-Host "----- Publicly trusted TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting NC Excluded DNS matching TLD into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-nc.excluded-dns" "org"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting NC Excluded DNS non-matching TLD into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-nc.excluded-dns" "com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/"
If (!$?) {
  exit 222
}

# all done
Write-Host "----- All TLS handshake tests for store-wide $physical_store/$logical_store passed -----"
exit 0
