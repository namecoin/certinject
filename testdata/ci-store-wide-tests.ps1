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

Write-Host "----- Publicly trusted TLS website; injecting Magic into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-capi.set-magic-name" "foo" "-capi.set-magic-data" "5"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting NC Excluded DNS non-matching TLD with matching Magic Skip into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-nc.excluded-dns" "com" "-capi.skip-magic-name" "foo" "-capi.skip-magic-data" "5"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting NC Excluded DNS non-matching TLD with non-matching Magic Skip Name into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-nc.excluded-dns" "com" "-capi.skip-magic-name" "bar" "-capi.skip-magic-data" "5"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/"
If (!$?) {
  exit 222
}

Write-Host "----- Publicly trusted TLS website; injecting NC Excluded DNS matching TLD with non-matching Magic Skip Value into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-nc.excluded-dns" "org" "-capi.skip-magic-name" "foo" "-capi.skip-magic-data" "2"
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

Write-Host "----- Injecting Magic with Watch into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
Start-Process "certinject.exe" "-capi.physical-store $physical_store -capi.logical-store $logical_store -capi.all-certs -capi.watch -certstore.cryptoapi -capi.set-magic-name watch1 -capi.set-magic-data 1 -xlog.severity INFO -xlog.file watch.txt"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

Write-Host "Waiting for Magic Watch to stabilize"
Start-Sleep -seconds 5

$watch_base_size = (Get-Item ".\watch.txt").length
Write-Host "Magic Watch log base size: $watch_base_size"

Write-Host "Checking if Magic Watch is stable..."
Start-Sleep -seconds 5

$watch_base_size_2 = (Get-Item ".\watch.txt").length
Write-Host "Magic Watch log base size 2: $watch_base_size_2"
If ( $watch_base_size -ne $watch_base_size_2 ) {
  Write-Host "Magic Watch not stable!  Spontaneously increased to $watch_base_size_2"
  exit 222
}

Write-Host "----- Injecting Magic to trigger Watch into store-wide $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.all-certs" "-certstore.cryptoapi" "-capi.set-magic-name" "watch2" "-capi.set-magic-data" "2"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

Write-Host "Waiting for Magic Watch to stabilize"
Start-Sleep -seconds 5

$watch_new_size = (Get-Item ".\watch.txt").length
Write-Host "Magic Watch log new size: $watch_new_size"
If ( $watch_base_size -eq $watch_new_size ) {
  Write-Host "Magic Watch did not trigger!"
  exit 222
}

Write-Host "Checking if Magic Watch is stable..."
Start-Sleep -seconds 5

$watch_new_size_2 = (Get-Item ".\watch.txt").length
Write-Host "Magic Watch log new size 2: $watch_new_size_2"
If ( $watch_new_size -ne $watch_new_size_2 ) {
  Write-Host "Magic Watch not stable!  Spontaneously increased to $watch_new_size_2"
  exit 222
}

# all done
Write-Host "----- All TLS handshake tests for store-wide $physical_store/$logical_store passed -----"
exit 0
