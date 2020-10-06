Write-Host "----- Publicly trusted TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://github.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Self-signed end-entity TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://self-signed.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Self-signed end-entity TLS website; injecting DER certificate into System/Root -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/badssl.com.der.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://self-signed.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into System/Root -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into System/Root with EKU Email -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.email"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into System/Root with EKU Any -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.any"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into System/Root with EKU Client -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.client"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into System/Root with EKU Server -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.server"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

# all done
Write-Host "----- self-signed tests passed -----"
exit 0
