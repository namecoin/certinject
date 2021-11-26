param (
  $physical_store,
  $logical_store
)

Write-Host "----- Running TLS handshake tests for $physical_store/$logical_store -----"

Write-Host "----- Publicly trusted TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://www.namecoin.org/"
If (!$?) {
  exit 222
}

Write-Host "----- Self-signed end-entity TLS website; no injection -----"

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://self-signed.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

# Extract via: torsocks openssl s_client -showcerts -servername self-signed.badssl.com -connect self-signed.badssl.com:443 < /dev/null | openssl x509 -outform DER > testdata/badssl.com.der.cert
Write-Host "----- Self-signed end-entity TLS website; injecting DER certificate into $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/badssl.com.der.cert" "-certstore.cryptoapi"
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

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with EKU Email -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.email"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with EKU Any -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.any"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with EKU Client -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.client"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with EKU Server -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.server"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with NC Permitted DNS matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.permitted-dns" "badssl.com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with NC Permitted DNS non-matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.permitted-dns" "notbadssl.com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with NC Excluded DNS matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.excluded-dns" "badssl.com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with NC Excluded DNS non-matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.excluded-dns" "notbadssl.com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with 2-step EKU Client + Non-BlobReset NC Permitted DNS matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.client"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.permitted-dns" "badssl.com"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA PEM certificate into $physical_store/$logical_store with 2-step EKU Client + BlobReset NC Permitted DNS matching 2LD -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-eku.client"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi" "-nc.permitted-dns" "badssl.com" "-capi.reset"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/"
If (!$?) {
  exit 222
}

Write-Host "----- Untrusted root CA TLS website; editing SHA1 of root CA PEM certificate into $physical_store/$logical_store with EKU Client -----"
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-capi.physical-store" "$physical_store" "-capi.logical-store" "$logical_store" "-capi.search-sha1" "7890C8934D5869B25D2F8D0D646F9A5D7385BA85" "-certstore.cryptoapi" "-eku.client"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

& "powershell" "-ExecutionPolicy" "Unrestricted" "-File" "testdata/try-tls-handshake.ps1" "-url" "https://untrusted-root.badssl.com/" "-fail"
If (!$?) {
  exit 222
}

Write-Host "----- Cleanup $physical_store/$logical_store via certutil -----"
$root_cn = "BadSSL Untrusted Root Certificate Authority"
$self_signed_cn = "*.badssl.com"
If ( "system" -eq $physical_store ) {
  & "certutil" "-delstore" "$logical_store" "$self_signed_cn"
  If (!$?) {
    exit 222
  }
  & "certutil" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}
If ( "enterprise" -eq $physical_store ) {
  & "certutil" "-enterprise" "-delstore" "$logical_store" "$self_signed_cn"
  If (!$?) {
    exit 222
  }
  & "certutil" "-enterprise" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}
If ( "group-policy" -eq $physical_store ) {
  & "certutil" "-grouppolicy" "-delstore" "$logical_store" "$self_signed_cn"
  If (!$?) {
    exit 222
  }
  & "certutil" "-grouppolicy" "-delstore" "$logical_store" "$root_cn"
  If (!$?) {
    exit 222
  }
}

# all done
Write-Host "----- All TLS handshake tests for $physical_store/$logical_store passed -----"
exit 0
