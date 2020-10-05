try {
  Write-Host "----- Publicly trusted TLS website; no injection -----"
  Invoke-WebRequest -Uri "https://github.com/" -Method GET -UseBasicParsing
  If (!$?) {
    Write-Host "self-signed test #0 failed"
    exit 111
  }
}
catch {
  Write-Host "failed"
  exit 112
}
Write-Host "Good; GET request succeeded."

# try GET request to a self-signed certificate
try {
  Write-Host "----- Self-signed end-entity TLS website; no injection -----"
  Invoke-WebRequest -Uri "https://self-signed.badssl.com/" -Method GET -UseBasicParsing
  If ($?) {
    Write-Host "self-signed test #1 failed"
    exit 113
  }
}
catch {
  Write-Host "Good. GET request to self-signed cert has failed ($Error)"
}

Write-Host "----- Self-signed end-entity TLS website; injecting certificate into System/Root -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/badssl.com.der.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

# try GET request again
Write-Host "trying GET request after certificate injection"
Invoke-WebRequest -Uri "https://self-signed.badssl.com/" -Method GET -UseBasicParsing
If (!$?) {
  Write-Host "self-signed test #2 failed"
  exit 333
}
Write-Host "Good, Injection Success"

# try GET request to an untrusted root CA certificate
try {
  Write-Host "----- Untrusted root CA TLS website; no injection -----"
  Invoke-WebRequest -Uri "https://untrusted-root.badssl.com/" -Method GET -UseBasicParsing
  If ($?) {
    Write-Host "self-signed test #3 failed"
    exit 444
  }
}
catch {
  Write-Host "Good. GET request to untrusted root CA cert has failed ($Error)"
}

Write-Host "----- Untrusted root CA TLS website; injecting root CA certificate into System/Root -----"
# inject certificate into trust store
Write-Host "injecting certificate into trust store"
& "certinject.exe" "-certinject.cert" "testdata/untrusted-root.badssl.com.ca.pem.cert" "-certstore.cryptoapi"
If (!$?) {
  Write-Host "certificate injection failed"
  exit 222
}

# try GET request again
Write-Host "trying GET request after certificate injection"
Invoke-WebRequest -Uri "https://untrusted-root.badssl.com/" -Method GET -UseBasicParsing
If (!$?) {
  Write-Host "self-signed test #4 failed"
  exit 333
}
Write-Host "Good, Injection Success"

# all done
Write-Host "----- self-signed tests passed -----"
exit 0
