try {
  Write-Host "trying GET request to a proper SSL website"
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

# try GET request to a self-signed certificate
try {
  Write-Host "trying GET request to a self-signed cert without certificate in store"
  Invoke-WebRequest -Uri "https://self-signed.badssl.com/" -Method GET -UseBasicParsing
  If ($?) {
    Write-Host "self-signed test #1 failed"
    exit 113
  }
}
catch {
  Write-Host "good. GET request to self-signed cert has failed ($Error)"
}

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
Write-Host "Injection Success"

# all done
Write-Host "self-signed tests passed"
exit 0
