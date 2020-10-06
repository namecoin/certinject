# Warning!  This script must be run in a fresh PowerShell process.  Otherwise,
# PowerShell will cache any successful cert validation results, so you'll be
# getting fictitious results.

param (
  $url,
  [switch] $fail
)

$should_succeed = -not $fail

try {
  Invoke-WebRequest -Uri "$url" -Method GET -UseBasicParsing
  $success = $?
  if ( ( $success ) -ne ( $should_succeed ) ) {
    Write-Host "TLS test failed"
    exit 111
  }
}
catch {
  if ( $should_succeed ) {
    Write-Host "TLS test failed: $Error"
    exit 111
  }
  else {
    Write-Host "Good, TLS handshake rejected: $Error"
    exit 0
  }
}

Write-Host "Good; TLS test passed."
exit 0
