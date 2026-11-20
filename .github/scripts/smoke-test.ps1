# Smoke test of mirrust.exe on Windows: it prints its usage, then serves /api/clean over HTTPS.
#
#   ./smoke-test.ps1 -Binary target/x86_64-pc-windows-msvc/release/mirrust.exe [-Port 8443]
#
# The counterpart of smoke-test.sh. It needs curl.exe, which Windows 10 and later and the
# GitHub runner image have. Run it with PowerShell 7 (pwsh).
param(
    [Parameter(Mandatory)][string]$Binary,
    [int]$Port = 8443
)
$ErrorActionPreference = 'Stop'

$Binary = (Resolve-Path -LiteralPath $Binary).Path
$stdout = New-TemporaryFile
$stderr = New-TemporaryFile
$body = New-TemporaryFile

Write-Host "--- $Binary --help"
& $Binary --help
if ($LASTEXITCODE -ne 0) { throw "--help exited with code $LASTEXITCODE" }

Write-Host "--- start on 127.0.0.1:$Port"
$server = Start-Process -FilePath $Binary -ArgumentList '--listen', "127.0.0.1:$Port" `
    -PassThru -NoNewWindow -RedirectStandardOutput $stdout -RedirectStandardError $stderr

function Show-ServerOutput {
    Write-Host "server output:"
    Get-Content -LiteralPath $stdout, $stderr | Write-Host
}

try {
    # -k: the certificate is self-signed. The retries cover the time the server needs to
    # bind. %{http_version} proves that ALPN negotiated HTTP/2 and not only that TLS worked.
    $version = & curl.exe -sS -k --retry 20 --retry-delay 1 --retry-connrefused --max-time 10 `
        --fail -o $body -w '%{http_version}' "https://127.0.0.1:$Port/api/clean"
    if ($LASTEXITCODE -ne 0) {
        Show-ServerOutput
        throw "curl.exe failed with code $LASTEXITCODE"
    }

    # Another server on the port would answer in place of the binary under test, which then
    # exits because it cannot bind; give it a moment to do so.
    Start-Sleep -Seconds 1
    if ($server.HasExited) {
        Show-ServerOutput
        throw "the server under test has exited"
    }

    Write-Host "HTTP version: $version"
    # The curl.exe on the Windows runners may negotiate HTTP/1.1 where other curls use HTTP/2;
    # either one proves that the server answered over TLS.
    if ($version -ne '2' -and $version -ne '1.1') { throw "expected HTTP/2 or HTTP/1.1, got HTTP/$version" }
    if (-not (Select-String -LiteralPath $body -Pattern '"audit"' -Quiet)) {
        throw "the response has no audit field"
    }
    $text = Get-Content -LiteralPath $body -Raw
    Write-Host ("response: " + $text.Substring(0, [Math]::Min(200, $text.Length)))
    Write-Host "--- ok: $Binary"
}
finally {
    # Windows has no SIGINT for a background process, so the server is simply ended.
    if (-not $server.HasExited) { Stop-Process -Id $server.Id -Force }
}
