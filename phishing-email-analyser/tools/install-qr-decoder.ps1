# Cybersteps one-time jsQR installer for Windows PowerShell 5.1+.
# The npm archive is pinned with a known SHA-512; no remote JavaScript is used at runtime.
$ErrorActionPreference = 'Stop'
$expected = 'dxLob7q65Xg2DvstYkRpkYtmKm2sPJ9oFhrhmudT1dZvNFFTlroai3AWSpLey/w5vMcLBXRgOJsbXpdN9HzU/A=='
$url = 'https://registry.npmjs.org/jsqr/-/jsqr-1.4.0.tgz'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('cybersteps-jsqr-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $tgz = Join-Path $tmp 'jsqr.tgz'
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Write-Host 'Downloading jsQR 1.4.0 from npm and validating SHA-512...'
  Invoke-WebRequest -Uri $url -OutFile $tgz -UseBasicParsing -TimeoutSec 30
  if ((Get-Item $tgz).Length -gt 1500000) { throw 'npm package exceeds 1.5 MB cap' }
  $sha = [System.Security.Cryptography.SHA512]::Create()
  try { $bytes = [System.IO.File]::ReadAllBytes($tgz); $digest = [Convert]::ToBase64String($sha.ComputeHash($bytes)) }
  finally { $sha.Dispose() }
  if ($digest -cne $expected) { throw 'Package SHA-512 mismatch. No files installed.' }
  & tar.exe -xzf $tgz -C $tmp package/dist/jsQR.js package/LICENSE
  if ($LASTEXITCODE -ne 0) { throw 'Unable to extract verified npm package' }
  $js = Join-Path $tmp 'package/dist/jsQR.js'
  $license = Join-Path $tmp 'package/LICENSE'
  if (!(Test-Path $js) -or !(Test-Path $license)) { throw 'Required assets absent' }
  if ((Get-Item $js).Length -gt 500000 -or (Get-Item $license).Length -gt 500000) { throw 'Extracted asset too large' }
  if (-not (Select-String -Path $js -Pattern 'webpackUniversalModuleDefinition' -Quiet)) { throw 'Unexpected jsQR bundle format' }
  if (-not (Select-String -Path $license -Pattern 'Apache License' -Quiet)) { throw 'Apache license not found' }
  $htmlPath = Join-Path $root 'index.html'
  $html = [System.IO.File]::ReadAllText($htmlPath)
  $anchor = '<!-- The verified offline jsQR decoder is installed by tools/install-qr-decoder.py or tools/install-qr-decoder.ps1. -->'
  $script = '<script src="js/vendor/jsQR.js"></script>'
  if (-not $html.Contains($anchor) -and -not $html.Contains($script)) { throw 'HTML insertion point missing' }
  $dest = Join-Path $root 'js/vendor'
  New-Item -ItemType Directory -Force -Path $dest | Out-Null
  Copy-Item $js (Join-Path $dest 'jsQR.js') -Force
  Copy-Item $license (Join-Path $dest 'jsQR.LICENSE') -Force
  $lock = @{
    library='jsqr'; version='1.4.0'; license='Apache-2.0'; runtime_network=$false;
    npm_tarball=$url; npm_integrity=('sha512-' + $expected);
    provenance='npm published v1.4.0 integrity; verified SHA-512 before extraction';
    sha256=@{
      'jsQR.js'=(Get-FileHash -Path $js -Algorithm SHA256).Hash.ToLowerInvariant();
      'jsQR.LICENSE'=(Get-FileHash -Path $license -Algorithm SHA256).Hash.ToLowerInvariant()
    }
  }
  $utf8 = New-Object System.Text.UTF8Encoding($false)
  [System.IO.File]::WriteAllText((Join-Path $dest 'jsQR.lock.json'), ($lock | ConvertTo-Json -Depth 8), $utf8)
  if (-not $html.Contains($script)) {
    [System.IO.File]::WriteAllText($htmlPath, $html.Replace($anchor, ($anchor + "`n" + $script)), $utf8)
  }
  Write-Host 'Success: jsQR is installed LOCALLY. Reload Cybersteps and test: typeof window.jsQR' -ForegroundColor Green
  Write-Host 'Important: regenerate release manifest before pushing these changes.'
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
