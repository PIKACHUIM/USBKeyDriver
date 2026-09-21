# Build the GM3000 PKCS#11 shim (32-bit, MSVC x86).
# Output: build\gm3000_pkcs11.dll
#
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File build.ps1
#
# NOTE: keep this script pure ASCII. Windows PowerShell 5.1 reads .ps1 files
#       without a BOM as ANSI, which corrupts non-ASCII text.
$ErrorActionPreference = 'Stop'

$vcvarsCandidates = @(
    'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars32.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Auxiliary\Build\vcvars32.bat',
    'C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars32.bat',
    'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars32.bat'
)
$vcvars = $vcvarsCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $vcvars) {
    Write-Error 'vcvars32.bat not found (MSVC x86 toolchain is required)'
    exit 1
}
Write-Host "[build] vcvars32 = $vcvars"

# Capture the x86 toolchain environment into this process.
$tmp = Join-Path $env:TEMP ('gmshim_env_' + [guid]::NewGuid().ToString('N') + '.cmd')
$content = "@echo off`r`ncall `"$vcvars`" >nul`r`nset"
Set-Content -Path $tmp -Value $content -Encoding ASCII
try {
    $lines = & cmd.exe /c $tmp
} finally {
    Remove-Item $tmp -Force -ErrorAction SilentlyContinue
}
foreach ($line in $lines) {
    if ($line -match '^([^=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
    }
}
$cl = (Get-Command cl.exe -ErrorAction SilentlyContinue).Source
Write-Host "[build] cl.exe = $cl"

Set-Location -Path $PSScriptRoot
if (-not (Test-Path 'build')) { New-Item -ItemType Directory 'build' | Out-Null }

& cl.exe /nologo /LD /O2 /W3 /utf-8 /D_CRT_SECURE_NO_WARNINGS shim.c `
    /link /DEF:shim.def '/OUT:build\gm3000_pkcs11.dll' '/PDB:build\gm3000_pkcs11.pdb'
if ($LASTEXITCODE -ne 0) {
    Write-Error "compile failed, cl exit code = $LASTEXITCODE"
    exit $LASTEXITCODE
}

$out = Join-Path $PSScriptRoot 'build\gm3000_pkcs11.dll'
$size = (Get-Item $out).Length
Write-Host "[ok] output: $out ($size bytes)"
