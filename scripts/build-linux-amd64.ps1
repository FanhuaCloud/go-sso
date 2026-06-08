param(
    [string]$OutputDir = "dist/go-sso-linux-amd64",
    [string]$BinaryName = "go-sso-linux-amd64"
)

$ErrorActionPreference = "Stop"

$repoRoot = Split-Path -Parent $PSScriptRoot
$outPath = Join-Path $repoRoot $OutputDir
$binaryPath = Join-Path $outPath $BinaryName

New-Item -ItemType Directory -Force -Path $outPath | Out-Null

Push-Location $repoRoot
try {
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"

    go build -trimpath -ldflags "-s -w" -o $binaryPath .

    Copy-Item -Force ".env.example" (Join-Path $outPath ".env.example")

    Write-Host "Built Linux amd64 binary:"
    Write-Host "  $binaryPath"
    Write-Host ""
    Write-Host "Upload this directory to your Linux server, then run:"
    Write-Host "  chmod +x ./$BinaryName"
    Write-Host "  cp .env.example .env"
    Write-Host "  ./$BinaryName"
}
finally {
    Pop-Location
    Remove-Item Env:\GOOS -ErrorAction SilentlyContinue
    Remove-Item Env:\GOARCH -ErrorAction SilentlyContinue
    Remove-Item Env:\CGO_ENABLED -ErrorAction SilentlyContinue
}
