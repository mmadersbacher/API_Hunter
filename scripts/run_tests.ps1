# Run format/lint/tests/build and capture logs
# Usage: Open PowerShell in project root and run: .\scripts\run_tests.ps1

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$root = (Resolve-Path .).Path
$logdir = Join-Path -Path $root -ChildPath (Join-Path "test-logs" $ts)
New-Item -ItemType Directory -Force -Path $logdir | Out-Null

function Run-CmdLog($name, $cmd, $arguments) {
    $outfile = Join-Path $logdir ($name + ".txt")
    Write-Host "Running: $cmd $arguments" -ForegroundColor Cyan
    $argArray = @()
    if ($arguments -ne $null -and $arguments -ne "") { $argArray = $arguments -split ' ' }
    & $cmd @argArray 2>&1 | Tee-Object -FilePath $outfile
    $exit = $LASTEXITCODE
    if ($exit -ne 0) { Write-Host "Command $name exited with $exit" -ForegroundColor Red }
    return $exit
}

# Ensure cargo is available
if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    Write-Host "cargo not found in PATH. Please ensure Rust toolchain is installed and cargo is on PATH." -ForegroundColor Red
    exit 1
}

$ret = 0
$ret = Run-CmdLog -name "fmt-check" -cmd "cargo" -arguments "fmt -- --check"
if ($ret -ne 0) { Write-Host "fmt check failed. See logs in $logdir" -ForegroundColor Red }

$ret = Run-CmdLog -name "clippy" -cmd "cargo" -arguments "clippy -- -D warnings"
if ($ret -ne 0) { Write-Host "clippy failed. See logs in $logdir" -ForegroundColor Red }

$ret = Run-CmdLog -name "tests" -cmd "cargo" -arguments "test --verbose"
if ($ret -ne 0) { Write-Host "tests failed. See logs in $logdir" -ForegroundColor Red }

$ret = Run-CmdLog -name "build-release" -cmd "cargo" -arguments "build --release"
if ($ret -ne 0) { Write-Host "build failed. See logs in $logdir" -ForegroundColor Red }

Write-Host "All commands completed. Logs written to: $logdir" -ForegroundColor Green
Write-Host "If something failed, please paste the corresponding file from the log directory here (e.g. fmt-check.txt or build-release.txt)." -ForegroundColor Yellow
