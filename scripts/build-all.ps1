$ErrorActionPreference = "Stop"

$targets = @(
    "x86_64-unknown-linux-gnu",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-freebsd",
    "aarch64-linux-android",
    "x86_64-linux-android"
)

foreach ($target in $targets) {
    Write-Host "Building for $target"
    cross build --all-features --target $target
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}
