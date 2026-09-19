param(
    [Parameter(Mandatory=$true)][string]$Java17,
    [Parameter(Mandatory=$true)][string]$Java21,
    [Parameter(Mandatory=$true)][string]$Java25
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$originalJava = $env:JAVA_HOME
$matrix = @(
    @{ api='1.20.1-R0.1-SNAPSHOT'; java=$Java17 },
    @{ api='1.20.6-R0.1-SNAPSHOT'; java=$Java21 },
    @{ api='1.21.11-R0.1-SNAPSHOT'; java=$Java21 },
    @{ api='26.2-R0.1-SNAPSHOT'; java=$Java25 },
    @{ api='26.3-R0.1-SNAPSHOT'; java=$Java25 }
)
$results = @()
Push-Location $repo
try {
    $env:JAVA_HOME = $Java21
    foreach ($item in $matrix) {
        & .\gradlew.bat test "-PtestApi=$($item.api)" "-PtestJavaHome=$($item.java)" --no-daemon
        if ($LASTEXITCODE -ne 0) { throw "Compatibility tests failed for $($item.api)" }
        $destination = Join-Path $repo "build/compatibility/$($item.api)"
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Copy-Item -Path 'build/test-results/test/TEST-*.xml' -Destination $destination -Force
        $tests=0; $failures=0; $skipped=0
        Get-ChildItem -LiteralPath $destination -Filter 'TEST-*.xml' | ForEach-Object {
            [xml]$xml=Get-Content -LiteralPath $_.FullName -Raw
            $tests += [int]$xml.testsuite.tests
            $failures += [int]$xml.testsuite.failures + [int]$xml.testsuite.errors
            $skipped += [int]$xml.testsuite.skipped
        }
        $results += [PSCustomObject]@{api=$item.api; java=$item.java; tests=$tests; failures=$failures; skipped=$skipped}
    }
    $results | ConvertTo-Json | Set-Content -LiteralPath 'build/compatibility/results.json' -Encoding utf8
    $results | Format-Table -AutoSize
} finally { $env:JAVA_HOME=$originalJava; Pop-Location }
