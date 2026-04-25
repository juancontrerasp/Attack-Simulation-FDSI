param(
    [string]$Target = "http://localhost:8080"
)

$ErrorActionPreference = "Continue"
Set-StrictMode -Version Latest

$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

$checks = @(
    @{
        Name = "Node runtime";
        Command = "node --version";
        ExpectedToPass = $true
    },
    @{
        Name = "Java runtime";
        Command = "java -version";
        ExpectedToPass = $true
    },
    @{
        Name = "STRIDE static analysis";
        Command = "npm run stride:analyze";
        ExpectedToPass = $true
    },
    @{
        Name = "Dynamic attack launcher (single attack)";
        Command = "powershell -NoProfile -ExecutionPolicy Bypass -File .\launch_attack.ps1 -Attacks SqlInjection -Target $Target";
        ExpectedToPass = $true
    },
    @{
        Name = "Consolidated report generation";
        Command = "node scripts/combine-results.js";
        ExpectedToPass = $true
    },
    @{
        Name = "Metrics comparison report";
        Command = "node compare.js";
        ExpectedToPass = $true
    },
    @{
        Name = "Windows full pipeline (demo-safe)";
        Command = "powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations -SkipBaseline";
        ExpectedToPass = $true
    },
    @{
        Name = "Windows full pipeline (security gate enforced)";
        Command = "powershell -NoProfile -ExecutionPolicy Bypass -File .\run-full-analysis.ps1 -SkipDynamic -SkipRecommendations";
        ExpectedToPass = $false
    }
)

$results = New-Object System.Collections.Generic.List[object]

Write-Host ""
Write-Host "=== Attack-Simulation-FDSI Demo Preflight ===" -ForegroundColor Cyan
Write-Host "Repo: $root" -ForegroundColor DarkGray
Write-Host "Target: $Target" -ForegroundColor DarkGray
Write-Host ""

foreach ($check in $checks) {
    Write-Host ">>> $($check.Name)" -ForegroundColor Cyan
    Write-Host "CMD: $($check.Command)" -ForegroundColor DarkGray

    & powershell -NoProfile -ExecutionPolicy Bypass -Command $check.Command
    $exit = $LASTEXITCODE

    $ok = ($check.ExpectedToPass -and $exit -eq 0) -or ((-not $check.ExpectedToPass) -and $exit -ne 0)
    $status = if ($ok) { "PASS" } else { "FAIL" }
    $expectation = if ($check.ExpectedToPass) { "expect=0" } else { "expect!=0" }

    if ($ok) {
        Write-Host "RESULT: $status (exit=$exit, $expectation)" -ForegroundColor Green
    }
    else {
        Write-Host "RESULT: $status (exit=$exit, $expectation)" -ForegroundColor Red
    }

    Write-Host ""

    $results.Add([PSCustomObject]@{
        Name = $check.Name
        ExitCode = $exit
        ExpectedToPass = $check.ExpectedToPass
        Passed = $ok
    }) | Out-Null
}

$passed = @($results | Where-Object { $_.Passed }).Count
$total = $results.Count

Write-Host "=== Summary ===" -ForegroundColor Cyan
Write-Host "$passed/$total checks passed expectation." -ForegroundColor Yellow

$reportPath = Join-Path $root "demo-preflight-report.json"
$results | ConvertTo-Json -Depth 3 | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "Report: $reportPath" -ForegroundColor DarkGray

if ($passed -ne $total) {
    exit 1
}

exit 0
