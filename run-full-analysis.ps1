param(
    [switch]$SkipDynamic,
    [switch]$SkipRecommendations,
    [switch]$SkipBaseline,
    [string]$Target
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Log([string]$Message, [string]$Color = "Cyan") {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Write-Host "[$timestamp] $Message" -ForegroundColor $Color
}

function Require-Command([string]$Name) {
    if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
        Log "Error: $Name is not installed or not available in PATH." "Red"
        exit 1
    }
}

function Get-TargetUrlFromConfig([string]$Path) {
    if (-not (Test-Path $Path -PathType Leaf)) {
        return ""
    }

    $line = Select-String -Path $Path -Pattern '^\s*target_url:\s*(.+?)\s*$' | Select-Object -First 1
    if ($null -eq $line) {
        return ""
    }

    $value = $line.Matches[0].Groups[1].Value.Trim()
    return $value.Trim('"', "'")
}

Log "Phase 0: Dependency check" "Blue"
Require-Command "node"
Require-Command "java"

Log "Phase 1: AI static analysis (STRIDE)" "Blue"
& node "scripts/full-repo-analyzer.js"
if ($LASTEXITCODE -ne 0) {
    Log "Error in static analysis." "Red"
    exit 1
}

if ($SkipRecommendations) {
    Log "Phase 1.5: Skipping recommendations (-SkipRecommendations)" "Yellow"
}
else {
    Log "Phase 1.5: Mitigation recommendation engine" "Blue"
    & node "stride-agent/recommend.js" "--threats" "threats-output.json" "--in-place" "--repo" "."
    if ($LASTEXITCODE -ne 0) {
        Log "Warning: recommendation module failed. Continuing without enrichment." "Yellow"
    }
    else {
        Log "Recommendations applied to threats-output.json" "Green"
    }
}

if ($SkipDynamic) {
    Log "Phase 2: Skipping dynamic validation (-SkipDynamic)" "Yellow"
    if (Test-Path "results.json") {
        Remove-Item "results.json" -Force
    }
}
else {
    Log "Phase 2: Dynamic validation (Java engine)" "Blue"

    $targetUrl = Get-TargetUrlFromConfig "config/attack-config.yaml"
    if ($Target) {
        $targetUrl = $Target
    }

    if ([string]::IsNullOrWhiteSpace($targetUrl)) {
        Log "Error: target_url is missing in config/attack-config.yaml and no -Target was provided." "Red"
        exit 1
    }

    Log "Running health check against: $targetUrl"
    $healthy = $false

    for ($i = 1; $i -le 3; $i++) {
        try {
            Invoke-WebRequest -Uri $targetUrl -Method Get -TimeoutSec 5 | Out-Null
            $healthy = $true
            break
        }
        catch {
            Log "Retry ${i}: target is not responding..." "Yellow"
            Start-Sleep -Seconds 2
        }
    }

    if ($healthy) {
        Log "Target is reachable. Starting dynamic attacks..." "Green"

        $attacks = & node -e "const fs=require('fs'); const threats=JSON.parse(fs.readFileSync('threats-output.json','utf8')).threats; const map=JSON.parse(fs.readFileSync('config/stride-attacks-map.json','utf8')); const selected=new Set(); for (const cat of Object.keys(threats||{})) { const items=threats[cat]||[]; if (items.length>0 && map[cat]) map[cat].forEach(a=>selected.add(a)); } console.log(Array.from(selected).join(','));"
        if ($LASTEXITCODE -ne 0) {
            Log "Warning: unable to map threats to attacks. Skipping dynamic validation." "Yellow"
            if (Test-Path "results.json") {
                Remove-Item "results.json" -Force
            }
        }
        elseif ([string]::IsNullOrWhiteSpace($attacks)) {
            Log "No threats detected that require dynamic validation."
            if (Test-Path "results.json") {
                Remove-Item "results.json" -Force
            }
        }
        else {
            Log "Running attacks: $attacks"
            if ($Target) {
                & .\launch_attack.ps1 -Attacks $attacks -Target $Target
            }
            else {
                & .\launch_attack.ps1 -Attacks $attacks
            }

            if ($LASTEXITCODE -ne 0) {
                Log "Dynamic validation failed." "Red"
                exit $LASTEXITCODE
            }
        }
    }
    else {
        Log "Error: target is unavailable after 3 retries." "Red"
        if (Test-Path "results.json") {
            Remove-Item "results.json" -Force
        }
    }
}

Log "Phase 3: Consolidating final report" "Blue"
& node "scripts/combine-results.js"
if ($LASTEXITCODE -ne 0) {
    Log "Error while consolidating final report." "Red"
    exit $LASTEXITCODE
}

if ($SkipBaseline) {
    Log "Phase 4: Skipping baseline verification (-SkipBaseline)" "Yellow"
    Log "Pipeline completed with baseline verification skipped." "Green"
}
else {
    Log "Phase 4: Security baseline verification" "Blue"
    & node "scripts/check-baseline.js"
    $baselineExit = $LASTEXITCODE
    if ($baselineExit -ne 0) {
        Log "PIPELINE FAILED: Security regression detected (threats in 'reopened' state)." "Red"
        exit $baselineExit
    }

    Log "Pipeline completed successfully." "Green"
}

Log "Consolidated report: combined-report.json" "Green"
Log "Threat registry: security/threat-registry.json" "Green"
Log "Trend report: security/trend-report.json" "Green"
