param(
    [string]$Config = "config/attack-config.yaml",
    [string]$Target,
    [string]$Attacks
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$validAttacks = @(
    "SqlInjection", "BruteForce", "SessionFixation", "JwtToken", "XSS",
    "PathTraversal", "InfoLeak", "InsecureHeaders", "CORS", "WeakPassword"
)

function Write-Info([string]$Message) {
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host $Message -ForegroundColor Green
}

function Write-WarnMsg([string]$Message) {
    Write-Host $Message -ForegroundColor Yellow
}

function Write-ErrMsg([string]$Message) {
    Write-Host $Message -ForegroundColor Red
}

Write-Info "Attack Simulation Tool"
Write-Info "======================"

if ($Attacks) {
    $requestedAttacks = $Attacks.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    foreach ($name in $requestedAttacks) {
        if ($validAttacks -notcontains $name) {
            Write-ErrMsg "Error: invalid attack name '$name'"
            Write-ErrMsg "Valid values: $($validAttacks -join ', ')"
            exit 1
        }
    }
}

if (-not (Test-Path "attack-engine" -PathType Container)) {
    Write-ErrMsg "Error: attack-engine directory not found"
    Write-ErrMsg "Run this script from the Attack-Simulation-FDSI root directory"
    exit 1
}

$libDir = Join-Path "attack-engine" "lib"
$snakeJarName = "snakeyaml-2.2.jar"
$snakeJar = Join-Path $libDir $snakeJarName
$snakeUrl = "https://repo1.maven.org/maven2/org/yaml/snakeyaml/2.2/snakeyaml-2.2.jar"

if (-not (Test-Path $libDir)) {
    New-Item -ItemType Directory -Path $libDir | Out-Null
}

if (-not (Test-Path $snakeJar -PathType Leaf)) {
    Write-Info "Downloading SnakeYAML $snakeJarName ..."
    try {
        Invoke-WebRequest -Uri $snakeUrl -OutFile $snakeJar
    }
    catch {
        Write-ErrMsg "Error: could not download SnakeYAML."
        Write-ErrMsg "Download manually from: $snakeUrl"
        Write-ErrMsg "Save it to: $snakeJar"
        exit 1
    }
    Write-Ok "SnakeYAML downloaded"
}

$classFile = "out/AttackEngine.class"
$needsCompile = -not (Test-Path $classFile -PathType Leaf)

if (-not $needsCompile) {
    $classWrite = (Get-Item $classFile).LastWriteTimeUtc
    $newestJava = Get-ChildItem "attack-engine" -Recurse -Filter "*.java" |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1

    if ($null -ne $newestJava -and $newestJava.LastWriteTimeUtc -gt $classWrite) {
        $needsCompile = $true
    }
}

if ($needsCompile) {
    Write-Info "Compiling attack engine..."
    if (-not (Test-Path "out")) {
        New-Item -ItemType Directory -Path "out" | Out-Null
    }

    Push-Location "attack-engine"
    try {
        $sourceFiles = @("AttackEngine.java")
        $sourceFiles += Get-ChildItem "attacks", "model", "util", "config" -Filter "*.java" |
            ForEach-Object { $_.FullName }

        & javac -cp ("lib/{0}" -f $snakeJarName) -d "../out" @sourceFiles
        if ($LASTEXITCODE -ne 0) {
            Write-ErrMsg "Compilation error"
            exit 1
        }
    }
    finally {
        Pop-Location
    }

    Write-Ok "Compilation succeeded"
    Write-Host ""
}

$javaArgs = @("-cp", ("out;attack-engine/lib/{0}" -f $snakeJarName), "AttackEngine", "--config", $Config)

if ($Target) {
    $javaArgs += @("--target", $Target)
    Write-Info "Target override: $Target"
}

if ($Attacks) {
    $javaArgs += @("--attacks", $Attacks)
    Write-Info "Attacks: $Attacks"
}

Write-Host ""
Write-Info "Running attack simulation..."
Write-Host ""

& java @javaArgs
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

if (Test-Path "results.json" -PathType Leaf) {
    Write-Host ""
    Write-Ok "Simulation completed"
    Write-Host ""

    if (Test-Path "create-standalone-dashboard.py" -PathType Leaf) {
        Write-Info "Generating standalone dashboard..."
        try {
            & python "create-standalone-dashboard.py"
            if ($LASTEXITCODE -ne 0) {
                Write-WarnMsg "Dashboard generation failed, but simulation results are available."
            }
        }
        catch {
            Write-WarnMsg "Python not available. Skipping dashboard generation."
        }
        Write-Host ""
    }

    Write-Host "Results saved in:"
    Write-Host " - results.json"
    Write-Host " - dashboard-standalone.html"
    Write-Host ""

    $vulnCount = @(Select-String -Path "results.json" -Pattern '"vulnerable"\s*:\s*true').Count
    if ($vulnCount -gt 0) {
        Write-WarnMsg "Warning: $vulnCount vulnerabilities detected"
    }
    else {
        Write-Ok "No vulnerabilities detected"
    }
}
else {
    Write-ErrMsg "Error: results.json was not generated"
    exit 1
}
