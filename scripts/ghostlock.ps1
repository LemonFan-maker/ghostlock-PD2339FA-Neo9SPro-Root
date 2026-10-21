$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'WindowsCommon.ps1')

$command = if ($args.Count -ge 1) { $args[0] } else { 'info' }
$rest = if ($args.Count -ge 2) { $args[1..($args.Count - 1)] } else { @() }

function Push-Repo {
    Push-Location $repoRoot
}

function Invoke-Make {
    param([string[]] $Targets)
    if (-not (Get-Command make -ErrorAction SilentlyContinue)) {
        Write-Host 'ERROR: make was not found on PATH.' -ForegroundColor Red
        Write-Host ''
        Write-Host 'Install GNU Make, e.g.:'
        Write-Host '    choco install make'
        Write-Host 'or add C:\ProgramData\chocolatey\bin to PATH.'
        exit 9009
    }
    Push-Repo
    try {
        & make @Targets
        exit $LASTEXITCODE
    } finally {
        Pop-Location
    }
}

switch ($command) {
    'info' { Invoke-Make @('info') }
    'clean' { Invoke-Make @('clean') }
    'build' { Invoke-Make @('all') }
    'all' { Invoke-Make @('all') }

    'package' {
        $bash = Resolve-BashPath
        if (-not $bash) {
            Write-Host 'ERROR: no real bash found (only the System32 WSL forwarder).' -ForegroundColor Red
            Write-Host 'Install Git for Windows, or set GL_BASH to a bash.exe path.'
            exit 9009
        }
        Push-Repo
        try {
            & $bash 'scripts/package_release.sh' @rest
            exit $LASTEXITCODE
        } finally {
            Pop-Location
        }
    }

    'fire' {
        $fireScript = Join-Path $PSScriptRoot 'autofire.ps1'
        if (-not (Test-Path -LiteralPath $fireScript)) {
            Write-Host "ERROR: not found: $fireScript" -ForegroundColor Red
            exit 2
        }
        & $fireScript @rest
        exit $LASTEXITCODE
    }

    default {
        Write-Host "unknown command '$command'." -ForegroundColor Red
        Write-Host 'expected one of: info, clean, build, all, package, fire'
        exit 2
    }
}
