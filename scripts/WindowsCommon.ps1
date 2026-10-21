function Resolve-BashPath {
    if ($env:GL_BASH -and (Test-Path -LiteralPath $env:GL_BASH -PathType Leaf)) {
        return $env:GL_BASH
    }

    $candidates = @()
    $bases = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, (Join-Path $env:LOCALAPPDATA 'Programs'))
    foreach ($base in $bases) {
        if ($base) { $candidates += (Join-Path $base 'Git\bin\bash.exe') }
    }
    $git = Get-Command git -ErrorAction SilentlyContinue
    if ($git) {
        $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source)
        $candidates += (Join-Path $gitRoot 'bin\bash.exe')
    }
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c -PathType Leaf) { return $c }
    }

    $systemDir = [Environment]::GetFolderPath([Environment+SpecialFolder]::System)
    foreach ($c in (Get-Command bash -All -ErrorAction SilentlyContinue)) {
        if (-not $c.Source) { continue }
        if ($c.Source.StartsWith($systemDir, [StringComparison]::OrdinalIgnoreCase)) { continue }
        if ($c.Source -match '\\WindowsApps\\') { continue }
        return $c.Source
    }
    return $null
}
