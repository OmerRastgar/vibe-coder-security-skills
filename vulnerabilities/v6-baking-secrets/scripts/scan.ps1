<#
.SYNOPSIS
    V6 Baking Secrets into Source scanner (PowerShell edition).
    Scans source files (and optionally Git history) for hardcoded credentials:
    API keys, DB URIs, default passwords, AWS keys, private key blocks,
    kubeconfig tokens, npm auth tokens, and high-entropy secret assignments.
    Driven by config.yml. Native PowerShell, no Python required.

.PARAMETER Target
    Path to scan (default: current directory).

.PARAMETER History
    Also scan full Git history (git log -p --all).

.PARAMETER Config
    Path to config.yml (default: sibling of this script's parent folder).

.PARAMETER Json
    Emit results as JSON.
#>
param(
    [string]$Target = ".",
    [switch]$History,
    [string]$Config,
    [switch]$Json
)

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Definition

if ($Config) {
    $cfgPath = $Config
} else {
    $sibling = Join-Path $here "..\config.yml"
    $cfgPath = if (Test-Path $sibling) { $sibling } else { Join-Path $here "config.yml" }
}

if (-not (Test-Path $cfgPath)) {
    Write-Error "config.yml not found at $cfgPath"
    exit 1
}

# -----------------------------------------------------------------------
# Parse config.yml — purpose-built for the v6 config shape.
# Reads: exclude_patterns, source_extensions, sensitive_filenames (lists),
#        mask_secret (bool), patterns (list of maps).
# -----------------------------------------------------------------------
function Read-V6Config {
    param([string]$Path)

    $cfg = @{
        exclude_patterns   = [System.Collections.Generic.List[string]]::new()
        source_extensions  = [System.Collections.Generic.List[string]]::new()
        sensitive_filenames = [System.Collections.Generic.List[string]]::new()
        patterns           = [System.Collections.Generic.List[hashtable]]::new()
        mask_secret        = $true
    }

    function Strip-Quotes($s) {
        $s = $s.Trim()
        if ($s.Length -ge 2) {
            $fc = $s[0]; $lc = $s[$s.Length - 1]
            if (($fc -eq '"' -and $lc -eq '"') -or ($fc -eq "'" -and $lc -eq "'")) {
                return $s.Substring(1, $s.Length - 2)
            }
        }
        return $s
    }

    $lines      = Get-Content -Path $Path
    $section    = ""
    $curPattern = $null

    foreach ($raw in $lines) {
        $inQ = $null; $out = ""
        foreach ($ch in $raw.ToCharArray()) {
            if ($inQ) {
                $out += $ch
                if ($ch -eq $inQ) { $inQ = $null }
            } elseif ($ch -eq '"' -or $ch -eq "'") {
                $inQ = $ch; $out += $ch
            } elseif ($ch -eq '#' -and $out.TrimStart() -eq "") {
                break
            } else {
                $out += $ch
            }
        }
        $line    = $out.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.TrimStart()
        $indent  = $line.Length - $trimmed.Length

        # top-level key: value (scalar)
        if ($indent -eq 0 -and $trimmed -match '^(\w[\w_-]*):\s*(\S.*)$') {
            $k = $Matches[1]; $v = Strip-Quotes $Matches[2]
            if ($k -eq "mask_secret") { $cfg.mask_secret = ($v -eq "true") }
            continue
        }

        # top-level section header
        if ($indent -eq 0 -and $trimmed -match '^(\w[\w_-]*):\s*$') {
            if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern); $curPattern = $null }
            $section = $Matches[1]
            continue
        }

        # scalar list item
        if ($trimmed.StartsWith("- ") -and $indent -eq 2 -and $section -in @("exclude_patterns","source_extensions","sensitive_filenames")) {
            $val = Strip-Quotes ($trimmed.Substring(2).Trim())
            switch ($section) {
                "exclude_patterns"    { $cfg.exclude_patterns.Add($val) }
                "source_extensions"   { $cfg.source_extensions.Add($val) }
                "sensitive_filenames" { $cfg.sensitive_filenames.Add($val) }
            }
            continue
        }

        # new pattern entry
        if ($trimmed.StartsWith("- ") -and $indent -eq 2 -and $section -eq "patterns") {
            if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern) }
            $curPattern = @{ name = ""; regex = ""; category = ""; severity = "medium"; note = "" }
            $rest = $trimmed.Substring(2).Trim()
            if ($rest -match '^(\w+):\s*(.+)$') {
                $curPattern[$Matches[1]] = Strip-Quotes $Matches[2]
            }
            continue
        }

        # property inside a pattern
        if ($curPattern -ne $null -and $indent -ge 4 -and $trimmed -match '^(\w+):\s*(.+)$') {
            $curPattern[$Matches[1]] = Strip-Quotes $Matches[2]
            continue
        }
    }

    if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern) }
    return $cfg
}

function Test-Excluded($rel, $excl) {
    $parts = $rel.Replace("\", "/").Split("/")
    foreach ($pat in $excl) {
        if ($parts -contains $pat.TrimEnd("/")) { return $true }
    }
    return $false
}

function Test-SensitiveName($name, $sens) {
    $nl = $name.ToLower()
    foreach ($s in $sens) {
        $sl = $s.ToLower()
        if ($sl.StartsWith("*.")) { if ($nl.EndsWith($sl.Substring(1))) { return $true } }
        elseif ($sl -eq $nl) { return $true }
    }
    return $false
}

function Mask-Secret($value) {
    $v = $value.Trim().Trim('"').Trim("'")
    if ($v.Length -le 8) { return $v.Substring(0, [Math]::Min(2, $v.Length)) + "..." }
    return $v.Substring(0, 4) + "..." + $v.Substring($v.Length - 4)
}

# ---- load config -------------------------------------------------------
$cfg        = Read-V6Config -Path $cfgPath
$exclude    = @($cfg.exclude_patterns)
$extensions = @($cfg.source_extensions)
$sensitive  = @($cfg.sensitive_filenames)
$doMask     = $cfg.mask_secret

$compiled = [System.Collections.Generic.List[PSCustomObject]]::new()
foreach ($p in $cfg.patterns) {
    if (-not $p.regex) { continue }
    try {
        $rx = [regex]::new($p.regex, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
        $compiled.Add([PSCustomObject]@{
            name     = $p.name
            rx       = $rx
            category = $p.category
            severity = $p.severity
            note     = $p.note
        })
    } catch {
        Write-Warning "Bad regex for '$($p.name)': $_"
    }
}

# ---- scan filesystem ---------------------------------------------------
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$base = (Resolve-Path -Path $Target).Path.TrimEnd("\")

Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $abs = $_.FullName
    $rel = if ($abs.StartsWith($base)) {
        $abs.Substring($base.Length).TrimStart("\").Replace("\", "/")
    } else { $abs }

    if (Test-Excluded $rel $exclude) { return }

    if (Test-SensitiveName $_.Name $sensitive) {
        $findings.Add([PSCustomObject]@{
            file = $rel; line = 0; name = "Sensitive filename"
            category = "Dev Boilerplate"; severity = "high"
            note = "This file type should not be committed with real values."
            evidence = $_.Name; source = "filesystem"
        })
    }

    if ($extensions.Count -gt 0 -and ($extensions -notcontains $_.Extension.ToLower())) { return }

    try {
        $lines = Get-Content -Path $abs -ErrorAction SilentlyContinue
    } catch { return }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        foreach ($p in $compiled) {
            $m = $p.rx.Match($ln)
            if ($m.Success) {
                $ev = if ($doMask) { Mask-Secret $m.Value } else { $m.Value }
                $findings.Add([PSCustomObject]@{
                    file = $rel; line = ($i + 1); name = $p.name
                    category = $p.category; severity = $p.severity
                    note = $p.note; evidence = $ev; source = "filesystem"
                })
            }
        }
    }
}

# ---- scan Git history --------------------------------------------------
if ($History) {
    try {
        $log = git -C $Target log -p --all --pretty=format:COMMIT:%H 2>$null
        $commit = "unknown"; $lineno = 0
        foreach ($line in $log) {
            $lineno++
            if ($line.StartsWith("COMMIT:")) { $commit = $line.Substring(7).Trim(); continue }
            foreach ($p in $compiled) {
                $m = $p.rx.Match($line)
                if ($m.Success) {
                    $ev = if ($doMask) { Mask-Secret $m.Value } else { $m.Value }
                    $findings.Add([PSCustomObject]@{
                        file = "commit:$commit"; line = $lineno; name = $p.name
                        category = $p.category; severity = $p.severity
                        note = $p.note; evidence = $ev; source = "git-history"
                    })
                }
            }
        }
    } catch {
        Write-Warning "git history scan failed: $_"
    }
}

# ---- output ------------------------------------------------------------
if ($Json) {
    [ordered]@{ count = $findings.Count; findings = @($findings) } | ConvertTo-Json -Depth 4
} else {
    Write-Host "`n=== V6 Baking Secrets Scan :: $Target ==="
    Write-Host "Total findings: $($findings.Count)`n"
    $groups = @{}
    foreach ($f in $findings) {
        if (-not $groups.ContainsKey($f.file)) { $groups[$f.file] = @() }
        $groups[$f.file] += $f
    }
    foreach ($k in ($groups.Keys | Sort-Object)) {
        $grp = $groups[$k]
        Write-Host "## $k  ($($grp.Count) hit(s))"
        foreach ($it in $grp) {
            $loc = if ($it.line) { "L$($it.line)" } else { "" }
            Write-Host "  [$($it.severity.ToUpper())] $($it.name) $loc [$($it.category)]"
            Write-Host "      $($it.note)"
            Write-Host "      > $($it.evidence)"
        }
        Write-Host ""
    }
}
