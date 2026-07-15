<#
.SYNOPSIS
    AI Commit Trap scanner (PowerShell edition).
    Scans a target directory and its Git history for leaked secrets / credentials.
    Driven by config.yml (sibling file). Native, no Python required.

.PARAMETER Target
    Path to scan (default: current directory).

.PARAMETER History
    Also scan full Git history (git log -p --all).

.PARAMETER Config
    Path to config.yml (default: alongside this script).

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
if ($Config) { $cfgPath = $Config }
else {
    $sibling = Join-Path $here "config.yml"
    $cfgPath = if (Test-Path $sibling) { $sibling } else { Join-Path $here "..\config.yml" }
}

# ---- minimal YAML reader (subset used by config.yml) ----
function Read-ConfigYaml {
    param([string]$Path)
    $lines = Get-Content -Path $Path
    $cfg = @{ patterns = @(); sensitive_filenames = @(); exclude_patterns = @(); mask_secret = $true }
    $current = $null
    foreach ($raw in $lines) {
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.TrimStart().StartsWith("#")) { continue }
        $body = $raw
        # strip trailing comment not inside quotes
        $inQ = $null; $out = ""
        foreach ($ch in $body.ToCharArray()) {
            if ($inQ) { $out += $ch; if ($ch -eq $inQ) { $inQ = $null } }
            elseif ($ch -eq '"' -or $ch -eq "'") { $inQ = $ch; $out += $ch }
            elseif ($ch -eq '#' -and $out.Trim() -eq "") { break }
            else { $out += $ch }
        }
        $body = $out.Trim()
        if ($body -eq "") { continue }
        if ($body.StartsWith("- ")) {
            $val = $body.Substring(2).Trim()
            if ($val -match "^(.+?):\s*(.*)$") {
                $pk = $Matches[1].Trim(); $pv = $Matches[2].Trim().Trim('"').Trim("'")
                if ($pk -eq "name") {
                    $current = @{ name = $pv; regex = ""; severity = "medium" }
                    $cfg.patterns += $current
                }
            }
        } elseif ($body -match "^(name|regex|severity)\s*:\s*(.*)$") {
            $k = $Matches[1]; $v = $Matches[2].Trim().Trim('"').Trim("'")
            if ($k -eq "name" -and $current) { $current.name = $v }
            elseif ($k -eq "regex" -and $current) { $current.regex = $v }
            elseif ($k -eq "severity" -and $current) { $current.severity = $v }
        } elseif ($body -match "^(sensitive_filenames|exclude_patterns)\s*:\s*(.*)$") {
            # list header; following "- item" lines fill it
        } elseif ($body -match "^(\w[\w_-]*)\s*:\s*(.*)$") {
            $k = $Matches[1]; $v = $Matches[2].Trim()
            if ($k -eq "mask_secret") { $cfg.mask_secret = ($v -eq "true") }
        } elseif ($body.StartsWith("-") -and $current -eq $null) {
            # list scalar (sensitive_filenames / exclude_patterns)
            $item = $body.Substring(1).Trim().Trim('"').Trim("'")
            if ($item -ne "") {
                if ($cfg._lastList -eq "sensitive_filenames") { $cfg.sensitive_filenames += $item }
                elseif ($cfg._lastList -eq "exclude_patterns") { $cfg.exclude_patterns += $item }
            }
        }
        if ($body -match "^(sensitive_filenames|exclude_patterns)\s*:") { $cfg._lastList = $Matches[1] }
        elseif (-not $body.StartsWith("- ")) { $cfg._lastList = $null }
    }
    return $cfg
}

function Mask-Secret {
    param([string]$value)
    $v = $value.Trim().Trim('"').Trim("'")
    if ($v.Length -le 8) { return $v }
    return $v.Substring(0, 4) + "..." + $v.Substring($v.Length - 4)
}

$cfg = Read-ConfigYaml -Path $cfgPath
$compiled = @()
foreach ($p in $cfg.patterns) {
    try { $rx = [regex]::new($p.regex, [Text.RegularExpressions.RegexOptions]::IgnoreCase) }
    catch { Write-Warning "Bad regex: $($p.name)"; continue }
    $compiled += @{ name = $p.name; rx = $rx; severity = $p.severity }
}

$findings = @()
$exclude = $cfg.exclude_patterns
$sensitive = $cfg.sensitive_filenames

function Test-Excluded {
    param([string]$rel, [array]$excl)
    $parts = $rel.Replace("\", "/").Split("/")
    foreach ($pat in $excl) {
        $pat = $pat.TrimEnd("/")
        if ($parts -contains $pat) { return $true }
    }
    return $false
}
function Test-SensitiveName {
    param([string]$name, [array]$sens)
    $nl = $name.ToLower()
    foreach ($s in $sens) {
        $sl = $s.ToLower()
        if ($sl.StartsWith("*.")) { if ($nl.EndsWith($sl.Substring(1))) { return $true } }
        elseif ($sl -eq $nl) { return $true }
    }
    return $false
}

# ---- scan filesystem ----
Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $abs = $_.FullName
    $base = (Resolve-Path -Path $Target).Path.TrimEnd("\")
    $rel = $abs
    if ($abs.StartsWith($base)) {
        $rel = $abs.Substring($base.Length).TrimStart("\")
    }
    $rel = $rel.Replace("\", "/")
    if (Test-Excluded $rel $exclude) { return }
    if (Test-SensitiveName $_.Name $sensitive) {
        $findings += @{ file = $rel; line = 0; type = "Sensitive filename"; severity = "high"; evidence = $_.Name; source = "filesystem" }
    }
    try {
        $lines = Get-Content -Path $_.FullName -ErrorAction SilentlyContinue
    } catch { return }
    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        foreach ($p in $compiled) {
            foreach ($m in $p.rx.Matches($ln)) {
                $ev = if ($cfg.mask_secret) { Mask-Secret $m.Value } else { $m.Value }
                $findings += @{ file = $rel; line = ($i + 1); type = $p.name; severity = $p.severity; evidence = $ev; source = "filesystem" }
            }
        }
    }
}

# ---- scan git history ----
if ($History) {
    try {
        $log = git -C $Target log -p --all --pretty=format:COMMIT:%H 2>$null
        $commit = "unknown"
        $lineno = 0
        foreach ($line in $log) {
            $lineno++
            if ($line.StartsWith("COMMIT:")) { $commit = $line.Substring(7).Trim(); continue }
            foreach ($p in $compiled) {
                foreach ($m in $p.rx.Matches($line)) {
                    $ev = if ($cfg.mask_secret) { Mask-Secret $m.Value } else { $m.Value }
                    $findings += @{ file = "commit:$commit"; line = $lineno; type = $p.name; severity = $p.severity; evidence = $ev; source = "git-history" }
                }
            }
        }
    } catch {
        Write-Warning "git history scan failed: $_"
    }
}

# ---- output ----
if ($Json) {
    $out = @{ count = $findings.Count; findings = $findings }
    $out | ConvertTo-Json -Depth 4
} else {
    Write-Host "`n=== AI Commit Trap Scan :: $Target ==="
    Write-Host "Total high-risk exposures found: $($findings.Count)`n"
    $groups = @{}
    foreach ($f in $findings) {
        $k = $f.file
        if (-not $groups.ContainsKey($k)) { $groups[$k] = @() }
        $groups[$k] += $f
    }
    foreach ($k in ($groups.Keys | Sort-Object)) {
        $grp = $groups[$k]
        Write-Host "## $k  ($($grp.Count) hit(s))"
        foreach ($it in $grp) {
            $loc = if ($it.line) { "L$($it.line)" } else { "" }
            Write-Host "  [$($it.severity.ToUpper())] $($it.type) $loc -> $($it.evidence)"
        }
        Write-Host ""
    }
}
