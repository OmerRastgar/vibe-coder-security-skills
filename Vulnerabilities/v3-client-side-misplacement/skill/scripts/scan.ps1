<#
.SYNOPSIS
    V3 Client-Side Security Misplacement scanner (PowerShell edition).
    Scans frontend source files for patterns that indicate security logic
    placed only in the browser — route guards, JWT decoding, client-side
    pricing math, feature-flag gating, HTML-only input limits, etc.
    Driven by config.yml. Native PowerShell, no Python required.

.PARAMETER Target
    Path to scan (default: current directory).

.PARAMETER Config
    Path to config.yml (default: sibling of this script's parent folder).

.PARAMETER Json
    Emit results as JSON.
#>
param(
    [string]$Target = ".",
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
# Parse config.yml — purpose-built for the v3 config shape.
# Reads: exclude_patterns (list), source_extensions (list),
#        patterns (list of maps with name/regex/category/severity/note).
# -----------------------------------------------------------------------
function Read-V3Config {
    param([string]$Path)

    $cfg = @{
        exclude_patterns  = [System.Collections.Generic.List[string]]::new()
        source_extensions = [System.Collections.Generic.List[string]]::new()
        patterns          = [System.Collections.Generic.List[hashtable]]::new()
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

    $lines = Get-Content -Path $Path
    $section = ""           # top-level list key we are currently filling
    $curPattern = $null     # hashtable being built for a patterns entry

    foreach ($raw in $lines) {
        # strip inline comment and trailing whitespace
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
        $line = $out.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        $trimmed = $line.TrimStart()
        $indent  = $line.Length - $trimmed.Length

        # top-level section header (indent 0, ends with colon, no value)
        if ($indent -eq 0 -and $trimmed -match '^(\w[\w_-]*):\s*$') {
            # flush any in-progress pattern
            if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern); $curPattern = $null }
            $section = $Matches[1]
            continue
        }

        # list item under exclude_patterns or source_extensions
        if ($trimmed.StartsWith("- ") -and $indent -eq 2 -and $section -in @("exclude_patterns","source_extensions")) {
            $val = Strip-Quotes ($trimmed.Substring(2).Trim())
            if ($section -eq "exclude_patterns") { $cfg.exclude_patterns.Add($val) }
            else                                 { $cfg.source_extensions.Add($val) }
            continue
        }

        # start of a new pattern block: "  - name: ..."
        if ($trimmed.StartsWith("- ") -and $indent -eq 2 -and $section -eq "patterns") {
            if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern) }
            $curPattern = @{ name = ""; regex = ""; category = ""; severity = "medium"; note = "" }
            $rest = $trimmed.Substring(2).Trim()
            if ($rest -match '^(\w+):\s*(.+)$') {
                $curPattern[$Matches[1]] = Strip-Quotes $Matches[2]
            }
            continue
        }

        # property line inside a pattern block: "    key: value"
        if ($curPattern -ne $null -and $indent -ge 4 -and $trimmed -match '^(\w+):\s*(.+)$') {
            $curPattern[$Matches[1]] = Strip-Quotes $Matches[2]
            continue
        }
    }

    # flush last pattern
    if ($curPattern -ne $null) { $cfg.patterns.Add($curPattern) }

    return $cfg
}

# -----------------------------------------------------------------------
# Helper: check if a relative path falls under an excluded directory
# -----------------------------------------------------------------------
function Test-Excluded($rel, $excl) {
    $parts = $rel.Replace("\", "/").Split("/")
    foreach ($pat in $excl) {
        if ($parts -contains $pat.TrimEnd("/")) { return $true }
    }
    return $false
}

# ---- load config -------------------------------------------------------
$cfg        = Read-V3Config -Path $cfgPath
$exclude    = @($cfg.exclude_patterns)
$extensions = @($cfg.source_extensions)

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

# ---- scan --------------------------------------------------------------
$findings = [System.Collections.Generic.List[PSCustomObject]]::new()
$base = (Resolve-Path -Path $Target).Path.TrimEnd("\")

Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $abs = $_.FullName
    $rel = if ($abs.StartsWith($base)) {
        $abs.Substring($base.Length).TrimStart("\").Replace("\", "/")
    } else { $abs }

    if (Test-Excluded $rel $exclude) { return }
    if ($extensions.Count -gt 0 -and ($extensions -notcontains $_.Extension.ToLower())) { return }

    try {
        $lines = Get-Content -Path $abs -ErrorAction SilentlyContinue
    } catch { return }

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $ln = $lines[$i]
        foreach ($p in $compiled) {
            if ($p.rx.IsMatch($ln)) {
                $snippet = $ln.Trim()
                if ($snippet.Length -gt 120) { $snippet = $snippet.Substring(0, 117) + "..." }
                $findings.Add([PSCustomObject]@{
                    file     = $rel
                    line     = ($i + 1)
                    name     = $p.name
                    category = $p.category
                    severity = $p.severity
                    note     = $p.note
                    evidence = $snippet
                })
            }
        }
    }
}

# ---- output ------------------------------------------------------------
if ($Json) {
    $out = [ordered]@{ count = $findings.Count; findings = @($findings) }
    $out | ConvertTo-Json -Depth 4
} else {
    Write-Host "`n=== V3 Client-Side Misplacement Scan :: $Target ==="
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
            Write-Host "  [$($it.severity.ToUpper())] $($it.name) (L$($it.line)) [$($it.category)]"
            Write-Host "      $($it.note)"
            Write-Host "      > $($it.evidence)"
        }
        Write-Host ""
    }
}
