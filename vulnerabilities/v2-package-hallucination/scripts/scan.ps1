<#
.SYNOPSIS
    AI Package Hallucination scanner (PowerShell edition).
    Flags typosquatted / AI-hallucinated dependencies by parsing manifests and
    source imports, then comparing against known-real packages and heuristics.
    Driven by config.yml. Native, no Python required.

.PARAMETER Target
    Path to scan (default: current directory).
.PARAMETER Config
    Path to config.yml (default: alongside this script).
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
if ($Config) { $cfgPath = $Config }
else {
    $sibling = Join-Path $here "config.yml"
    $cfgPath = if (Test-Path $sibling) { $sibling } else { Join-Path $here "..\config.yml" }
}

# ---- purpose-built config reader for v2 config shape ----
function Read-ConfigYaml {
    param([string]$Path)

    $out = @{
        manifests                 = [System.Collections.Generic.List[string]]::new()
        known_packages            = @{}
        source_files              = @{}
        ai_hallucination_patterns = [System.Collections.Generic.List[string]]::new()
        exclude_patterns          = [System.Collections.Generic.List[string]]::new()
        typosquat_max_distance    = 2
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

    $lines   = Get-Content -Path $Path
    $section = ""          # top-level key currently active
    $subKey  = ""          # second-level key (for known_packages / source_files)

    foreach ($raw in $lines) {
        $inQ = $null; $o = ""
        foreach ($ch in $raw.ToCharArray()) {
            if ($inQ) { $o += $ch; if ($ch -eq $inQ) { $inQ = $null } }
            elseif ($ch -eq '"' -or $ch -eq "'") { $inQ = $ch; $o += $ch }
            elseif ($ch -eq '#' -and $o.TrimStart() -eq "") { break }
            else { $o += $ch }
        }
        $line = $o.TrimEnd()
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $trimmed = $line.TrimStart()
        $indent  = $line.Length - $trimmed.Length

        # top-level key (indent 0, ends with colon)
        if ($indent -eq 0 -and $trimmed -match '^(\w[\w_-]*):\s*$') {
            $section = $Matches[1]; $subKey = ""; continue
        }

        # top-level scalar value (e.g. typosquat_max_distance: 2)
        if ($indent -eq 0 -and $trimmed -match '^(\w[\w_-]*):\s*(\S.*)$') {
            $k = $Matches[1]; $v = Strip-Quotes $Matches[2]
            if ($k -eq "typosquat_max_distance") { $out.typosquat_max_distance = [int]$v }
            continue
        }

        # second-level map key under known_packages / source_files (e.g. "  npm:")
        if ($indent -eq 2 -and $trimmed -match '^(\w[\w_-]*):\s*$' -and $section -in @("known_packages","source_files")) {
            $subKey = $Matches[1]
            if ($section -eq "known_packages" -and -not $out.known_packages.ContainsKey($subKey)) {
                $out.known_packages[$subKey] = [System.Collections.Generic.List[string]]::new()
            }
            if ($section -eq "source_files" -and -not $out.source_files.ContainsKey($subKey)) {
                $out.source_files[$subKey] = [System.Collections.Generic.List[string]]::new()
            }
            continue
        }

        # list item (indent 2 or 4)
        if ($trimmed.StartsWith("- ")) {
            $val = Strip-Quotes ($trimmed.Substring(2).Trim())
            switch ($section) {
                "manifests"                 { $out.manifests.Add($val) }
                "ai_hallucination_patterns" { $out.ai_hallucination_patterns.Add($val) }
                "exclude_patterns"          { $out.exclude_patterns.Add($val) }
                "known_packages"            { if ($subKey -and $out.known_packages.ContainsKey($subKey)) { $out.known_packages[$subKey].Add($val) } }
                "source_files"              { if ($subKey -and $out.source_files.ContainsKey($subKey))   { $out.source_files[$subKey].Add($val) } }
            }
            continue
        }
    }

    # convert Lists to arrays for compatibility with existing scan logic
    $result = @{
        manifests                 = @($out.manifests)
        known_packages            = @{}
        source_files              = @{}
        ai_hallucination_patterns = @($out.ai_hallucination_patterns)
        exclude_patterns          = @($out.exclude_patterns)
        typosquat_max_distance    = $out.typosquat_max_distance
    }
    foreach ($k in $out.known_packages.Keys) { $result.known_packages[$k] = @($out.known_packages[$k]) }
    foreach ($k in $out.source_files.Keys)   { $result.source_files[$k]   = @($out.source_files[$k]) }
    return $result
}

function Norm($n) { return $n.Replace("_", "-").ToLower() }

function Levenshtein($a, $b) {
    if ($a -eq $b) { return 0 }
    $la, $lb = $a.Length, $b.Length
    if ($la -eq 0) { return $lb }
    if ($lb -eq 0) { return $la }
    $prev = @(0..$lb)
    for ($i = 1; $i -le $la; $i++) {
        $cur = @($i) + @(0) * $lb
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($a[$i-1] -eq $b[$j-1]) { 0 } else { 1 }
            $cur[$j] = [Math]::Min([Math]::Min($prev[$j] + 1, $cur[$j-1] + 1), $prev[$j-1] + $cost)
        }
        $prev = $cur
    }
    return $prev[$lb]
}

function Test-Excluded($rel, $excl) {
    $parts = $rel.Replace("\", "/").Split("/")
    foreach ($pat in $excl) {
        $pat = $pat.TrimEnd("/")
        if ($parts -contains $pat) { return $true }
    }
    return $false
}

$cfg = Read-ConfigYaml -Path $cfgPath
$findings = @()
$declared = @{}      # name -> list of {file, eco, raw}
$declaredByEco = @{}
$importedByEco = @{}

# ---- walk manifests ----
Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $abs = $_.FullName
    $base = (Resolve-Path -Path $Target).Path.TrimEnd("\")
    $rel = $abs
    if ($abs.StartsWith($base)) { $rel = $abs.Substring($base.Length).TrimStart("\").Replace("\", "/") }
    if (Test-Excluded $rel $cfg.exclude_patterns) { return }
    foreach ($man in $cfg.manifests) {
        $parts = ($man -split '\|', 2)
        $mp = $parts[0].Trim(); $eco = if ($parts.Count -gt 1) { $parts[1].Trim() } else { "" }
        $matched = ($_.Name -eq $mp) -or ($mp.StartsWith("*.") -and $_.Name.EndsWith($mp.Substring(1)))
        if (-not $matched) { continue }
        $pkgs = @()
        if ($eco -eq "npm") {
            if ($_.Name -eq "package.json") {
                $txt = Get-Content $_.FullName -Raw
                foreach ($m in [regex]::Matches($txt, '"(?:dependencies|devDependencies|peerDependencies|optionalDependencies)"\s*:\s*\{([^}]*)\}')) {
                    foreach ($pm in [regex]::Matches($m.Groups[1].Value, '"([^"]+)"\s*:\s*"')) { $pkgs += $pm.Groups[1].Value }
                }
            } else {
                $txt = Get-Content $_.FullName -Raw
                foreach ($m in [regex]::Matches($txt, '^\s*"([a-zA-Z0-9@/_\.\-]+)"\s*:', [Text.RegularExpressions.RegexOptions]::Multiline)) {
                    $nm = $m.Groups[1].Value
                    if ($nm -notin @("name","version","lockfileVersion","requires","dependencies","packages")) { $pkgs += $nm }
                }
            }
        } elseif ($eco -eq "pypi") {
            $lines = Get-Content $_.FullName
            foreach ($line in $lines) {
                $line = $line.Split("#")[0].Trim()
                if ($line -and -not $line.StartsWith("-")) {
                    if ($line -match '^([A-Za-z0-9_\.\-]+)') { $pkgs += $Matches[1] }
                }
            }
        } elseif ($eco -eq "go") {
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), '^\s*([A-Za-z0-9_/\-]+)\s+[v0-9]', [Text.RegularExpressions.RegexOptions]::Multiline)) { $pkgs += $m.Groups[1].Value }
        } elseif ($eco -eq "cargo") {
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), '^([a-zA-Z0-9_\-]+)\s*=\s*"', [Text.RegularExpressions.RegexOptions]::Multiline)) { $pkgs += $m.Groups[1].Value }
        } elseif ($eco -eq "rubygems") {
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), "gem\s+['\""]([^'""]+)['""]")) { $pkgs += $m.Groups[1].Value }
        } elseif ($eco -eq "docker") {
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), '(?:RUN|ARG|ENV)\s+[^#]*?\b(?:npm|pip|pip3|poetry|cargo|go get)\s+install\s+([A-Za-z0-9_@/.\-]+)')) { $pkgs += $m.Groups[1].Value }
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), 'FROM\s+([a-zA-Z0-9_/.\-]+)')) { $pkgs += "image:" + $m.Groups[1].Value }
        } elseif ($eco -eq "ci") {
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), 'uses:\s*([A-Za-z0-9_./\-@]+)')) { $pkgs += "action:" + $m.Groups[1].Value }
            foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), '(?:npm|pip|pip3|poetry|cargo|go get|gem)\s+install\s+([A-Za-z0-9_@/.\-]+)')) { $pkgs += $m.Groups[1].Value }
        }
        foreach ($p in $pkgs) {
            $baseName = if ($p.StartsWith("image:") -or $p.StartsWith("action:")) { $p } else { $p.Split("/")[0].TrimStart("@") }
            if (-not $declared.ContainsKey($baseName)) { $declared[$baseName] = @() }
            $declared[$baseName] += @{ file = $rel; eco = $eco; raw = $p }
            if (-not $declaredByEco.ContainsKey($eco)) { $declaredByEco[$eco] = @{} }
            $declaredByEco[$eco][$baseName] = $true
        }
    }
}

# ---- walk source imports ----
Get-ChildItem -Path $Target -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    $abs = $_.FullName
    $base = (Resolve-Path -Path $Target).Path.TrimEnd("\")
    $rel = $abs
    if ($abs.StartsWith($base)) { $rel = $abs.Substring($base.Length).TrimStart("\").Replace("\", "/") }
    if (Test-Excluded $rel $cfg.exclude_patterns) { return }
    foreach ($eco in $cfg.source_files.Keys) {
        foreach ($g in $cfg.source_files[$eco]) {
            if ($g.StartsWith("*.") -and $_.Name.EndsWith($g.Substring(1))) {
                $imps = @()
                if ($eco -eq "npm") {
                    foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), "require\(\s*['\""]([^'""]+)['\""]")) { $imps += $m.Groups[1].Value.Split("/")[0].TrimStart("@") }
                    foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), "from\s+['\""]([^'""]+)['\""]")) {
                        $n = $m.Groups[1].Value
                        if (-not $n.StartsWith(".") -and -not $n.StartsWith("/")) { $imps += $n.Split("/")[0].TrimStart("@") }
                    }
                } elseif ($eco -eq "pypi") {
                    foreach ($m in [regex]::Matches((Get-Content $_.FullName -Raw), '^\s*(?:import|from)\s+([A-Za-z0-9_]+)', [Text.RegularExpressions.RegexOptions]::Multiline)) { $imps += $m.Groups[1].Value }
                }
                if (-not $importedByEco.ContainsKey($eco)) { $importedByEco[$eco] = @{} }
                foreach ($imp in $imps) { $importedByEco[$eco][$imp] = $true }
            }
        }
    }
}

# ---- flag ----
$aiPatterns = $cfg.ai_hallucination_patterns | ForEach-Object { $_.ToLower() }
foreach ($name in $declared.Keys) {
    $nname = Norm $name
    if ($aiPatterns -contains $nname) {
        foreach ($o in $declared[$name]) {
            $findings += @{ package = $o.raw; file = $o.file; ecosystem = $o.eco; type = "AI-hallucination name"; severity = "high"; detail = "Matches common AI-fictionalized package name pattern '$name'" }
        }
        continue
    }
    foreach ($eco in $cfg.known_packages.Keys) {
        foreach ($kp in $cfg.known_packages[$eco]) {
            $d = Levenshtein $nname (Norm $kp)
            if ($d -le $cfg.typosquat_max_distance -and $nname -ne (Norm $kp)) {
                foreach ($o in $declared[$name]) {
                    $findings += @{ package = $o.raw; file = $o.file; ecosystem = $o.eco; type = "Typosquat candidate"; severity = "high"; detail = "Near-match to known package '$kp' (distance $d)" }
                }
                break
            }
        }
    }
}
foreach ($eco in $importedByEco.Keys) {
    if (-not $declaredByEco.ContainsKey($eco)) { continue }
    foreach ($imp in $importedByEco[$eco].Keys) {
        $ib = $imp.Split("/")[0].TrimStart("@")
        if ($ib -notin $declaredByEco[$eco].Keys -and $ib -notin @("image","action")) {
            $findings += @{ package = $imp; file = "(source import)"; ecosystem = $eco; type = "Unlisted import"; severity = "medium"; detail = "Imported '$imp' but not found in $eco manifest" }
        }
    }
}

# ---- output ----
if ($Json) {
    $out = @{ count = $findings.Count; findings = $findings }
    $out | ConvertTo-Json -Depth 4
} else {
    Write-Host "`n=== AI Package Hallucination Scan :: $Target ==="
    Write-Host "Total suspicious packages identified: $($findings.Count)`n"
    $groups = @{}
    foreach ($f in $findings) {
        if (-not $groups.ContainsKey($f.package)) { $groups[$f.package] = @() }
        $groups[$f.package] += $f
    }
    foreach ($k in ($groups.Keys | Sort-Object)) {
        $grp = $groups[$k]
        Write-Host "## $k  ($($grp.Count) flag(s))"
        foreach ($it in $grp) {
            Write-Host "  [$($it.severity.ToUpper())] $($it.type) [$($it.ecosystem)] @ $($it.file)"
            Write-Host "      $($it.detail)"
        }
        Write-Host ""
    }
}
