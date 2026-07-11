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

# ---- minimal YAML reader (subset) ----
function Read-ConfigYaml {
    param([string]$Path)
    $rawLines = Get-Content -Path $Path
    $script:pos = 0
    $script:tokens = @()
    foreach ($raw in $rawLines) {
        if ([string]::IsNullOrWhiteSpace($raw) -or $raw.TrimStart().StartsWith("#")) { continue }
        $body = $raw
        $inQ = $null; $out = ""
        foreach ($ch in $body.ToCharArray()) {
            if ($inQ) { $out += $ch; if ($ch -eq $inQ) { $inQ = $null } }
            elseif ($ch -eq '"' -or $ch -eq "'") { $inQ = $ch; $out += $ch }
            elseif ($ch -eq '#' -and $out.Trim() -eq "") { break }
            else { $out += $ch }
        }
        $body = $out.Trim()
        if ($body -eq "") { continue }
        $indent = $body.Length - $body.TrimStart(" ").Length
        if ($body.StartsWith("- ")) {
            $script:tokens += [PSCustomObject]@{ ind = $indent; k = $null; val = $body.Substring(2).Trim() }
        } elseif ($body -eq "-") {
            $script:tokens += [PSCustomObject]@{ ind = $indent; k = $null; val = "" }
        } elseif ($body -match "^(.*?):\s*(.*)$") {
            $script:tokens += [PSCustomObject]@{ ind = $indent; k = $Matches[1].Trim(); val = $Matches[2].Trim() }
        }
    }
    function Strip-Q($s) {
        $s = $s.Trim()
        if (($s.StartsWith('"') -and $s.EndsWith('"')) -or ($s.StartsWith("'") -and $s.EndsWith("'"))) { return $s.Substring(1, $s.Length - 2) }
        return $s
    }
    $pos = 0
    $parseBlock = {
        param($minIndent)
        $r = $null
        while ($script:pos -lt $script:tokens.Count) {
            $t = $script:tokens[$script:pos]
            if ($t.ind -lt $minIndent) { break }
            if ($t.k -eq $null) {
                if ($r -eq $null) { $r = @() }
                if ($r -is [hashtable]) { $r = @() }
                if ($t.val -match "^(.+?):\s*(.*)$") {
                    $m = @{ ($Matches[1].Trim()) = Strip-Q $Matches[2] }
                    $script:pos++
                    $r += $m
                } else {
                    $script:pos++
                    $r += (Strip-Q $t.val)
                }
            } else {
                if ($r -eq $null) { $r = @{} }
                if ($r -isnot [hashtable]) { $r = @{} }
                $script:pos++
                if ($t.val -eq "") {
                    $child = & $parseBlock ($t.ind + 1)
                    if ($child -ne $null) { $r[$t.k] = $child }
                } else {
                    $r[$t.k] = Strip-Q $t.val
                }
            }
        }
        return $r
    }
    $cfg = & $parseBlock 0
    # Normalize into the shapes the scanner expects
    $out = @{
        manifests = @()
        known_packages = @{}
        source_files = @{}
        ai_hallucination_patterns = @()
        exclude_patterns = @()
        typosquat_max_distance = 2
    }
    if ($cfg.manifests) { foreach ($m in $cfg.manifests) { $out.manifests += $m } }
    if ($cfg.known_packages) { foreach ($k in $cfg.known_packages.Keys) { $out.known_packages[$k] = @($cfg.known_packages[$k]) } }
    if ($cfg.source_files) { foreach ($k in $cfg.source_files.Keys) { $out.source_files[$k] = @($cfg.source_files[$k]) } }
    if ($cfg.ai_hallucination_patterns) { $out.ai_hallucination_patterns = @($cfg.ai_hallucination_patterns) }
    if ($cfg.exclude_patterns) { $out.exclude_patterns = @($cfg.exclude_patterns) }
    if ($cfg.typosquat_max_distance) { $out.typosquat_max_distance = $cfg.typosquat_max_distance }
    return $out
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
