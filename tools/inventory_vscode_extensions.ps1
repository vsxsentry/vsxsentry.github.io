# VSXSentry - VS Code Extension Inventory & Threat Scanner (PowerShell)
# Scans ALL user profiles. Run as Administrator for full visibility.

$outputFile = "$env:TEMP\vscode_extension_inventory.csv"
$feedUrl = "https://raw.githubusercontent.com/mthcht/awesome-lists/refs/heads/main/Lists/VSCODE%20Extensions/feeds/vsxsentry_feed.json"

$iocs = @{}
try {
    Write-Host "[*] Downloading VSXSentry feed..." -ForegroundColor Cyan
    $feed = Invoke-RestMethod -Uri $feedUrl -TimeoutSec 15
    foreach ($row in $feed.records) {
        $eid = $row.extension_id.Trim().ToLower()
        if ($eid) {
            $iocs[$eid] = @{
                severity = $row.metadata_severity
                category = $row.metadata_category
                comment  = $row.metadata_comment
                source   = $row.metadata_source
            }
        }
    }
    Write-Host "[+] Loaded $($iocs.Count) VSXSentry IOCs" -ForegroundColor Green
} catch { Write-Host "[!] Feed download failed: $_" -ForegroundColor Yellow }

# Enumerate ALL user profiles
$usersDir = Join-Path $env:SystemDrive "Users"
$skip = @("Public", "Default", "Default User", "All Users")
$userHomes = @()
Get-ChildItem $usersDir -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin $skip -and !$_.Name.StartsWith(".") } | ForEach-Object {
    $userHomes += @{Name=$_.Name; Path=$_.FullName}
}
Write-Host "[*] Found $($userHomes.Count) user(s): $($userHomes.Name -join ', ')" -ForegroundColor Cyan

$results = @()
foreach ($uh in $userHomes) {
    $un = $uh.Name; $hp = $uh.Path; $uc = 0

    # Scan VS Code variants
    foreach ($variant in @(
        @{N="VS Code";       P=Join-Path $hp ".vscode\extensions"},
        @{N="VS Code Insiders"; P=Join-Path $hp ".vscode-insiders\extensions"},
        @{N="VSCodium";      P=Join-Path $hp ".vscode-oss\extensions"},
        @{N="Cursor";        P=Join-Path $hp ".cursor\extensions"}
    )) {
        if (!(Test-Path $variant.P)) { continue }
        Get-ChildItem $variant.P -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $dirName = $_.Name
            # Parse publisher.extension-version pattern
            if ($dirName -match '^([^.]+\.[^-]+)-(.+)$') {
                $extId = $Matches[1]
                $version = $Matches[2]
            } else { return }

            $manifestPath = Join-Path $_.FullName "package.json"
            $extName = ""; $description = ""; $publisher = ""
            if (Test-Path $manifestPath) {
                try {
                    $m = Get-Content $manifestPath -Raw | ConvertFrom-Json
                    $extName = $m.displayName
                    if (!$extName) { $extName = $m.name }
                    $description = $m.description
                    $publisher = $m.publisher
                } catch {}
            }

            $installDate = ""
            try { $installDate = $_.CreationTime.ToString("yyyy-MM-dd HH:mm:ss") } catch {}
            $updateDate = ""
            if (Test-Path $manifestPath) {
                try { $updateDate = (Get-Item $manifestPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss") } catch {}
            }

            $mt = "clean"; $sev = ""; $cat = ""; $cm = ""
            $key = $extId.ToLower()
            if ($iocs.ContainsKey($key)) {
                $mt = "MATCH"
                $sev = $iocs[$key].severity
                $cat = $iocs[$key].category
                $cm  = $iocs[$key].comment
            }

            $results += [PSCustomObject]@{
                Computer          = $env:COMPUTERNAME
                User              = $un
                Editor            = $variant.N
                ExtensionID       = $extId
                DisplayName       = $extName
                Publisher         = $publisher
                Version           = $version
                Description       = $description
                InstallDate       = $installDate
                UpdatedDate       = $updateDate
                MarketplaceURL    = "https://marketplace.visualstudio.com/items?itemName=$extId"
                VSXSENTRY_MATCH   = $mt
                VSXSENTRY_SEVERITY = $sev
                VSXSENTRY_CATEGORY = $cat
                VSXSENTRY_COMMENT  = $cm
            }
            $uc++
        }
    }
    if ($uc -gt 0) { Write-Host "    ${un}: $uc extensions" }
}

$results | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
$matched = @($results | Where-Object {$_.VSXSENTRY_MATCH -eq "MATCH"}).Count
Write-Host "`n[+] $($userHomes.Count) user(s) scanned: $($results.Count) extensions found" -ForegroundColor Green
if ($matched -gt 0) {
    Write-Host "[!] MATCHED: $matched extension(s) in VSXSentry feed!" -ForegroundColor Red
    $results | Where-Object {$_.VSXSENTRY_MATCH -eq "MATCH"} | ForEach-Object {
        Write-Host "    >> [$($_.User)] $($_.Editor): $($_.ExtensionID) [$($_.VSXSENTRY_SEVERITY)] $($_.VSXSENTRY_CATEGORY)" -ForegroundColor Red
    }
}
Write-Host "[+] Report: $outputFile" -ForegroundColor Green
