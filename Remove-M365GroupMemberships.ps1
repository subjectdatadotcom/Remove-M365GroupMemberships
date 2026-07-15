#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Users, Microsoft.Graph.Groups

<#
.SYNOPSIS
    Removes target users from Microsoft 365 groups using in-memory group scan.

.DESCRIPTION
    Enumerates all Unified groups once, compares memberships in memory against
    target users from CSV, writes PRE audit, and optionally performs removals.

.PARAMETER CsvPath
    Path to CSV with a UserEmail column.

.PARAMETER ReportDir
    Output folder for logs and audit/result CSV files.

.PARAMETER WhatIf
    Discovery and PRE audit only. No removals are made.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [string] $CsvPath = (Join-Path $PSScriptRoot "Users.csv"),
    [string] $ReportDir = (Join-Path $PSScriptRoot "reports")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Hardcoded break-glass owner for sole-owner groups.
$ServiceAccountUpn = "admin@M365x64332454.onmicrosoft.com"

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$RunMode   = if ($WhatIfPreference) { "WHATIF" } else { "LIVE" }

New-Item -ItemType Directory -Path $ReportDir -Force -WhatIf:$false | Out-Null

$RunLogPath       = Join-Path $ReportDir "RunLog_${Timestamp}_${RunMode}.txt"
$PreAuditCsv      = Join-Path $ReportDir "Audit_PRE_${Timestamp}.csv"
$PostResultCsv    = Join-Path $ReportDir "REMOVE_POST_${Timestamp}.csv"
$UsersNotFoundTxt = Join-Path $ReportDir "UsersNotFound_${Timestamp}.txt"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")

    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts] [$Level] $Message"

    switch ($Level) {
        "INFO"    { Write-Host $line -ForegroundColor Cyan }
        "WARN"    { Write-Host $line -ForegroundColor Yellow }
        "ERROR"   { Write-Host $line -ForegroundColor Red }
        "SUCCESS" { Write-Host $line -ForegroundColor Green }
        default    { Write-Host $line }
    }

    Add-Content -Path $RunLogPath -Value $line -WhatIf:$false
}

Write-Log "======================================================="
Write-Log " M365 Group Membership Removal (In-Memory) | $RunMode"
Write-Log "======================================================="

Write-Log "Connecting to Microsoft Graph (interactive delegated auth)..."
#Connect-MgGraph -Scopes @("User.Read.All","Group.Read.All","Group.ReadWrite.All","Directory.Read.All") -NoWelcome
Write-Log "Connected." "SUCCESS"

if (-not (Test-Path $CsvPath)) {
    Write-Log "CSV not found: $CsvPath" "ERROR"
    #Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Log "Reading CSV: $CsvPath"
$TargetRows = @(Import-Csv -Path $CsvPath)
if (-not ($TargetRows | Get-Member -Name 'UserEmail' -ErrorAction SilentlyContinue)) {
    Write-Log "CSV must contain a UserEmail column." "ERROR"
    #Disconnect-MgGraph | Out-Null
    exit 1
}

$TargetUsersById = @{}
$TargetUsersByUpn = @{}

foreach ($row in $TargetRows) {
    $upn = [string]$row.UserEmail
    if ([string]::IsNullOrWhiteSpace($upn)) { continue }
    $upn = $upn.Trim()

    try {
        $u = Get-MgUser -UserId $upn -Property "id,displayName,userPrincipalName" -ErrorAction Stop
        $TargetUsersById[$u.Id] = @{
            Upn = $u.UserPrincipalName
            DisplayName = $u.DisplayName
        }
        $TargetUsersByUpn[$u.UserPrincipalName.Trim().ToLowerInvariant()] = $true
        Write-Log "  Resolved target user: $($u.UserPrincipalName) -> $($u.Id)"
    }
    catch {
        Write-Log "  Target user not found: $upn" "WARN"
    }
}

if ($TargetUsersById.Count -eq 0) {
    Write-Log "No target users resolved. Exiting." "ERROR"
    #Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Log "Resolving service account: $ServiceAccountUpn"
try {
    $ServiceAccountUser = Get-MgUser -UserId $ServiceAccountUpn -Property "id,userPrincipalName" -ErrorAction Stop
    Write-Log "  Service account resolved: $($ServiceAccountUser.UserPrincipalName)" "SUCCESS"
}
catch {
    Write-Log "Service account not found or inaccessible: $ServiceAccountUpn" "ERROR"
    #Disconnect-MgGraph | Out-Null
    exit 1
}

Write-Log "Enumerating Unified M365 groups..."
$AllGroups = @(Get-MgGroup -Filter "groupTypes/any(c:c eq 'Unified')" -Property "id,displayName,mail,mailNickname" -All)
Write-Log "  Total Unified groups: $($AllGroups.Count)"

$AuditRecords = [System.Collections.Generic.List[PSCustomObject]]::new()
$MatchedUserIds = @{}
$scanErrors = 0
$scanStart = Get-Date

for ($idx = 0; $idx -lt $AllGroups.Count; $idx++) {
    $g = $AllGroups[$idx]

    if (($idx + 1) % 50 -eq 0 -or $idx -eq 0) {
        $elapsed = (Get-Date) - $scanStart
        $pct = [Math]::Round((($idx + 1) / [Math]::Max($AllGroups.Count, 1)) * 100, 2)
        Write-Log ("  Discovery progress: {0}/{1} ({2}%) | elapsed {3}" -f ($idx + 1), $AllGroups.Count, $pct, $elapsed.ToString('hh\:mm\:ss'))
    }

    try {
        $owners = @(Get-MgGroupOwner -GroupId $g.Id -All -ErrorAction Stop)
        $members = @(Get-MgGroupMember -GroupId $g.Id -All -ErrorAction Stop)
    }
    catch {
        $scanErrors++
        Write-Log "  ERROR reading group '$($g.DisplayName)': $($_.Exception.Message)" "WARN"
        continue
    }

    $ownerIds = @{}
    foreach ($o in $owners) {
        if (-not [string]::IsNullOrWhiteSpace([string]$o.Id)) { $ownerIds[[string]$o.Id] = $true }
    }

    $memberIds = @{}
    foreach ($m in $members) {
        if (-not [string]::IsNullOrWhiteSpace([string]$m.Id)) { $memberIds[[string]$m.Id] = $true }
    }

    $ownerCount = $ownerIds.Count

    $candidateIds = @($ownerIds.Keys + $memberIds.Keys | Select-Object -Unique)
    foreach ($id in $candidateIds) {
        if (-not $TargetUsersById.ContainsKey($id)) { continue }

        $MatchedUserIds[$id] = $true
        $isOwner = $ownerIds.ContainsKey($id)
        $isMember = $memberIds.ContainsKey($id)
        $isSoleOwner = $isOwner -and ($ownerCount -eq 1)

        $u = $TargetUsersById[$id]
        $AuditRecords.Add([PSCustomObject]@{
            UserUpn          = $u.Upn
            UserDisplayName  = $u.DisplayName
            UserId           = $id
            GroupName        = $g.DisplayName
            GroupId          = $g.Id
            GroupMail        = $g.Mail
            GroupMailNick    = $g.MailNickname
            IsOwner          = $isOwner
            IsMember         = $isMember
            IsSoleOwner      = $isSoleOwner
            ServiceAcctAdded = $false
            OwnerRemoved     = $false
            MemberRemoved    = $false
            Result           = "Pending"
            ErrorDetail      = ""
            ProcessedAt      = ""
        })
    }
}

Write-Log "Discovery complete. Membership records: $($AuditRecords.Count)"
Write-Log "Groups with read errors: $scanErrors"

$UsersNotFound = [System.Collections.Generic.List[string]]::new()
foreach ($id in $TargetUsersById.Keys) {
    if (-not $MatchedUserIds.ContainsKey($id)) {
        $UsersNotFound.Add([string]$TargetUsersById[$id].Upn)
    }
}

if ($UsersNotFound.Count -gt 0) {
    $UsersNotFound | Sort-Object | Out-File -FilePath $UsersNotFoundTxt -Encoding utf8 -WhatIf:$false
    Write-Log "Users not found in any Unified group: $($UsersNotFound.Count)" "WARN"
    Write-Log "  Not-found list: $UsersNotFoundTxt" "WARN"
}

Write-Log "Writing PRE audit: $PreAuditCsv"
$AuditRecords |
    Select-Object UserUpn,UserDisplayName,UserId,GroupName,GroupId,GroupMail,GroupMailNick,IsOwner,IsMember,IsSoleOwner,Result,ErrorDetail |
    Export-Csv -Path $PreAuditCsv -NoTypeInformation -Encoding utf8 -WhatIf:$false

if ($WhatIfPreference) {
    Write-Log ""
    Write-Log "== WhatIf Summary (no changes made) ==" "WARN"
    Write-Log "  Users resolved       : $($TargetUsersById.Count)" "WARN"
    Write-Log "  Users matched        : $($MatchedUserIds.Count)" "WARN"
    Write-Log "  Users not found      : $($UsersNotFound.Count)" "WARN"
    Write-Log "  Membership rows      : $($AuditRecords.Count)" "WARN"
    Write-Log "  PRE audit CSV        : $PreAuditCsv" "WARN"
    if ($UsersNotFound.Count -gt 0) { Write-Log "  UsersNotFound list   : $UsersNotFoundTxt" "WARN" }
    Write-Log "======================================" "WARN"
    #Disconnect-MgGraph | Out-Null
    exit 0
}

Write-Log "Starting live removals..."

foreach ($r in $AuditRecords) {
    $r.ProcessedAt = (Get-Date -Format "o")

    try {
        if ($r.IsOwner -and $r.IsSoleOwner) {
            if ($r.UserId -eq $ServiceAccountUser.Id) {
                throw "Target user is the configured service account for sole-owner group '$($r.GroupName)'."
            }

            Write-Log "  Sole owner guard for '$($r.GroupName)': adding service account..."
            try {
                $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$($ServiceAccountUser.Id)" }
                New-MgGroupOwnerByRef -GroupId $r.GroupId -BodyParameter $body -ErrorAction Stop
                $r.ServiceAcctAdded = $true
            }
            catch {
                if ($_.Exception.Message -match "(already exists|One or more added object references already exist|object references already exist)") {
                    Write-Log "  Service account already owner for '$($r.GroupName)'" "WARN"
                }
                else {
                    throw
                }
            }
        }

        if ($r.IsOwner) {
            try {
                Remove-MgGroupOwnerByRef -GroupId $r.GroupId -DirectoryObjectId $r.UserId -ErrorAction Stop
                $r.OwnerRemoved = $true
            }
            catch {
                if ($_.Exception.Message -match "(not found|does not exist|ResourceNotFound)") {
                    $r.OwnerRemoved = $false
                }
                else {
                    throw
                }
            }
        }

        if ($r.IsMember) {
            try {
                Remove-MgGroupMemberByRef -GroupId $r.GroupId -DirectoryObjectId $r.UserId -ErrorAction Stop
                $r.MemberRemoved = $true
            }
            catch {
                if ($_.Exception.Message -match "(not found|does not exist|ResourceNotFound)") {
                    $r.MemberRemoved = $false
                }
                else {
                    throw
                }
            }
        }

        if ($r.OwnerRemoved -or $r.MemberRemoved) {
            $r.Result = "Removed"
        }
        else {
            $r.Result = "AlreadyGone"
        }
    }
    catch {
        $r.Result = "Failed"
        $r.ErrorDetail = $_.Exception.Message
        Write-Log "  ERROR for user '$($r.UserUpn)' group '$($r.GroupName)': $($_.Exception.Message)" "ERROR"
    }
}

Write-Log "Writing POST results: $PostResultCsv"
$AuditRecords |
    Select-Object UserUpn,UserDisplayName,UserId,GroupName,GroupId,GroupMail,GroupMailNick,IsOwner,IsMember,IsSoleOwner,ServiceAcctAdded,OwnerRemoved,MemberRemoved,Result,ErrorDetail,ProcessedAt |
    Export-Csv -Path $PostResultCsv -NoTypeInformation -Encoding utf8 -WhatIf:$false

$removed = @($AuditRecords | Where-Object { $_.Result -eq "Removed" }).Count
$gone    = @($AuditRecords | Where-Object { $_.Result -eq "AlreadyGone" }).Count
$failed  = @($AuditRecords | Where-Object { $_.Result -eq "Failed" }).Count
$svcAdd  = @($AuditRecords | Where-Object { $_.ServiceAcctAdded }).Count

Write-Log "======================================================="
Write-Log "FINAL SUMMARY"
Write-Log "  Total rows            : $($AuditRecords.Count)"
Write-Log "  Removed               : $removed"
Write-Log "  Already gone          : $gone"
Write-Log "  Service owner added   : $svcAdd"
Write-Log "  Failed                : $failed"
Write-Log "  Users not found       : $($UsersNotFound.Count)"
Write-Log "  PRE audit             : $PreAuditCsv"
Write-Log "  POST results          : $PostResultCsv"
if ($UsersNotFound.Count -gt 0) { Write-Log "  UsersNotFound list    : $UsersNotFoundTxt" }
Write-Log "  Run log               : $RunLogPath"
Write-Log "======================================================="

#Disconnect-MgGraph | Out-Null
Write-Log "Done." "SUCCESS"
