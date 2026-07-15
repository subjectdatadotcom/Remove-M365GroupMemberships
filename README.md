# M365 Group Membership Removal

This script removes target users from Microsoft 365 group memberships (owners and members), with audit files before and after changes.

It covers Unified Microsoft 365 groups, including groups behind Teams and group-connected SharePoint sites.

## Script

- Remove-M365GroupMemberships.ps1

## What It Does

- Reads users from Users.csv (UserEmail column).
- Discovers matching memberships across Unified groups.
- Writes pre-change audit CSV.
- Supports WhatIf (discovery only, no changes).
- In live mode, removes owner/member links.
- If target user is sole owner, adds the configured service account owner first.
- Writes post-change results CSV and run log.

## Prerequisites

- PowerShell with Microsoft Graph modules available.
- Permissions to read users/groups and update group memberships.
- Interactive Graph sign-in is used by the script.

## Input File

Users.csv must include:

```csv
UserEmail
user1@contoso.com
```

## Service Account

The script uses a hardcoded service account variable near the top:

- $ServiceAccountUpn = "admin@M365x64332454.onmicrosoft.com"

Update that value for your environment before running live.

## Run Commands

From this folder:

### Dry Run (WhatIf)

```powershell
.\Remove-M365GroupMemberships.ps1 -WhatIf
```

### Live Run

```powershell
.\Remove-M365GroupMemberships.ps1
```

## Outputs

In reports folder:

- Audit_PRE_<timestamp>.csv
- REMOVE_POST_<timestamp>.csv
- RunLog_<timestamp>_<mode>.txt
- UsersNotFound_<timestamp>.txt (only when applicable)
