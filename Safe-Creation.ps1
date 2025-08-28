$items = Import-Csv .\SafeList.csv

$results = foreach ($row in $items) {
    $name = $row.SafeName.Trim()
    if (-not $name) { continue }

    $desc   = $row.Description
    $cpm    = if ($row.ManagingCPM) { $row.ManagingCPM } else { "PasswordManager" }
    $vers   = if ($row.VersionsRetention)     { [int]$row.VersionsRetention}     else { 0 }

    New-CPCSafe -PVWAURL $PVWAURL -BearerToken $BearerToken -Name $name -Description $desc -ManagingCPM $cpm -DaysRetention $days
}

$results | Format-Table -AutoSize



# Variables definition

$tenantFQDN = "acme-lab-2528.privilegecloud.cyberark.cloud"
$pvwaAPI    = "https://$tenantFQDN/PasswordVault/api"
$username   = "mike@acme.corp"
$password   = "Cyberark1"
$safeName   = "APIDemoSafe"
$adGroup    = "John@acme.corp"

$body = @{
    username = $username
    password = $password
}
$tokenResponse = Invoke-RestMethod -Uri "$pvwaAPI/auth/Cyberark/Logon" -Method POST -Body ($body | ConvertTo-Json) -ContentType "application/json"
$sessionToken = $tokenResponse

$safeBody = @{
    safeName                     = $safeName
    description                  = "Safe created via API"
    OLACEnabled                  = $false
    managingCPM                  = "PasswordManager"
    numberOfVersionsRetention    = 5
    numberOfDaysRetention        = 0
}

# 2) Add members from CSV (pick Option A or B above)
$members = Import-Csv .\members.csv   # or .\members-detailed.csv
foreach ($m in $members) {
    $perms = Get-CPCPermissionSet -Name $m.PermissionSet
    Add-CPCSafeMember -PVWAURL $PVWAURL -BearerToken $BearerToken `
        -SafeName $m.SafeName -MemberName $m.MemberName -MemberType $m.MemberType `
        -SearchIn $m.SearchIn -Permissions $perms
}
# ==========================
# Config (edit these)
# ==========================
$PVWAURL     = "https://<YourSubdomain>.privilegecloud.cyberark.cloud/PasswordVault"
# IMPORTANT: Include the "Bearer " prefix if your token is a raw JWT.
$BearerToken = "Bearer eyJhbGciOi..." 

# ==========================
# Helper: create a Safe (idempotent)
# ==========================
function New-CPCSafe {
    param(
        [Parameter(Mandatory)] [string] $PVWAURL,
        [Parameter(Mandatory)] [string] $BearerToken,
        [Parameter(Mandatory)] [string] $Name,
        [string] $Description = "Safe created via API",
        [string] $ManagingCPM = "PasswordManager",
        [int]    $VersionsRetention = 5,
        [int]    $DaysRetention = 0,
        [bool]   $OLACEnabled = $false
    )

    $headers = @{ Authorization = $BearerToken; "Content-Type" = "application/json" }

    # Skip if exists
    try {
        $null = Invoke-RestMethod -Uri "$PVWAURL/api/Safes/$($Name)" -Method GET -Headers $headers -ErrorAction Stop
        Write-Host "Safe '$Name' already exists. Skipping creation." -ForegroundColor Yellow
        return
    } catch {
        if ($_.Exception.Response.StatusCode.Value__ -ne 404) { throw }
    }

    $body = @{
        safeName                  = $Name
        description               = $Description
        OLACEnabled               = $OLACEnabled
        managingCPM               = $ManagingCPM
        numberOfVersionsRetention = $VersionsRetention
        numberOfDaysRetention     = $DaysRetention
    } | ConvertTo-Json

    Invoke-RestMethod -Uri "$PVWAURL/api/Safes" -Method POST -Headers $headers -Body $body -ErrorAction Stop
    Write-Host "Created safe '$Name'." -ForegroundColor Green
}

# ==========================
# Helper: quick permission sets (simple presets)
# ==========================
function Get-CPCPermissionSet {
    param(
        [Parameter(Mandatory)][ValidateSet('Reader','Contributor','Owner')]
        [string] $Name
    )
    switch ($Name) {
        'Reader' {
            return @{
                useAccounts=$false; retrieveAccounts=$true;  listAccounts=$true;   addAccounts=$false
                updateAccountContent=$false; updateAccountProperties=$false
                initiateCPMAccountManagementOperations=$false; specifyNextAccountContent=$false
                renameAccounts=$false; deleteAccounts=$false; unlockAccounts=$false
                manageSafe=$false; manageSafeMembers=$false; backupSafe=$false; viewAuditLog=$true
            }
        }
        'Contributor' {
            return @{
                useAccounts=$true; retrieveAccounts=$true;  listAccounts=$true;   addAccounts=$true
                updateAccountContent=$true; updateAccountProperties=$true
                initiateCPMAccountManagementOperations=$true; specifyNextAccountContent=$true
                renameAccounts=$true; deleteAccounts=$false; unlockAccounts=$false
                manageSafe=$false; manageSafeMembers=$false; backupSafe=$false; viewAuditLog=$true
            }
        }
        'Owner' {
            return @{
                useAccounts=$true; retrieveAccounts=$true;  listAccounts=$true;   addAccounts=$true
                updateAccountContent=$true; updateAccountProperties=$true
                initiateCPMAccountManagementOperations=$true; specifyNextAccountContent=$true
                renameAccounts=$true; deleteAccounts=$true; unlockAccounts=$true
                manageSafe=$true; manageSafeMembers=$true; backupSafe=$true; viewAuditLog=$true
            }
        }
    }
}

# ==========================
# Helper: add a member (user or group) to a Safe
# ==========================
function Add-CPCSafeMember {
    param(
        [Parameter(Mandatory)] [string] $PVWAURL,
        [Parameter(Mandatory)] [string] $BearerToken,
        [Parameter(Mandatory)] [string] $SafeName,
        [Parameter(Mandatory)] [string] $MemberName,
        [ValidateSet('User','Group')]   [string] $MemberType = 'Group',
        [string] $SearchIn = 'Vault',  # Examples: 'Vault' for vault users, 'Directory' or 'LDAP' for AD/IdP objects
        [hashtable] $Permissions
    )

    $headers = @{ Authorization = $BearerToken; "Content-Type" = "application/json" }

    if (-not $Permissions) {
        throw "Permissions must be provided (either via preset with Get-CPCPermissionSet or a custom hashtable)."
    }

    $body = @{
        memberName  = $MemberName
        memberType  = $MemberType
        searchIn    = $SearchIn
        permissions = $Permissions
    } | ConvertTo-Json -Depth 5

    try {
        Invoke-RestMethod -Uri "$PVWAURL/api/Safes/$($SafeName)/Members" -Method POST -Headers $headers -Body $body -ErrorAction Stop
        Write-Host "Added $MemberType '$MemberName' to safe '$SafeName'." -ForegroundColor Green
    } catch {
        $status = $_.Exception.Response.StatusCode.Value__
        if ($status -eq 409) {
            Write-Host "Member '$MemberName' is already in safe '$SafeName'. Skipping." -ForegroundColor Yellow
        } else {
            throw
        }
    }
}
