<#
.SYNOPSIS
    Hardened local privilege escalation enumeration (PowerUp-level accuracy)
#>

# =============================
# Helpers
# =============================

function Get-CurrentUserSIDs {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    @($id.User.Value) + $id.Groups.Value
}

function Get-ServiceExecutablePath {
    param ([string]$PathName)
    if ([string]::IsNullOrWhiteSpace($PathName)) { return $null }
    
    $expanded = [Environment]::ExpandEnvironmentVariables($PathName)

    # 1. Handle Quoted Paths
    if ($expanded -match '^"([^"]+)"') { return $matches[1] }

    # 2. Handle Unquoted Paths (Fixed Logic)
    # Grab everything from start to the first occurrence of '.exe'
    # This handles "C:\Program Files\App\bin.exe /s" correctly
    if ($expanded -match '^(.+?\.exe)') { return $matches[1] }

    # 3. Fallback: split by space (rare non-.exe cases)
    return ($expanded -split ' ')[0]
}

function Test-WriteAccess {
    param ([string]$Path, [string[]]$UserSIDs)
    # Check if file exists; if not, check parent directory (for Ghost/Hijack vectors)
    $target = if (Test-Path $Path) { $Path } else { Split-Path $Path -Parent }
    
    if (-not (Test-Path $target)) { return $null }
    
    try {
        $acl = Get-Acl $target -EA SilentlyContinue
        if (-not $acl) { return $null }
        
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -eq 'Allow' -and 
                $UserSIDs -contains $ace.IdentityReference.Value -and 
                ($ace.FileSystemRights -match 'Write|Modify|FullControl|CreateFiles')) {
                return @{ ID = $ace.IdentityReference.Value; Rights = $ace.FileSystemRights.ToString() }
            }
        }
    } catch {}
    return $null
}

# =============================
# PrivEsc Checks
# =============================

function Get-SystemSummary {
    [PSCustomObject]@{
        Hostname       = $env:COMPUTERNAME
        Username       = $env:USERNAME
        Architecture   = (Get-CimInstance Win32_OperatingSystem).OSArchitecture
        HighValuePrivs = (whoami /priv | Select-String 'SeImpersonate|SeBackup|SeRestore' | ForEach-Object { $_.ToString().Trim() })
    }
}

function Find-GhostScheduledTasks {
    param ($UserSIDs)
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -match 'SYSTEM|Administrator' -or $_.Principal.GroupId -eq 'S-1-5-32-544' } | ForEach-Object {
        foreach ($action in $_.Actions) {
            if (-not $action.Execute) { continue }
            
            # Combine Execute + Arguments to catch hidden paths
            $full = "$($action.Execute) $($action.Arguments)"
            $exe = Get-ServiceExecutablePath $full
            
            # If path is found AND it does not exist on disk -> Ghost
            if ($exe -and -not (Test-Path $exe)) { 
                $access = Test-WriteAccess -Path $exe -UserSIDs $UserSIDs
                if ($access) {
                    [PSCustomObject]@{ Vector='Ghost Scheduled Task'; Task=$_.TaskName; Path=$exe; Identity=$access.ID; Rights=$access.Rights; Severity='High' }
                }
            }
        }
    }
}

function Find-ServiceAnomalies {
    param ($UserSIDs, $Services)
    foreach ($svc in $Services) {
        $exe = Get-ServiceExecutablePath $svc.PathName
        if (-not $exe) { continue }
        
        # Check 1: Writable OR Ghost Binary
        $access = Test-WriteAccess -Path $exe -UserSIDs $UserSIDs
        if ($access) {
            $isGhost = -not (Test-Path $exe)
            [PSCustomObject]@{ 
                Vector   = if ($isGhost) { 'Ghost Service (Missing Binary)' } else { 'Writable Service Binary' }
                Service  = $svc.Name
                Path     = $exe
                Identity = $access.ID
                Rights   = $access.Rights
                Severity = if ($isGhost) { 'High' } else { 'Critical' }
            }
        }
        
        # Check 2: Unquoted Service Path (Hijack Execution Flow)
        if ($svc.PathName -notmatch '^".*"$' -and $svc.PathName -match ' ') {
            $parts = $exe -split '\\'
            for ($i = 1; $i -lt $parts.Count; $i++) {
                $candidate = ($parts[0..$i] -join '\')
                if ($candidate -match ' ' -and (Test-Path (Split-Path $candidate -Parent))) {
                    $access = Test-WriteAccess -Path $candidate -UserSIDs $UserSIDs
                    if ($access) {
                        [PSCustomObject]@{ Vector='Unquoted Service Path'; Service=$svc.Name; Path=$candidate; Identity=$access.ID; Rights=$access.Rights; Severity='High' }
                        break 
                    }
                }
            }
        }
    }
}

function Find-WritableStartupItems {
    param ($UserSIDs)
    $startupPaths = @(
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",
        "$env:AppData\Microsoft\Windows\Start Menu\Programs\StartUp"
    )
    foreach ($path in $startupPaths) {
        $access = Test-WriteAccess -Path $path -UserSIDs $UserSIDs
        if ($access) {
            [PSCustomObject]@{ Vector='Writable Startup Directory'; Path=$path; Identity=$access.ID; Rights=$access.Rights; Severity='Medium' }
        }
    }
}

function Find-ModifiableServiceRegistry {
    param ($UserSIDs, $Services)
    $subKeys = @('', '\Parameters', '\Environment')
    foreach ($svc in $Services) {
        foreach ($sub in $subKeys) {
            $key = "Registry::HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)$sub"
            try {
                $acl = Get-Acl $key -EA SilentlyContinue
                if (-not $acl) { continue }
                foreach ($ace in $acl.Access) {
                    if ($ace.AccessControlType -eq 'Allow' -and $UserSIDs -contains $ace.IdentityReference.Value -and ($ace.RegistryRights -match 'Write|SetValue|FullControl')) {
                        [PSCustomObject]@{ Vector='Service Registry Permissions'; Service=$svc.Name; Key=$key; Identity=$ace.IdentityReference.Value; Rights=$ace.RegistryRights.ToString(); Severity='High' }
                    }
                }
            } catch {}
        }
    }
}

function Test-AlwaysInstallElevated {
    if ((Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated -eq 1 -and
        (Get-ItemProperty 'HKCU:\Software\Policies\Microsoft\Windows\Installer' -Name AlwaysInstallElevated -EA SilentlyContinue).AlwaysInstallElevated -eq 1) {
        [PSCustomObject]@{ Vector='AlwaysInstallElevated'; Severity='Critical'; Details='HKLM and HKCU policies enabled' }
    }
}

# =============================
# Dispatcher
# =============================

function Invoke-HardenedPrivEsc {
    param ([switch]$ShowUI)
    $userSIDs = Get-CurrentUserSIDs
    $services = Get-CimInstance Win32_Service
    $results = @(
        Get-SystemSummary
        Find-GhostScheduledTasks -UserSIDs $userSIDs
        Find-ServiceAnomalies -UserSIDs $userSIDs -Services $services
        Find-WritableStartupItems -UserSIDs $userSIDs
        Find-ModifiableServiceRegistry -UserSIDs $userSIDs -Services $services
        Test-AlwaysInstallElevated
    ) | Where-Object { $_ }
    
    if ($ShowUI) { $results | Out-GridView }
    return $results
}
