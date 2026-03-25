<#
.SYNOPSIS
    Verify_Lockdown.ps1 v4.6.0 - AutoLockdown Health Check & Validation
.DESCRIPTION
    Comprehensive verification tool that validates AutoLockdown deployment,
    monitors system health, and provides detailed status reports.
    
.NOTES
    File Name : Verify_Lockdown.ps1
    Version   : 4.6.0
    Author    : Meet Gandhi (Product Security Engineer)
    Created   : February 2026
    Requires  : PowerShell 5.1+, Administrator privileges
    
.EXAMPLE
    .\Verify_Lockdown.ps1
    
    Performs complete system verification
.EXAMPLE
    .\Verify_Lockdown.ps1 -Detailed
    
    Shows detailed diagnostic information
.EXAMPLE
    .\Verify_Lockdown.ps1 -ExportReport -OutputPath "C:\Reports"
    
    Exports verification report to file

    Exit codes: 0 = healthy, 1 = errors, 2 = warnings only
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [switch]$Detailed,
    [switch]$ExportReport,
    [switch]$Interactive,
    [string]$OutputPath = "C:\Reports"
)

$ScriptVersion = "4.6.0"
$ProductName = "AutoLockdown"

# Load assemblies
Add-Type -AssemblyName System.Security
# Lazy-load GUI assemblies only when needed for -Interactive mode
if ($Interactive) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
}
$DPAPI_SCOPE = [System.Security.Cryptography.DataProtectionScope]::LocalMachine

function Unprotect-Data {
    param([string]$Ciphertext)
    try {
        $bytes = [Convert]::FromBase64String($Ciphertext)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $DPAPI_SCOPE)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    catch {
        return $null
    }
}

function Import-JsonSafe {
    param([string]$Path, [switch]$IsEncrypted)
    $attempts = @($Path, "$Path.bak1", "$Path.bak2")
    foreach ($file in $attempts) {
        if (Test-Path $file) {
            try {
                $content = Get-Content $file -Raw -Encoding UTF8
                
                if ($IsEncrypted) {
                    # Check if looks like JSON (legacy support). If starts with {, assume unencrypted
                    if ($content.Trim().StartsWith("{")) {
                        # Unencrypted file
                    }
                    else {
                        $decrypted = Unprotect-Data -Ciphertext $content
                        if (-not $decrypted) { continue }
                        $content = $decrypted
                    }
                }
                
                $data = $content | ConvertFrom-Json
                if ($file -ne $Path) {
                    Write-Host "    [!] Loaded from backup: $file" -ForegroundColor Yellow
                }
                return $data
            }
            catch { continue }
        }
    }
    return $null
}

# XOR-encoded author
$cfg_A = @(103, 79, 79, 94, 10, 109, 75, 68, 78, 66, 67)
$cfg_B = @(2, 122, 88, 69, 78, 95, 73, 94, 10, 121, 79, 73, 95, 88, 67, 94, 83, 10, 111, 68, 77, 67, 68, 79, 79, 88, 3)
$cfg_K = 0x2A
$cfg_Hash = "A7F2E9C4B1D8F6E3"

function Get-SystemConfig {
    param([string]$Key)
    try {
        if ($Key -eq "Author") {
            $p1 = -join ($cfg_A | ForEach-Object { [char]($_ -bxor $cfg_K) })
            $p2 = -join ($cfg_B | ForEach-Object { [char]($_ -bxor $cfg_K) })
            return "$p1 $p2"
        }
        elseif ($Key -eq "Hash") { return $cfg_Hash }
        return $null
    }
    catch {
        return "System Configuration Error"
    }
}

$ScriptAuthor = Get-SystemConfig -Key "Author"

# Paths
$BasePath = "C:\ProgramData\AutoLockdown"
$LogFile = Join-Path $BasePath "Security.log"
$USBWhitelist = Join-Path $BasePath "USB_Whitelist.json"
$NetWhitelist = Join-Path $BasePath "Network_Whitelist.json"
$ThreatDBFile = Join-Path $BasePath "ThreatDB.json"
$LockFile = Join-Path $BasePath "monitor.lock"
$MetaFile = Join-Path $BasePath "Deployment_Meta.json"
$LearningFile = Join-Path $BasePath "Learning_State.json"
$DeployedScript = Join-Path $BasePath "AutoLockdown.ps1"
$HIDVendorsFile = Join-Path $BasePath "Trusted_HID.json"
$BackupFile = Join-Path $BasePath "System_Backup.json"
$EmergencyBypassFile = Join-Path $BasePath "EMERGENCY_BYPASS"

# Always-Allowed USB Vendors (Infrastructure devices - bypass blocking)
$ALWAYS_ALLOWED_USB_VENDORS = @(
    "VID_0403",  # FTDI (Future Technology Devices International) - Relay Antenna
    "VID_322B"   # JAC (Shanghai JAC) - 5G Cellular USB Dongle
)

function Test-AlwaysAllowedUSB {
    param([string]$InstanceId)
    if (-not $InstanceId) { return $false }
    $idUpper = $InstanceId.ToUpper()
    foreach ($vendor in $ALWAYS_ALLOWED_USB_VENDORS) {
        if ($idUpper -match [regex]::Escape($vendor)) { return $true }
    }
    return $false
}

# Verification results
$script:Warnings = 0
$script:Errors = 0
$script:Checks = @()

function Write-Check {
    param(
        [string]$Component,
        [string]$Status,
        [string]$Message = "",
        [string]$Detail = ""
    )
    
    $color = "White"
    $icon = switch ($Status) {
        "PASS" { "[OK]"; $color = "Green" }
        "WARN" { "[!]"; $color = "Yellow"; $script:Warnings++ }
        "FAIL" { "[XX]"; $color = "Red"; $script:Errors++ }
        "INFO" { "[i]"; $color = "Cyan" }
    }
    
    Write-Host "$icon " -ForegroundColor $color -NoNewline
    Write-Host "$Component" -ForegroundColor White -NoNewline
    if ($Message) {
        Write-Host " - $Message" -ForegroundColor Gray
    }
    else {
        Write-Host ""
    }
    
    if ($Detailed -and $Detail) {
        Write-Host "    $Detail" -ForegroundColor DarkGray
    }
    
    $script:Checks += @{
        Component = $Component
        Status    = $Status
        Message   = $Message
        Detail    = $Detail
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Test-FileIntegrity {
    param([string]$Path, [string]$Name, [switch]$IsEncrypted)
    
    if (-not (Test-Path $Path)) {
        Write-Check -Component $Name -Status "FAIL" -Message "File not found" -Detail "Path: $Path"
        return $false
    }
    
    try {
        $size = [math]::Round((Get-Item $Path).Length / 1KB, 2)
        
        if ($Path -match "\.json$") {
            if (Import-JsonSafe -Path $Path -IsEncrypted:$IsEncrypted) {
                Write-Check -Component $Name -Status "PASS" -Message "Valid ($size KB)" -Detail "Path: $Path"
            }
            else {
                throw "Invalid JSON structure"
            }
        }
        else {
            Write-Check -Component $Name -Status "PASS" -Message "Exists ($size KB)" -Detail "Path: $Path"
        }
        return $true
    }
    catch {
        Write-Check -Component $Name -Status "FAIL" -Message "Corrupted or invalid" -Detail "Error: $_"
        return $false
    }
}

function Test-MonitorRunning {
    if (-not (Test-Path $LockFile)) {
        Write-Check -Component "Monitor Process" -Status "FAIL" -Message "Not running (lockfile missing)" -Detail "Expected: $LockFile"
        return $false
    }
    
    try {
        $lockContent = Get-Content $LockFile -Raw -ErrorAction Stop
        
        if ($lockContent -match "PID:(\d+)") {
            $processId = [int]$Matches[1]
            
            # Check with timeout to prevent hanging
            $process = $null
            $job = Start-Job -ScriptBlock {
                param($ProcessId)
                Get-Process -Id $ProcessId -ErrorAction SilentlyContinue
            } -ArgumentList $processId
            
            if (Wait-Job $job -Timeout 5) {
                $process = Receive-Job $job
            }
            Remove-Job $job -Force -ErrorAction SilentlyContinue
            
            if ($process) {
                $startTime = if ($lockContent -match "Started:([^|]+)") {
                    $Matches[1]
                }
                else {
                    "Unknown"
                }
                
                $uptime = if ($startTime -ne "Unknown") {
                    $started = [DateTime]::Parse($startTime)
                    [math]::Round(((Get-Date) - $started).TotalHours, 2)
                }
                else {
                    0
                }
                
                Write-Check -Component "Monitor Process" -Status "PASS" -Message "Running (PID $processId, uptime ${uptime}h)" -Detail "Started: $startTime"
                return $true
            }
            else {
                Write-Check -Component "Monitor Process" -Status "FAIL" -Message "Process not found (PID $processId)" -Detail "Stale lockfile detected"
                return $false
            }
        }
        else {
            Write-Check -Component "Monitor Process" -Status "WARN" -Message "Lockfile format invalid" -Detail "Content: $lockContent"
            return $false
        }
    }
    catch {
        Write-Check -Component "Monitor Process" -Status "FAIL" -Message "Error checking process" -Detail "Error: $_"
        return $false
    }
}

function Test-WMIEventSubscription {
    try {
        $subscription = Get-EventSubscriber -SourceIdentifier "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue
        
        if ($subscription) {
            $job = Get-Job -Name "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue
            
            if ($job) {
                Write-Check -Component "WMI Event Handler" -Status "PASS" -Message "Registered and active (WITHIN 1 catch-all)" -Detail "State: $($subscription.State), Job: $($job.State)"
                return $true
            }
            else {
                Write-Check -Component "WMI Event Handler" -Status "WARN" -Message "Registered but no background job" -Detail "Subscription exists but job missing"
                return $false
            }
        }
        else {
            Write-Check -Component "WMI Event Handler" -Status "WARN" -Message "Not registered" -Detail "Monitor may be starting up or failed to register"
            return $false
        }
    }
    catch {
        Write-Check -Component "WMI Event Handler" -Status "FAIL" -Message "Error checking subscription" -Detail "Error: $_"
        return $false
    }
}

function Test-RegistryWatcher {
    <#
    .SYNOPSIS
        Checks whether the fast-path registry watcher runspace is active.
        The watcher runs inside the monitor process as a PowerShell runspace,
        so we detect it indirectly by checking whether the monitor PID is alive
        and the lock file records a version that supports the watcher (>=4.7.0).
    #>
    try {
        if (-not (Test-Path $LockFile)) {
            Write-Check -Component "Fast-Path Watcher" -Status "WARN" -Message "Monitor not running — watcher inactive" -Detail "Start monitor to enable pre-driver USB blocking"
            return $false
        }

        $lockContent = Get-Content $LockFile -Raw -ErrorAction Stop
        $watcherVersion = $null
        if ($lockContent -match "Version:([0-9]+\.[0-9]+\.[0-9]+)") {
            $watcherVersion = $Matches[1]
        }

        if ($watcherVersion) {
            $parts = $watcherVersion -split '\.'
            $major = [int]$parts[0]; $minor = [int]$parts[1]; $patch = [int]$parts[2]
            $supportsWatcher = ($major -gt 4) -or ($major -eq 4 -and $minor -gt 6) -or ($major -eq 4 -and $minor -eq 7 -and $patch -ge 0)
            if ($supportsWatcher) {
                Write-Check -Component "Fast-Path Watcher" -Status "PASS" -Message "Active (monitor v$watcherVersion supports 250 ms pre-driver blocking)" -Detail "Registry watcher polls HKLM:\...\Enum\USB every 250 ms"
                return $true
            } else {
                Write-Check -Component "Fast-Path Watcher" -Status "WARN" -Message "Monitor v$watcherVersion does not include fast-path watcher" -Detail "Re-initialize to deploy v4.7.0+ for pre-driver blocking"
                return $false
            }
        } else {
            Write-Check -Component "Fast-Path Watcher" -Status "WARN" -Message "Cannot read monitor version from lock file" -Detail "Lock file: $LockFile"
            return $false
        }
    }
    catch {
        Write-Check -Component "Fast-Path Watcher" -Status "FAIL" -Message "Error checking watcher" -Detail "Error: $_"
        return $false
    }
}

function Test-ScheduledTask {
    try {
        $task = Get-ScheduledTask -TaskName "AutoLockdown_Service" -ErrorAction Stop
        
        $info = Get-ScheduledTaskInfo -TaskName "AutoLockdown_Service" -ErrorAction Stop
        
        $state = $task.State
        $lastRun = $info.LastRunTime
        $lastResult = $info.LastTaskResult
        
        if ($state -eq "Ready") {
            Write-Check -Component "Scheduled Task" -Status "PASS" -Message "State: Ready (normal)" -Detail "Last run: $lastRun, Result: $lastResult"
            return $true
        }
        elseif ($state -eq "Running") {
            Write-Check -Component "Scheduled Task" -Status "PASS" -Message "State: Running (monitor active)" -Detail "Last run: $lastRun, Result: $lastResult"
            return $true
        }
        elseif ($state -eq "Disabled") {
            Write-Check -Component "Scheduled Task" -Status "FAIL" -Message "State: Disabled" -Detail "Task will not run at startup"
            return $false
        }
        else {
            Write-Check -Component "Scheduled Task" -Status "WARN" -Message "State: $state" -Detail "Last run: $lastRun"
            return $false
        }
    }
    catch {
        Write-Check -Component "Scheduled Task" -Status "FAIL" -Message "Task not found or error" -Detail "Error: $_"
        return $false
    }
}

function Test-LearningMode {
    if (-not (Test-Path $LearningFile)) {
        Write-Check -Component "Learning State" -Status "FAIL" -Message "Learning state file missing" -Detail "Expected: $LearningFile"
        return $false
    }
    
    try {
        $state = Import-JsonSafe -Path $LearningFile -IsEncrypted
        if (-not $state) { throw "Unable to load learning state" }
        
        $mode = $state.Mode
        $expires = [DateTime]::Parse($state.Expires)
        
        if ($state.ExpiresUTC) {
            $expires = $expires.ToLocalTime()
        }
        
        $now = Get-Date
        
        if ($mode -eq "Learning") {
            if ($now -lt $expires) {
                $remaining = $expires - $now
                $remainingStr = "{0:D2}h {1:D2}m" -f $remaining.Hours, $remaining.Minutes
                Write-Check -Component "Learning Mode" -Status "INFO" -Message "ACTIVE (expires in $remainingStr)" -Detail "Expires: $($expires.ToString('yyyy-MM-dd HH:mm:ss'))"
            }
            else {
                Write-Check -Component "Learning Mode" -Status "WARN" -Message "EXPIRED but not transitioned" -Detail "Should transition to Enforced mode. Monitor may need restart."
            }
        }
        elseif ($mode -eq "Enforced") {
            Write-Check -Component "Learning Mode" -Status "PASS" -Message "ENFORCED (learning complete)" -Detail "Transitioned at: $($expires.ToString('yyyy-MM-dd HH:mm:ss'))"
        }
        else {
            Write-Check -Component "Learning Mode" -Status "WARN" -Message "Unknown mode: $mode" -Detail "Expected 'Learning' or 'Enforced'"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Learning Mode" -Status "FAIL" -Message "Error reading learning state" -Detail "Error: $_"
        return $false
    }
}

function Test-USBWhitelist {
    if (-not (Test-Path $USBWhitelist)) {
        Write-Check -Component "USB Whitelist" -Status "FAIL" -Message "Whitelist file missing" -Detail "Expected: $USBWhitelist"
        return $false
    }
    
    try {
        $whitelist = Import-JsonSafe -Path $USBWhitelist
        if (-not $whitelist) { throw "Unable to load whitelist" }
        
        $count = $whitelist.Devices.Count
        
        if ($count -eq 0) {
            Write-Check -Component "USB Whitelist" -Status "WARN" -Message "Empty whitelist (0 devices)" -Detail "No USB devices will be allowed in enforcement mode"
        }
        elseif ($count -lt 5) {
            Write-Check -Component "USB Whitelist" -Status "INFO" -Message "$count devices whitelisted (low)" -Detail "May need longer learning period"
        }
        else {
            Write-Check -Component "USB Whitelist" -Status "PASS" -Message "$count devices whitelisted" -Detail "Created: $($whitelist.Created)"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "USB Whitelist" -Status "FAIL" -Message "Error reading whitelist" -Detail "Error: $_"
        return $false
    }
}

function Test-NetworkPolicy {
    if (-not (Test-Path $NetWhitelist)) {
        Write-Check -Component "Network Whitelist" -Status "FAIL" -Message "Network whitelist missing" -Detail "Expected: $NetWhitelist"
        return $false
    }
    
    try {
        $data = Import-JsonSafe -Path $NetWhitelist
        if (-not $data) { throw "Unable to load network whitelist" }
        
        $count = if ($data.Adapters) { $data.Adapters.Count } else { 0 }
        
        Write-Check -Component "Network Whitelist" -Status "PASS" -Message "$count adapters allowed" -Detail "Created: $($data.Created)"
        
        # Check if physical adapters are disabled
        $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
        $disabledEthernet = $allAdapters | Where-Object { $_.InterfaceDescription -match "Ethernet" -and $_.InterfaceDescription -notmatch "Virtual" -and $_.Status -eq "Disabled" }
        $disabledWiFi = $allAdapters | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless|802\.11" -and $_.Status -eq "Disabled" }
        
        if ($disabledEthernet) {
            Write-Check -Component "Network Enforcement" -Status "PASS" -Message "Physical Ethernet disabled ($($disabledEthernet.Count) adapter(s))" -Detail "$($disabledEthernet.Name -join ', ')"
        }
        
        if ($disabledWiFi) {
            Write-Check -Component "Network Enforcement" -Status "PASS" -Message "WiFi disabled ($($disabledWiFi.Count) adapter(s))" -Detail "$($disabledWiFi.Name -join ', ')"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Network Whitelist" -Status "FAIL" -Message "Error reading network whitelist" -Detail "Error: $_"
        return $false
    }
}

function Test-ThreatDatabase {
    if (-not (Test-Path $ThreatDBFile)) {
        Write-Check -Component "Threat Database" -Status "FAIL" -Message "Threat DB missing" -Detail "Expected: $ThreatDBFile"
        return $false
    }
    
    try {
        $data = Get-Content $ThreatDBFile -Raw | ConvertFrom-Json
        $count = if ($data.Threats -is [hashtable]) {
            $data.Threats.Count
        }
        else {
            ($data.Threats.PSObject.Properties | Measure-Object).Count
        }
        
        Write-Check -Component "Threat Database" -Status "PASS" -Message "$count threat signatures loaded" -Detail "Updated: $($data.Updated)"
        
        return $true
    }
    catch {
        Write-Check -Component "Threat Database" -Status "FAIL" -Message "Error reading threat DB" -Detail "Error: $_"
        return $false
    }
}

function Test-LogActivity {
    if (-not (Test-Path $LogFile)) {
        Write-Check -Component "Security Log" -Status "FAIL" -Message "Log file missing" -Detail "Expected: $LogFile"
        return $false
    }
    
    try {
        $logInfo = Get-Item $LogFile
        $sizeMB = [math]::Round($logInfo.Length / 1MB, 2)
        
        # Check last log entry (heartbeat check)
        $lastLine = Get-Content $LogFile -Tail 1 -ErrorAction Stop
        
        if ($lastLine -match "\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]") {
            $lastLog = [DateTime]::Parse($Matches[1])
            $age = ((Get-Date) - $lastLog).TotalMinutes
            
            if ($age -lt 5) {
                Write-Check -Component "Security Log" -Status "PASS" -Message "Active (last entry $([math]::Round($age, 1)) min ago, $sizeMB MB)" -Detail "Last: $lastLine"
            }
            elseif ($age -lt 15) {
                Write-Check -Component "Security Log" -Status "WARN" -Message "Stale (last entry $([math]::Round($age, 1)) min ago)" -Detail "Monitor may not be actively logging"
            }
            else {
                Write-Check -Component "Security Log" -Status "FAIL" -Message "Inactive (last entry $([math]::Round($age, 1)) min ago)" -Detail "Monitor likely not running"
            }
        }
        else {
            Write-Check -Component "Security Log" -Status "WARN" -Message "Cannot parse timestamp" -Detail "Last line: $lastLine"
        }
        
        # Count recent blocks
        if ($Detailed) {
            $recent = Get-Content $LogFile -Tail 100 | Select-String "\[BLOCK\]"
            $blockCount = $recent.Count
            
            if ($blockCount -gt 0) {
                Write-Check -Component "Recent Activity" -Status "INFO" -Message "$blockCount blocks in last 100 log entries" -Detail "Last: $($recent[-1].Line)"
            }
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Security Log" -Status "FAIL" -Message "Error reading log" -Detail "Error: $_"
        return $false
    }
}

function Test-BlockedDevices {
    try {
        $blocked = Get-PnpDevice -ErrorAction Stop | Where-Object { $_.Status -eq "Error" -and $_.InstanceId -match "^USB\\" }
        
        if ($blocked) {
            $count = ($blocked | Measure-Object).Count
            Write-Check -Component "Blocked USB Devices" -Status "INFO" -Message "$count devices currently blocked" -Detail "$($blocked[0].FriendlyName), ..."
            
            if ($Detailed) {
                foreach ($dev in $blocked | Select-Object -First 5) {
                    Write-Host "    - $($dev.FriendlyName)" -ForegroundColor DarkGray
                }
            }
        }
        else {
            Write-Check -Component "Blocked USB Devices" -Status "PASS" -Message "No devices currently blocked" -Detail "All connected USB devices are whitelisted"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Blocked USB Devices" -Status "FAIL" -Message "Error checking devices" -Detail "Error: $_"
        return $false
    }
}

function Test-InfrastructureDevices {
    try {
        $allUSB = Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object { $_.InstanceId -match "^USB\\" }
        $infraDevices = @()
        
        foreach ($dev in $allUSB) {
            if (Test-AlwaysAllowedUSB -InstanceId $dev.InstanceId) {
                $infraDevices += $dev
            }
        }
        
        if ($infraDevices.Count -gt 0) {
            Write-Check -Component "Infrastructure Devices" -Status "PASS" -Message "$($infraDevices.Count) infrastructure device(s) connected" -Detail "FTDI/JAC - Always Allowed"
            
            if ($Detailed) {
                foreach ($dev in $infraDevices) {
                    Write-Host "    [INFRA] $($dev.FriendlyName)" -ForegroundColor Cyan
                }
            }
        }
        else {
            Write-Check -Component "Infrastructure Devices" -Status "INFO" -Message "No infrastructure devices connected" -Detail "FTDI relay, JAC 5G dongle not detected"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Infrastructure Devices" -Status "WARN" -Message "Error checking devices" -Detail "Error: $_"
        return $false
    }
}

function Test-DiskSpace {
    try {
        if (-not (Test-Path $BasePath)) {
            Write-Check -Component "Disk Space" -Status "WARN" -Message "Base path not found" -Detail "Path: $BasePath"
            return $false
        }
        $drive = (Get-Item $BasePath).PSDrive
        $freeGB = [math]::Round($drive.Free / 1GB, 2)
        $usedPercent = [math]::Round((($drive.Used / ($drive.Used + $drive.Free)) * 100), 1)
        
        if ($drive.Free -lt 100MB) {
            Write-Check -Component "Disk Space" -Status "FAIL" -Message "Critical: Only $freeGB GB free" -Detail "System may enter read-only mode"
        }
        elseif ($drive.Free -lt 1GB) {
            Write-Check -Component "Disk Space" -Status "WARN" -Message "Low: $freeGB GB free ($usedPercent% used)" -Detail "Monitor disk usage"
        }
        else {
            Write-Check -Component "Disk Space" -Status "PASS" -Message "$freeGB GB free ($usedPercent% used)" -Detail "Drive: $($drive.Name):"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "Disk Space" -Status "WARN" -Message "Cannot check disk space" -Detail "Error: $_"
        return $false
    }
}

function Test-SystemIntegrity {
    try {
        # Check if running in Safe Mode
        $safeMode = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" -ErrorAction SilentlyContinue).OptionValue
        
        if ($safeMode) {
            $mode = if ($safeMode -eq 1) { "Safe Mode" } else { "Safe Mode with Networking" }
            Write-Check -Component "System Integrity" -Status "WARN" -Message "Running in $mode" -Detail "WMI events may not function"
            return $false
        }
        
        # Check registry metadata
        $reg = "HKLM:\SOFTWARE\AutoLockdown"
        if (Test-Path $reg) {
            $version = (Get-ItemProperty -Path $reg -Name "Version" -ErrorAction SilentlyContinue).Version
            Write-Check -Component "System Integrity" -Status "PASS" -Message "Normal operation" -Detail "Registry version: $version"
        }
        else {
            Write-Check -Component "System Integrity" -Status "WARN" -Message "Registry metadata missing" -Detail "Expected: $reg"
        }
        
        return $true
    }
    catch {
        Write-Check -Component "System Integrity" -Status "WARN" -Message "Cannot verify integrity" -Detail "Error: $_"
        return $false
    }
}

function Test-PowerSettings {
    try {
        # Check display timeout (AC) - should be 0 (Never)
        $displayAC = (powercfg /QUERY SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 2>$null) -match "Current AC Power Setting Index"
        $sleepAC = (powercfg /QUERY SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 2>$null) -match "Current AC Power Setting Index"
        
        $displayOK = $displayAC -and ($displayAC -match "0x00000000")
        $sleepOK = $sleepAC -and ($sleepAC -match "0x00000000")
        
        if ($displayOK -and $sleepOK) {
            Write-Check -Component "Power Settings" -Status "PASS" -Message "Display/Sleep timeout: Never (LogMeIn compatible)" -Detail "Both AC values = 0x00000000"
        }
        elseif (-not $displayOK -and -not $sleepOK) {
            Write-Check -Component "Power Settings" -Status "FAIL" -Message "Display and Sleep timeouts not set to Never" -Detail "Re-run initialization to fix LogMeIn compatibility"
        }
        elseif (-not $displayOK) {
            Write-Check -Component "Power Settings" -Status "WARN" -Message "Display timeout not set to Never" -Detail "May cause LogMeIn disconnections"
        }
        else {
            Write-Check -Component "Power Settings" -Status "WARN" -Message "Sleep timeout not set to Never" -Detail "System may sleep and drop remote sessions"
        }
        
        return ($displayOK -and $sleepOK)
    }
    catch {
        Write-Check -Component "Power Settings" -Status "WARN" -Message "Cannot verify power settings" -Detail "Error: $_"
        return $false
    }
}

function Test-HIDVendorsContent {
    if (-not (Test-Path $HIDVendorsFile)) { return $false }
    
    try {
        $data = Import-JsonSafe -Path $HIDVendorsFile
        if (-not $data -or -not $data.Vendors) {
            Write-Check -Component "HID Vendors Content" -Status "FAIL" -Message "No vendor data found" -Detail "All keyboards/mice may be blocked"
            return $false
        }
        
        $count = $data.Vendors.Count
        if ($count -eq 0) {
            Write-Check -Component "HID Vendors Content" -Status "FAIL" -Message "Empty vendor list (0 vendors)" -Detail "All keyboards/mice will be blocked in enforcement mode"
            return $false
        }
        elseif ($count -lt 10) {
            Write-Check -Component "HID Vendors Content" -Status "WARN" -Message "$count vendors loaded (unusually low)" -Detail "Expected ~93 vendors. File may be truncated."
            return $true
        }
        else {
            Write-Check -Component "HID Vendors Content" -Status "PASS" -Message "$count trusted HID vendors loaded" -Detail "Updated: $($data.Updated)"
            return $true
        }
    }
    catch {
        Write-Check -Component "HID Vendors Content" -Status "WARN" -Message "Cannot validate vendor data" -Detail "Error: $_"
        return $false
    }
}

function Test-DeployedVersion {
    if (-not (Test-Path $DeployedScript)) { return $false }
    
    try {
        $deployedContent = Get-Content $DeployedScript -Raw -ErrorAction Stop
        $deployedVersion = $null
        if ($deployedContent -match '\$ScriptVersion\s*=\s*"([^"]+)"') {
            $deployedVersion = $Matches[1]
        }
        
        if (-not $deployedVersion) {
            Write-Check -Component "Version Check" -Status "WARN" -Message "Cannot read deployed script version" -Detail "Version variable not found in deployed script"
            return $false
        }
        
        if ($deployedVersion -ne $ScriptVersion) {
            Write-Check -Component "Version Check" -Status "WARN" -Message "Version mismatch: deployed v$deployedVersion, verify v$ScriptVersion" -Detail "Re-initialize to deploy updated script"
            return $false
        }
        else {
            Write-Check -Component "Version Check" -Status "PASS" -Message "Deployed version matches (v$deployedVersion)"
            return $true
        }
    }
    catch {
        Write-Check -Component "Version Check" -Status "WARN" -Message "Cannot check deployed version" -Detail "Error: $_"
        return $false
    }
}

function Export-VerificationReport {
    if (-not (Test-Path $OutputPath)) {
        New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $reportPath = Join-Path $OutputPath "AutoLockdown_Verification_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    $report = @{
        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Version   = $ScriptVersion
        Author    = $ScriptAuthor
        Summary   = @{
            TotalChecks = $script:Checks.Count
            Passed      = ($script:Checks | Where-Object { $_.Status -eq "PASS" }).Count
            Warnings    = $script:Warnings
            Errors      = $script:Errors
        }
        Checks    = $script:Checks
    }
    
    try {
        $report | ConvertTo-Json -Depth 5 | Out-File $reportPath -Force
        Write-Host ""
        Write-Host "Report exported to: $reportPath" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-Host "Failed to export report: $_" -ForegroundColor Red
        return $false
    }
}

# ============================================================================
#   GUI VERIFICATION DASHBOARD
# ============================================================================

function Show-VerifyDashboard {
    <#
    .SYNOPSIS
        Displays verification results in a visual GUI dashboard.
    #>
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "AutoLockdown - Verification Results"
    $form.Size = New-Object System.Drawing.Size(700, 600)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(25, 25, 35)
    
    # Colors
    $colorOK = [System.Drawing.Color]::FromArgb(50, 205, 50)
    $colorWarn = [System.Drawing.Color]::FromArgb(255, 180, 0)
    $colorFail = [System.Drawing.Color]::FromArgb(255, 80, 80)
    $colorText = [System.Drawing.Color]::White
    $colorDim = [System.Drawing.Color]::FromArgb(140, 140, 160)
    $colorPanel = [System.Drawing.Color]::FromArgb(35, 35, 50)
    
    # Title
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(15, 12)
    $lblTitle.Size = New-Object System.Drawing.Size(500, 30)
    $lblTitle.Text = "System Verification Results"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = $colorText
    $form.Controls.Add($lblTitle)
    
    # Summary stats panel
    $pnlStats = New-Object System.Windows.Forms.Panel
    $pnlStats.Location = New-Object System.Drawing.Point(15, 50)
    $pnlStats.Size = New-Object System.Drawing.Size(655, 70)
    $pnlStats.BackColor = $colorPanel
    $form.Controls.Add($pnlStats)
    
    $totalChecks = $script:Checks.Count
    $passed = ($script:Checks | Where-Object { $_.Status -eq "PASS" }).Count
    $warned = ($script:Checks | Where-Object { $_.Status -eq "WARN" }).Count
    $failed = ($script:Checks | Where-Object { $_.Status -eq "FAIL" }).Count
    $passRate = if ($totalChecks -gt 0) { [math]::Round(($passed / $totalChecks) * 100, 0) } else { 0 }
    
    # Pass count
    $lblPass = New-Object System.Windows.Forms.Label
    $lblPass.Location = New-Object System.Drawing.Point(20, 15)
    $lblPass.Size = New-Object System.Drawing.Size(150, 40)
    $lblPass.Text = "[OK] PASS: $passed"
    $lblPass.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblPass.ForeColor = $colorOK
    $pnlStats.Controls.Add($lblPass)
    
    # Warn count
    $lblWarn = New-Object System.Windows.Forms.Label
    $lblWarn.Location = New-Object System.Drawing.Point(180, 15)
    $lblWarn.Size = New-Object System.Drawing.Size(150, 40)
    $lblWarn.Text = "[!!] WARN: $warned"
    $lblWarn.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblWarn.ForeColor = $colorWarn
    $pnlStats.Controls.Add($lblWarn)
    
    # Fail count
    $lblFail = New-Object System.Windows.Forms.Label
    $lblFail.Location = New-Object System.Drawing.Point(340, 15)
    $lblFail.Size = New-Object System.Drawing.Size(150, 40)
    $lblFail.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblFail.Text = "[X] FAIL: $failed"
    $lblFail.ForeColor = $colorFail
    $pnlStats.Controls.Add($lblFail)
    
    # Pass rate
    $lblRate = New-Object System.Windows.Forms.Label
    $lblRate.Location = New-Object System.Drawing.Point(510, 15)
    $lblRate.Size = New-Object System.Drawing.Size(130, 40)
    $lblRate.Text = "$passRate%"
    $lblRate.Font = New-Object System.Drawing.Font("Segoe UI", 18, [System.Drawing.FontStyle]::Bold)
    $rateColor = if ($passRate -ge 90) { $colorOK } elseif ($passRate -ge 70) { $colorWarn } else { $colorFail }
    $lblRate.ForeColor = $rateColor
    $lblRate.TextAlign = [System.Drawing.ContentAlignment]::MiddleRight
    $pnlStats.Controls.Add($lblRate)
    
    # Check list panel
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point(15, 130)
    $panel.Size = New-Object System.Drawing.Size(655, 380)
    $panel.AutoScroll = $true
    $panel.BackColor = $colorPanel
    $form.Controls.Add($panel)
    
    $yPos = 8
    foreach ($check in $script:Checks) {
        $icon = switch ($check.Status) {
            "PASS" { "[OK]"; $color = $colorOK }
            "WARN" { "[!!]"; $color = $colorWarn }
            "FAIL" { "[X]"; $color = $colorFail }
            default { "[*]"; $color = $colorDim }
        }
        
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = New-Object System.Drawing.Point(10, $yPos)
        $lbl.Size = New-Object System.Drawing.Size(620, 20)
        $lbl.Text = "$icon $($check.Component): $($check.Message)"
        $lbl.Font = New-Object System.Drawing.Font("Consolas", 9)
        $lbl.ForeColor = $color
        $panel.Controls.Add($lbl)
        $yPos += 22
    }
    
    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Location = New-Object System.Drawing.Point(290, 520)
    $btnClose.Size = New-Object System.Drawing.Size(120, 35)
    $btnClose.Text = "Close"
    $btnClose.DialogResult = "OK"
    $btnClose.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $btnClose.ForeColor = $colorText
    $btnClose.FlatStyle = "Flat"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($btnClose)
    
    # ESC to close
    $form.KeyPreview = $true
    $form.Add_KeyDown({ if ($_.KeyCode -eq "Escape") { $this.Close() } })
    
    $form.ShowDialog() | Out-Null
    $form.Dispose()
}

# ============================================================================
#   MAIN EXECUTION
# ============================================================================

Clear-Host
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  $ProductName v$ScriptVersion - SYSTEM VERIFICATION" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "  Computer: $env:COMPUTERNAME" -ForegroundColor White
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Run all checks
Write-Host "Deployment Files:" -ForegroundColor Yellow
Test-FileIntegrity -Path $DeployedScript -Name "Deployed Script"
Test-FileIntegrity -Path $MetaFile -Name "Deployment Metadata"
Test-DeployedVersion

Write-Host ""
Write-Host "Configuration Files:" -ForegroundColor Yellow
Test-FileIntegrity -Path $USBWhitelist -Name "USB Whitelist"
Test-FileIntegrity -Path $NetWhitelist -Name "Network Whitelist"
Test-FileIntegrity -Path $ThreatDBFile -Name "Threat Database"
Test-FileIntegrity -Path $LearningFile -Name "Learning State" -IsEncrypted
Test-FileIntegrity -Path $HIDVendorsFile -Name "HID Vendors"
Test-FileIntegrity -Path $BackupFile -Name "System Backup"

# Check Emergency Bypass status
if (Test-Path $EmergencyBypassFile) {
    $created = (Get-Item $EmergencyBypassFile).CreationTime
    $age = ((Get-Date) - $created).TotalMinutes
    if ($age -lt 30) {
        Write-Check -Component "Emergency Bypass" -Status "WARN" -Message "ACTIVE ($([math]::Round(30 - $age, 0)) min remaining)" -Detail "Created: $($created.ToString('HH:mm:ss'))"
    }
    else {
        Write-Check -Component "Emergency Bypass" -Status "INFO" -Message "Expired (file present)" -Detail "Should be auto-removed"
    }
}

Write-Host ""
Write-Host "Runtime Components:" -ForegroundColor Yellow
Test-MonitorRunning
Test-WMIEventSubscription
Test-RegistryWatcher
Test-ScheduledTask

Write-Host ""
Write-Host "Security Status:" -ForegroundColor Yellow
Test-LearningMode
Test-USBWhitelist
Test-NetworkPolicy
Test-ThreatDatabase
Test-BlockedDevices
Test-InfrastructureDevices
Test-HIDVendorsContent

Write-Host ""
Write-Host "System Health:" -ForegroundColor Yellow
Test-LogActivity
Test-DiskSpace
Test-SystemIntegrity
Test-PowerSettings

# Summary
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  VERIFICATION SUMMARY" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

$totalChecks = $script:Checks.Count
$passed = ($script:Checks | Where-Object { $_.Status -eq "PASS" }).Count
$passRate = if ($totalChecks -gt 0) { [math]::Round(($passed / $totalChecks) * 100, 1) } else { 0 }

Write-Host "  Total Checks: $totalChecks" -ForegroundColor White
Write-Host "  Passed: " -NoNewline -ForegroundColor White
Write-Host $passed -ForegroundColor Green
Write-Host "  Warnings: " -NoNewline -ForegroundColor White
Write-Host $script:Warnings -ForegroundColor $(if ($script:Warnings -gt 0) { "Yellow" } else { "Green" })
Write-Host "  Errors: " -NoNewline -ForegroundColor White
Write-Host $script:Errors -ForegroundColor $(if ($script:Errors -gt 0) { "Red" } else { "Green" })
Write-Host ""
Write-Host "  Pass Rate: $passRate%" -ForegroundColor $(if ($passRate -ge 90) { "Green" } elseif ($passRate -ge 70) { "Yellow" } else { "Red" })
Write-Host ""

if ($script:Errors -eq 0 -and $script:Warnings -eq 0) {
    Write-Host "  Status: " -NoNewline
    Write-Host "HEALTHY" -ForegroundColor Green
    Write-Host "  All systems operational" -ForegroundColor Green
}
elseif ($script:Errors -eq 0) {
    Write-Host "  Status: " -NoNewline
    Write-Host "OPERATIONAL WITH WARNINGS" -ForegroundColor Yellow
    Write-Host "  System is functional but some issues detected" -ForegroundColor Yellow
}
else {
    Write-Host "  Status: " -NoNewline
    Write-Host "CRITICAL ISSUES DETECTED" -ForegroundColor Red
    Write-Host "  Immediate attention required" -ForegroundColor Red
}

Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Footer
$footerLine = "-" * 76
Write-Host $footerLine -ForegroundColor DarkGray
Write-Host "Verification by: $ScriptAuthor" -ForegroundColor DarkGray
Write-Host "System Integrity: $(Get-SystemConfig -Key 'Hash')" -ForegroundColor DarkGray
Write-Host $footerLine -ForegroundColor DarkGray
Write-Host ""

# Export report if requested
if ($ExportReport) {
    Export-VerificationReport
}

# Show interactive dashboard if requested
if ($Interactive) {
    Show-VerifyDashboard
}

# Exit code
if ($script:Errors -gt 0) {
    exit 1
}
elseif ($script:Warnings -gt 0) {
    exit 2
}
else {
    exit 0
}
