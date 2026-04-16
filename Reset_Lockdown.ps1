<#
.SYNOPSIS
    Reset_Lockdown.ps1 v4.9.1 - AutoLockdown System Reset & Cleanup
.DESCRIPTION
    Safely removes all AutoLockdown components and restores the system
    to its pre-deployment state. Creates backup before removal.
    
.NOTES
    File Name : Reset_Lockdown.ps1
    Version   : 4.9.1
    Author    : Meet Gandhi (Product Security Engineer)
    Created   : April 2026
    Requires  : PowerShell 5.1+, Administrator privileges
    
    Changelog v4.9.1:
    - Fixed USB restore timing behavior: reset now performs multi-pass USB re-enable
      retries so dependent/composite devices are restored in one reset run.
    - Version bump to match AutoLockdown v4.9.1.

    Changelog v4.9.0:
    - Version bump to match AutoLockdown v4.9.0.
    
.EXAMPLE
    .\Reset_Lockdown.ps1
    
    Performs full system reset with confirmation
.EXAMPLE
    .\Reset_Lockdown.ps1 -Force
    
    Resets without confirmation prompts
.EXAMPLE
    .\Reset_Lockdown.ps1 -KeepLogs
    
    Resets but preserves log files for analysis
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Force,
    [switch]$KeepLogs,
    [switch]$KeepWhitelist,
    [switch]$Interactive
)

$ScriptVersion = "4.9.1"
$ProductName = "AutoLockdown"

# Load assemblies for GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

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
    catch { return "System Configuration Error" }
}

$ScriptAuthor = Get-SystemConfig -Key "Author"

# Paths
$BasePath = "C:\ProgramData\AutoLockdown"
$LogFile = Join-Path $BasePath "Security.log"
$ResetLog = Join-Path $BasePath "Reset.log"
$BackupFile = Join-Path $BasePath "System_Backup.json"
$LockFile = Join-Path $BasePath "monitor.lock"

# Reset state
$script:Steps = 0
$script:Warnings = 0
$script:Errors = 0

function Write-ResetLog {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$timestamp] [$Level] $Message"
    
    $color = switch ($Level) {
        "SUCCESS" { "Green" }
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        default { "White" }
    }
    
    Write-Host $line -ForegroundColor $color
    
    try {
        Add-Content -Path $ResetLog -Value $line -Force -ErrorAction SilentlyContinue
    }
    catch {}
}

function Write-Step {
    param([string]$Step, [string]$Status, [string]$Detail = "")
    $script:Steps++
    
    # Separate icon/color from counter side-effects to keep $icon clean
    $stepIcon = "[..]"
    $stepColor = "White"
    switch ($Status) {
        "OK"   { $stepIcon = "[OK]"; $stepColor = "Green" }
        "SKIP" { $stepIcon = "[--]"; $stepColor = "DarkGray" }
        "WARN" { $stepIcon = "[!!]"; $stepColor = "Yellow"; $script:Warnings++ }
        "FAIL" { $stepIcon = "[XX]"; $stepColor = "Red"; $script:Errors++ }
    }
    
    Write-Host "  $stepIcon " -ForegroundColor $stepColor -NoNewline
    Write-Host "$Step" -ForegroundColor White
    if ($Detail) { Write-Host "      $Detail" -ForegroundColor DarkGray }
    
    Write-ResetLog "$Step - $Status $(if ($Detail) { "- $Detail" })" $Status
}

function Backup-PreResetState {
    Write-ResetLog "Creating pre-reset backup..." "INFO"
    
    try {
        $snapshot = @{
            Timestamp        = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Computer         = $env:COMPUTERNAME
            HasWhitelist     = (Test-Path (Join-Path $BasePath "USB_Whitelist.json"))
            HasNetWhitelist  = (Test-Path (Join-Path $BasePath "Network_Whitelist.json"))
            HasLearningState = (Test-Path (Join-Path $BasePath "Learning_State.json"))
            HasScheduledTask = $null -ne (Get-ScheduledTask -TaskName "AutoLockdown_Service" -ErrorAction SilentlyContinue)
            MonitorRunning   = (Test-Path $LockFile)
        }
        
        $snapshotPath = Join-Path $BasePath "PreReset_Snapshot.json"
        $snapshot | ConvertTo-Json -Depth 3 | Out-File $snapshotPath -Force
        
        # Also copy to temp so it survives directory deletion
        $tempCopy = Join-Path $env:TEMP "AutoLockdown_PreReset_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        Copy-Item $snapshotPath $tempCopy -Force -ErrorAction SilentlyContinue
        
        Write-Step "Pre-reset backup" "OK" "Saved to $tempCopy"
    }
    catch {
        Write-Step "Pre-reset backup" "WARN" "Error: $_"
    }
}

function Stop-MonitorProcess {
    Write-ResetLog "Stopping monitor process..." "INFO"
    
    if (Test-Path $LockFile) {
        try {
            $content = Get-Content $LockFile -Raw -ErrorAction Stop
            if ($content -match "PID:(\d+)") {
                $monitorPid = [int]$Matches[1]
                $process = Get-Process -Id $monitorPid -ErrorAction SilentlyContinue
                if ($process) {
                    if ($PSCmdlet.ShouldProcess("Process $monitorPid", "Stop")) {
                        Stop-Process -Id $monitorPid -Force -ErrorAction Stop
                        Start-Sleep -Milliseconds 500
                        Write-Step "Stop monitor (PID $monitorPid)" "OK"
                    }
                }
                else {
                    Write-Step "Stop monitor" "SKIP" "Process not running"
                }
            }
            Remove-Item $LockFile -Force -ErrorAction SilentlyContinue
        }
        catch {
            Write-Step "Stop monitor" "WARN" "Error: $_"
        }
    }
    else {
        Write-Step "Stop monitor" "SKIP" "Not running"
    }
}

function Remove-ScheduledTask {
    Write-ResetLog "Removing scheduled task..." "INFO"
    
    $taskName = "AutoLockdown_Service"
    try {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            if ($PSCmdlet.ShouldProcess($taskName, "Remove")) {
                Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop
                Write-Step "Remove scheduled task" "OK"
            }
        }
        else {
            Write-Step "Remove scheduled task" "SKIP" "Not found"
        }
    }
    catch {
        Write-Step "Remove scheduled task" "FAIL" "Error: $_"
    }
}

function Remove-WMISubscription {
    Write-ResetLog "Removing WMI subscriptions..." "INFO"
    
    try {
        $sub = Get-EventSubscriber -SourceIdentifier "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue
        if ($sub) {
            Unregister-Event -SourceIdentifier "AutoLockdown_USBWatch" -ErrorAction Stop
            Write-Step "Remove WMI subscription" "OK"
        }
        else {
            Write-Step "Remove WMI subscription" "SKIP" "Not registered"
        }
        
        Get-Job -Name "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue | Remove-Job -Force
    }
    catch {
        Write-Step "Remove WMI subscription" "WARN" "Error: $_"
    }
}

function Restore-NetworkAdapters {
    Write-ResetLog "Restoring network adapters..." "INFO"
    
    try {
        $disabled = Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Disabled" }
        $restored = 0
        
        foreach ($adapter in $disabled) {
            if ($PSCmdlet.ShouldProcess($adapter.Name, "Enable")) {
                Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
                $restored++
            }
        }
        
        if ($restored -gt 0) {
            Write-Step "Restore network adapters" "OK" "$restored adapter(s) enabled"
        }
        else {
            Write-Step "Restore network adapters" "SKIP" "None disabled"
        }
    }
    catch {
        Write-Step "Restore network adapters" "WARN" "Error: $_"
    }
}

function Restore-USBDevices {
    Write-ResetLog "Restoring USB devices..." "INFO"
    
    try {
        $statusesToRestore = @("Error", "Degraded", "Unknown")
        $maxPasses = 5
        $restoredIds = @{}

        for ($pass = 1; $pass -le $maxPasses; $pass++) {
            $blocked = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
                $_.InstanceId -match "^USB\\" -and $_.Status -in $statusesToRestore
            }

            if (-not $blocked -or $blocked.Count -eq 0) { break }

            foreach ($dev in $blocked) {
                $deviceLabel = if ($dev.FriendlyName) { $dev.FriendlyName } else { $dev.InstanceId }
                if ($PSCmdlet.ShouldProcess($deviceLabel, "Enable")) {
                    Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false -ErrorAction SilentlyContinue
                    $restoredIds[$dev.InstanceId] = $true
                }
            }

            # Composite/parent-child USB stacks can require additional passes.
            Start-Sleep -Milliseconds 1000
        }
        
        $remaining = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object {
            $_.InstanceId -match "^USB\\" -and $_.Status -in $statusesToRestore
        }

        $restored = $restoredIds.Keys.Count
        if ($restored -gt 0 -and $remaining.Count -eq 0) {
            Write-Step "Restore USB devices" "OK" "$restored device(s) enabled (multi-pass recovery complete)"
        }
        elseif ($restored -gt 0) {
            Write-Step "Restore USB devices" "WARN" "$restored device(s) enabled, $($remaining.Count) still not healthy after $maxPasses pass(es)"
        }
        else {
            Write-Step "Restore USB devices" "SKIP" "None blocked"
        }
    }
    catch {
        Write-Step "Restore USB devices" "WARN" "Error: $_"
    }
}

function Restore-AutoPlayPolicy {
    Write-ResetLog "Restoring AutoPlay policy..." "INFO"
    
    try {
        # Load backup if exists
        if (Test-Path $BackupFile) {
            $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json
            $originalValue = $backup.RegistryKeys.AutoPlay
            
            if ($null -ne $originalValue) {
                $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                if ($PSCmdlet.ShouldProcess("AutoPlay", "Restore")) {
                    Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value $originalValue -Force -ErrorAction Stop
                    Write-Step "Restore AutoPlay policy" "OK" "Value: $originalValue"
                }
            }
            else {
                # Remove if didn't exist before
                $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
                Remove-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Force -ErrorAction SilentlyContinue
                Write-Step "Restore AutoPlay policy" "OK" "Removed restriction"
            }
        }
        else {
            Write-Step "Restore AutoPlay policy" "SKIP" "No backup found"
        }
    }
    catch {
        Write-Step "Restore AutoPlay policy" "WARN" "Error: $_"
    }
}

function Restore-PowerSettings {
    Write-ResetLog "Restoring power settings..." "INFO"
    
    try {
        # Attempt to restore the original power plan from backup
        $originalPlanGuid = "381b4222-f694-41f0-9685-ff5bb260df2e"  # Balanced (fallback)
        $planSource = "Balanced (default)"
        if (Test-Path $BackupFile) {
            try {
                $backup = Get-Content $BackupFile -Raw | ConvertFrom-Json
                $planOutput = $backup.PowerPlan
                # powercfg /GETACTIVESCHEME output format: "Power Scheme GUID: <guid>  (<name>)"
                if ($planOutput -match "([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})") {
                    $originalPlanGuid = $Matches[1]
                    $planSource = "from backup"
                }
            }
            catch {}
        }

        if ($PSCmdlet.ShouldProcess("Power Plan", "Restore to $planSource ($originalPlanGuid)")) {
            & powercfg /SETACTIVE $originalPlanGuid 2>$null
            
            # Re-enable USB selective suspend (AutoLockdown disables it)
            & powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2beb146644c 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1 2>$null
            & powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2beb146644c 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 1 2>$null
            
            # Re-enable network adapter power management
            Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
                $adapterName = $_.Name
                try {
                    $powerMgmt = Get-NetAdapterPowerManagement -Name $adapterName -ErrorAction SilentlyContinue
                    if ($powerMgmt) {
                        Enable-NetAdapterPowerManagement -Name $adapterName -ErrorAction SilentlyContinue
                    }
                }
                catch {}
            }
            
            Write-Step "Restore power settings" "OK" "Plan: $planSource, USB suspend enabled, network power mgmt restored"
        }
    }
    catch {
        Write-Step "Restore power settings" "WARN" "Error: $_"
    }
}

function Remove-RegistryKeys {
    Write-ResetLog "Removing registry keys..." "INFO"
    
    try {
        $regPath = "HKLM:\SOFTWARE\AutoLockdown"
        if (Test-Path $regPath) {
            if ($PSCmdlet.ShouldProcess($regPath, "Remove")) {
                Remove-Item -Path $regPath -Recurse -Force -ErrorAction Stop
                Write-Step "Remove registry keys" "OK"
            }
        }
        else {
            Write-Step "Remove registry keys" "SKIP" "Not found"
        }
    }
    catch {
        Write-Step "Remove registry keys" "WARN" "Error: $_"
    }
}

function Remove-ConfigFiles {
    Write-ResetLog "Removing configuration files..." "INFO"
    
    if (-not (Test-Path $BasePath)) {
        Write-Step "Remove config files" "SKIP" "Directory not found"
        return
    }
    
    $filesToRemove = @(
        "AutoLockdown.ps1",
        "USB_Whitelist.json",
        "Network_Whitelist.json",
        "ThreatDB.json",
        "Trusted_HID.json",
        "Learning_State.json",
        "Deployment_Meta.json",
        "System_Backup.json",
        "ContainerAllowCache.json",
        "monitor.lock",
        "EMERGENCY_BYPASS"
    )
    
    # Keep whitelist if requested
    if ($KeepWhitelist) {
        $filesToRemove = $filesToRemove | Where-Object { $_ -notmatch "Whitelist" }
    }
    
    # Keep logs if requested
    if (-not $KeepLogs) {
        $filesToRemove += "Security.log"
        $filesToRemove += "Security.log.1"
        $filesToRemove += "Security.log.2"
        $filesToRemove += "Security.log.3"
        $filesToRemove += "Security.log.4"
        $filesToRemove += "Security.log.5"
    }
    
    $removed = 0
    foreach ($file in $filesToRemove) {
        $path = Join-Path $BasePath $file
        if (Test-Path $path) {
            if ($PSCmdlet.ShouldProcess($file, "Remove")) {
                Remove-Item $path -Force -ErrorAction SilentlyContinue
                $removed++
            }
        }
        
        # Also remove backup files
        foreach ($ext in @(".bak1", ".bak2", ".tmp")) {
            $bakPath = "$path$ext"
            if (Test-Path $bakPath) {
                Remove-Item $bakPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    
    Write-Step "Remove config files" "OK" "$removed file(s) removed"
}

function Remove-BaseDirectory {
    Write-ResetLog "Removing base directory..." "INFO"
    
    if (-not (Test-Path $BasePath)) {
        Write-Step "Remove directory" "SKIP" "Not found"
        return
    }
    
    # Check if directory is empty (except expected leftover files)
    $remaining = Get-ChildItem $BasePath -ErrorAction SilentlyContinue | Where-Object { 
        $_.Name -ne "Reset.log" -and 
        $_.Name -ne "PreReset_Snapshot.json" -and 
        $_.Name -notmatch "SecurityReport_.*\.txt"
    }
    
    if ($KeepLogs) {
        $remaining = $remaining | Where-Object { $_.Name -notmatch "\.log" }
    }
    
    if ($remaining.Count -eq 0 -or ($KeepLogs -and $remaining.Count -le 6)) {
        if (-not $KeepLogs) {
            # Preserve Reset.log to temp before deleting the directory
            $resetLogPath = Join-Path $BasePath "Reset.log"
            if (Test-Path $resetLogPath) {
                $tempResetLog = Join-Path $env:TEMP "AutoLockdown_Reset_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
                Copy-Item $resetLogPath $tempResetLog -Force -ErrorAction SilentlyContinue
                Write-Step "Preserve reset log" "OK" "Copied to $tempResetLog"
            }
            if ($PSCmdlet.ShouldProcess($BasePath, "Remove Directory")) {
                Remove-Item $BasePath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Step "Remove directory" "OK"
            }
        }
        else {
            Write-Step "Remove directory" "SKIP" "Keeping logs"
        }
    }
    else {
        Write-Step "Remove directory" "WARN" "Directory not empty ($($remaining.Count) items)"
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  RESET SUMMARY" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Steps completed: $script:Steps" -ForegroundColor White
    Write-Host "  Warnings: " -NoNewline
    Write-Host $script:Warnings -ForegroundColor $(if ($script:Warnings -gt 0) { "Yellow" } else { "Green" })
    Write-Host "  Errors: " -NoNewline
    Write-Host $script:Errors -ForegroundColor $(if ($script:Errors -gt 0) { "Red" } else { "Green" })
    Write-Host ""
    
    if ($script:Errors -eq 0) {
        Write-Host "  Status: " -NoNewline
        Write-Host "RESET COMPLETE" -ForegroundColor Green
        Write-Host ""
        Write-Host "  AutoLockdown has been removed from this system." -ForegroundColor White
        Write-Host "  A system reboot is recommended." -ForegroundColor Yellow
    }
    else {
        Write-Host "  Status: " -NoNewline
        Write-Host "RESET INCOMPLETE" -ForegroundColor Red
        Write-Host ""
        Write-Host "  Some components could not be removed." -ForegroundColor White
        Write-Host "  Check the reset log for details." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    
    # Footer
    $footerLine = "-" * 76
    Write-Host $footerLine -ForegroundColor DarkGray
    Write-Host "Reset by: $ScriptAuthor" -ForegroundColor DarkGray
    Write-Host "System Integrity: $(Get-SystemConfig -Key 'Hash')" -ForegroundColor DarkGray
    Write-Host $footerLine -ForegroundColor DarkGray
}

# ============================================================================
#   GUI CONFIRMATION DIALOG
# ============================================================================

function Show-ResetConfirmation {
    <#
    .SYNOPSIS
        Shows a GUI confirmation dialog before reset.
        Returns $true if user confirms, $false otherwise.
    #>
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "AutoLockdown - Confirm Reset"
    $form.Size = New-Object System.Drawing.Size(500, 380)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
    
    # Warning icon
    $lblIcon = New-Object System.Windows.Forms.Label
    $lblIcon.Location = New-Object System.Drawing.Point(20, 15)
    $lblIcon.Size = New-Object System.Drawing.Size(50, 50)
    $lblIcon.Text = "[!!]"
    $lblIcon.Font = New-Object System.Drawing.Font("Segoe UI", 28)
    $lblIcon.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 0)
    $form.Controls.Add($lblIcon)
    
    # Title
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(80, 20)
    $lblTitle.Size = New-Object System.Drawing.Size(380, 35)
    $lblTitle.Text = "Confirm System Reset"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($lblTitle)
    
    # Description
    $lblDesc = New-Object System.Windows.Forms.Label
    $lblDesc.Location = New-Object System.Drawing.Point(20, 70)
    $lblDesc.Size = New-Object System.Drawing.Size(450, 25)
    $lblDesc.Text = "This will remove all AutoLockdown components:"
    $lblDesc.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblDesc.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($lblDesc)
    
    # Items list
    $items = @(
        "  Stop monitor process",
        "  Remove WMI event subscription",
        "  Delete scheduled task",
        "  Restore disabled network adapters",
        "  Unblock USB devices",
        "  Restore AutoPlay and power settings",
        "  Remove registry keys",
        "  Delete configuration files"
    )
    
    $yPos = 100
    foreach ($item in $items) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = New-Object System.Drawing.Point(30, $yPos)
        $lbl.Size = New-Object System.Drawing.Size(420, 22)
        $lbl.Text = $item
        $lbl.Font = New-Object System.Drawing.Font("Consolas", 9)
        $lbl.ForeColor = [System.Drawing.Color]::FromArgb(200, 200, 220)
        $form.Controls.Add($lbl)
        $yPos += 24
    }
    
    # Warning
    $lblWarn = New-Object System.Windows.Forms.Label
    $lblWarn.Location = New-Object System.Drawing.Point(20, 275)
    $lblWarn.Size = New-Object System.Drawing.Size(450, 25)
    $lblWarn.Text = "A reboot will be recommended after reset."
    $lblWarn.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Italic)
    $lblWarn.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 0)
    $form.Controls.Add($lblWarn)
    
    # Buttons
    $btnYes = New-Object System.Windows.Forms.Button
    $btnYes.Location = New-Object System.Drawing.Point(130, 305)
    $btnYes.Size = New-Object System.Drawing.Size(100, 35)
    $btnYes.Text = "Reset"
    $btnYes.DialogResult = "Yes"
    $btnYes.BackColor = [System.Drawing.Color]::FromArgb(180, 60, 60)
    $btnYes.ForeColor = [System.Drawing.Color]::White
    $btnYes.FlatStyle = "Flat"
    $btnYes.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $form.Controls.Add($btnYes)
    
    $btnNo = New-Object System.Windows.Forms.Button
    $btnNo.Location = New-Object System.Drawing.Point(260, 305)
    $btnNo.Size = New-Object System.Drawing.Size(100, 35)
    $btnNo.Text = "Cancel"
    $btnNo.DialogResult = "No"
    $btnNo.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $btnNo.ForeColor = [System.Drawing.Color]::White
    $btnNo.FlatStyle = "Flat"
    $btnNo.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($btnNo)
    
    $form.AcceptButton = $btnNo  # Default to Cancel for safety
    
    $result = $form.ShowDialog()
    $form.Dispose()
    
    return ($result -eq "Yes")
}

function Show-ResetSummaryGUI {
    <#
    .SYNOPSIS
        Shows reset results in a GUI dialog.
    #>
    
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "AutoLockdown - Reset Complete"
    $form.Size = New-Object System.Drawing.Size(450, 280)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(30, 30, 40)
    
    $success = ($script:Errors -eq 0)
    
    # Icon
    $lblIcon = New-Object System.Windows.Forms.Label
    $lblIcon.Location = New-Object System.Drawing.Point(20, 20)
    $lblIcon.Size = New-Object System.Drawing.Size(50, 50)
    $lblIcon.Text = if ($success) { "[OK]" } else { "[!!]" }
    $lblIcon.Font = New-Object System.Drawing.Font("Segoe UI", 28)
    $form.Controls.Add($lblIcon)
    
    # Title
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(80, 25)
    $lblTitle.Size = New-Object System.Drawing.Size(320, 30)
    $lblTitle.Text = if ($success) { "Reset Complete" } else { "Reset Incomplete" }
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = if ($success) { [System.Drawing.Color]::FromArgb(50, 205, 50) } else { [System.Drawing.Color]::FromArgb(255, 180, 0) }
    $form.Controls.Add($lblTitle)
    
    # Stats
    $lblStats = New-Object System.Windows.Forms.Label
    $lblStats.Location = New-Object System.Drawing.Point(20, 90)
    $lblStats.Size = New-Object System.Drawing.Size(400, 80)
    $lblStats.Text = "Steps completed: $($script:Steps)`nWarnings: $($script:Warnings)`nErrors: $($script:Errors)`n`n$(if ($success) { 'A system reboot is recommended.' } else { 'Check reset log for details.' })"
    $lblStats.Font = New-Object System.Drawing.Font("Segoe UI", 11)
    $lblStats.ForeColor = [System.Drawing.Color]::White
    $form.Controls.Add($lblStats)
    
    # Close button
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Location = New-Object System.Drawing.Point(165, 190)
    $btnClose.Size = New-Object System.Drawing.Size(110, 35)
    $btnClose.Text = "OK"
    $btnClose.DialogResult = "OK"
    $btnClose.BackColor = [System.Drawing.Color]::FromArgb(60, 60, 80)
    $btnClose.ForeColor = [System.Drawing.Color]::White
    $btnClose.FlatStyle = "Flat"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($btnClose)
    
    $form.ShowDialog() | Out-Null
    $form.Dispose()
}

# ============================================================================
#   MAIN EXECUTION
# ============================================================================

Clear-Host
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host "  $ProductName v$ScriptVersion - SYSTEM RESET" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Author: $ScriptAuthor" -ForegroundColor White
Write-Host "  Timestamp: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host ""
Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host ""

# Confirmation
if (-not $Force) {
    if ($Interactive) {
        # Use GUI confirmation
        $confirmed = Show-ResetConfirmation
        if (-not $confirmed) {
            Write-Host "  Reset cancelled by user." -ForegroundColor Yellow
            exit 0
        }
    }
    else {
        # Console confirmation
        Write-Host "  WARNING: This will remove AutoLockdown and restore system defaults." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Options:" -ForegroundColor White
        Write-Host "    -KeepLogs       Preserve log files" -ForegroundColor Gray
        Write-Host "    -KeepWhitelist  Preserve whitelist (for reinstall)" -ForegroundColor Gray
        Write-Host "    -Force          Skip confirmation" -ForegroundColor Gray
        Write-Host "    -Interactive    Show GUI dialogs" -ForegroundColor Gray
        Write-Host ""
        
        $confirm = Read-Host "  Type 'RESET' to confirm"
        if ($confirm -ne "RESET") {
            Write-Host ""
            Write-Host "  Reset cancelled." -ForegroundColor Yellow
            exit 0
        }
        Write-Host ""
    }
}

Write-Host "  Starting reset process..." -ForegroundColor Cyan
Write-Host ""

# Create reset log
if (-not (Test-Path $BasePath)) {
    New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
}
"" | Out-File $ResetLog -Force
Write-ResetLog "Reset started" "INFO"

# Execute reset steps
Backup-PreResetState
Stop-MonitorProcess
Remove-WMISubscription
Remove-ScheduledTask
Restore-NetworkAdapters
Restore-USBDevices
Restore-AutoPlayPolicy
Restore-PowerSettings
Remove-RegistryKeys
Remove-ConfigFiles
Remove-BaseDirectory

# Post-reset verification
Write-Host ""
Write-Host "  Verifying reset..." -ForegroundColor Cyan
$verifyIssues = 0
if (Get-ScheduledTask -TaskName "AutoLockdown_Service" -ErrorAction SilentlyContinue) {
    Write-Step "Verify: Scheduled task" "FAIL" "Still exists"
    $verifyIssues++
}
else {
    Write-Step "Verify: Scheduled task" "OK" "Removed"
}
if (Test-Path $LockFile) {
    Write-Step "Verify: Lock file" "FAIL" "Still exists"
    $verifyIssues++
}
else {
    Write-Step "Verify: Lock file" "OK" "Removed"
}
if (Test-Path "HKLM:\SOFTWARE\AutoLockdown") {
    Write-Step "Verify: Registry" "FAIL" "Still exists"
    $verifyIssues++
}
else {
    Write-Step "Verify: Registry" "OK" "Removed"
}
if ($verifyIssues -gt 0) {
    Write-ResetLog "Post-reset verification: $verifyIssues issue(s) found" "WARNING"
}
else {
    Write-ResetLog "Post-reset verification: All clean" "SUCCESS"
}

# Show summary
Show-Summary

# Show GUI summary if interactive
if ($Interactive) {
    Show-ResetSummaryGUI
}

# Exit code
if ($script:Errors -gt 0) {
    exit 1
}
else {
    exit 0
}

