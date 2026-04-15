<#
.SYNOPSIS
    AutoLockdown v4.9.0 - Enterprise USB Security Hardening Suite
.DESCRIPTION
    Production-grade USB security enforcement with intelligent learning mode,
    threat detection, and comprehensive monitoring capabilities.
    
    LEARNING MODE: Whitelist legitimate USB devices automatically
    ENFORCEMENT MODE: Block all unauthorized USB devices
    HID PROTECTION: Always allow trusted keyboards/mice by vendor ID
    THREAT DETECTION: Block known attack devices (Rubber Ducky, Bash Bunny, etc.)
    FAST-PATH BLOCKING: Registry watcher blocks unknown devices before driver install
    
.NOTES
    File Name : AutoLockdown.ps1
    Version   : 4.9.1
    Author    : Meet Gandhi (Product Security Engineer)
    Created   : April 2026
    Requires  : PowerShell 5.1+, Administrator privileges
    
    Changelog v4.9.1:
    - Fixed Update-LearningMode unsafe finally block: if WaitOne timed out, calling
      ReleaseMutex on an unowned mutex threw System.ApplicationException, which could
      crash the monitor service. Changed to safe try/catch/finally pattern matching
      all other mutex sites in the codebase.
    - Fixed WMI event handler writing USB whitelist in UTF-16LE (Out-File default)
      instead of UTF-8. After the WMI handler learned a device, all subsequent
      whitelist reads (fast-path watcher, Protect-USBDevice, WMI handler itself)
      would fail because they specify -Encoding UTF8, causing every whitelisted
      device to be blocked in enforcement mode. Added -Encoding UTF8.

    Changelog v4.9.0:
    - Changed default learning window from 180 minutes to 5 minutes for faster deployment.
    - Fixed "Finish Early" button bug: clicking Finish Early during learning countdown now
      immediately transitions learning state to "Enforced", preventing the system from
      remaining in learning mode after the timer window closes.
    - Fixed Protect-USBDevice threat lookup null-reference when ThreatMap is a
      PSCustomObject and the VID/PID key does not exist (added null guard).
    - Fixed Reset_Lockdown.ps1 using raw ConvertFrom-Json on System_Backup.json without
      try/catch protection (wrapped in safe error handling).
    - Fixed Verify_Lockdown.ps1 Test-ThreatDatabase using raw ConvertFrom-Json outside
      Import-JsonSafe (wrapped in try/catch).

    Changelog v4.8.0:
    - Fixed boot-time blocking of JAC dongle modems by evaluating ContainerId during startup scan.
    - Mitigated JSON file corruption race condition by introducing Mutex locking and fallback .bak1/.bak2 save routines for ContainerAllowCache.json.
    - Implemented container-based allow for JAC 5G dongle (VID_322B) mode-switching:
      after the dongle's mass-storage identity is trusted, its DEVPKEY_Device_ContainerId
      (a Windows-assigned GUID grouping all devnodes of the same physical USB device) is
      recorded in a persistent allow cache (ContainerAllowCache.json, 24-hour TTL).
      Any subsequent devnode sharing that ContainerId (composite device, RNDIS/MBIM modem
      interface, CDC serial, etc.) is automatically allowed without needing to pre-know
      the modem-mode VID/PID.
    - Cache is shared across fast-path registry watcher, WMI handler, and Protect-USBDevice
      via the persisted JSON file; in-memory copy maintained in the watcher runspace for
      zero-latency lookups.

    Changelog v4.7.1:
    - Fixed fast-path registry watcher blocking USB hubs (Class="USB"/"HUBClass"):
      disabling a hub cut off every device on that hub, bricking all downstream ports
    - Fixed fast-path HID class-check timing race: Windows may not yet have written
      the "Class" registry value when the 250 ms watcher first sees a new device;
      watcher now retries up to 5 x 100 ms before the allow/block decision and
      allows any non-Apple trusted HID vendor whose class is still pending, preventing
      keyboards (VID_0461, VID_0D62, etc.) from being incorrectly blocked
    - Expanded HID_REGISTRY_CLASSES to include "Bluetooth" so trusted Bluetooth
      vendors (VID_8087 Intel, VID_0A5C Broadcom, VID_0A12 CSR) in the HID vendor
      list are allowed rather than blocked

    Changelog v4.7.0:
    - Added fast-path registry watcher runspace (250 ms polling) that detects and
      blocks unauthorized USB devices the instant the OS writes their registry entry,
      BEFORE any device driver is loaded  -  solves the 40-second blocking delay on
      iOS, Android, and USBSTOR devices observed on the Intel NUC Win11 deployment
    - Reduced WMI polling interval from WITHIN 2 to WITHIN 1 (secondary catch-all)
    - WMI handler now skips devices already disabled by the fast-path watcher
    - Added Start-RegistryWatcher function and $script:RegWatcher state variable
    - Registry watcher HID check now reads both Class and ClassGUID registry values;
      ClassGUID allow-list covers keyboard ({4D36E96B}), mouse ({4D36E96F}), and HID
      ({745A17A0}) so trusted peripherals are allowed even before the human-readable
      Class string is written (avoids transient block of legit keyboards/mice on first
      plug-in, including those on USB-C controllers/hubs)
    - Fast-path now defers (re-queues for next 250 ms poll) instead of blocking when a
      trusted HID vendor device has no Class or ClassGUID yet; WMI handler serves as
      secondary catch-all  -  Apple iPhones (VID_05AC, class Image/WPD) are still
      correctly blocked once their non-HID class is written
    - Allow/deny logic is class/interface/vendor-based throughout; physical connector
      type (USB-A vs USB-C) has no effect on policy decisions
    - Watcher runspace is fully cleaned up on monitor exit

    Changelog v4.6.0:
    - Fixed screen/sleep timeout overriding LogMeIn "Never" setting
    - Fixed WMI event handler failing to read DPAPI-encrypted whitelists
    - Fixed hardcoded always-allowed VIDs in WMI handler (now from single source)
    - Fixed emergency bypass being non-functional during enforcement
    - Fixed double-counting in block/allow metrics
    - Fixed misnumbered initialization steps and removed redundant whitelist creation
    - Fixed Set-LearningState writing unencrypted (now consistent with init)
    - Removed duplicate Test-TrustedHIDVendor and $HIDVendorsFile declarations
    - Optimized startup scan by skipping device-class wait for already-enumerated devices
    - GUI assemblies now lazy-loaded (skipped in -Monitor mode)
    - Added null guard on dashboard mode display
    - Removed undefined $InitialConfig reference
    
    Changelog v4.5.0:
    - Fixed 42 critical bugs including race conditions, memory leaks
    - Added timezone-safe learning windows
    - Implemented USB event batching and deduplication
    - Added 3-level JSON backup with corruption recovery
    - Disk space monitoring and safe mode detection
    - Improved HID device handling (port-change support)
    - Health check endpoint and watchdog integration
    - Enhanced logging with rotation and compression
    
.EXAMPLE
    .\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 5
    
    Initializes system with 5-minute learning window (default)
.EXAMPLE
    .\AutoLockdown.ps1 -Monitor
    
    Starts real-time USB monitoring service
.EXAMPLE
    .\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 60 -WhatIf
    
    Shows what would happen without making changes
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Initialize,
    [switch]$Monitor,
    [switch]$ExtendLearning,
    [switch]$AddDevice,
    [string]$DeviceVidPid,
    [string]$DeviceName = "Manually Added",
    [switch]$ShowStatus,
    [switch]$Silent,
    [int]$LearningWindowMinutes = 5,
    [int]$RebootDelaySeconds = 60,
    [switch]$EnableWatchdog,
    [switch]$EnableHealthCheck,
    [int]$HealthCheckPort = 8765,
    [int]$ExtendMinutes = 60
)

# ============================================================================
#   CONSTANTS & CONFIGURATION
# ============================================================================

Add-Type -AssemblyName System.Security
if (-not $Monitor) {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing
}

# Encryption Scope (LocalMachine allows authorized admins/SYSTEM to decrypt)
$DPAPI_SCOPE = [System.Security.Cryptography.DataProtectionScope]::LocalMachine

$ScriptVersion = "4.9.1"
$ProductName = "AutoLockdown"


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
$BackupFile = Join-Path $BasePath "System_Backup.json"
$LockFile = Join-Path $BasePath "monitor.lock"
$MetaFile = Join-Path $BasePath "Deployment_Meta.json"
$LearningFile = Join-Path $BasePath "Learning_State.json"
$DeployedScript = Join-Path $BasePath "AutoLockdown.ps1"
$HIDVendorsFile = Join-Path $BasePath "Trusted_HID.json"
$EmergencyBypassFile = Join-Path $BasePath "EMERGENCY_BYPASS"
$ContainerAllowCacheFile = Join-Path $BasePath "ContainerAllowCache.json"

# Configuration
$MaxLogSizeMB = 50
$MaxLogFiles = 5
$MaxWhitelistDevices = 100
$MutexTimeout = 30000
$MinDiskSpaceMB = 10
$CONTAINER_ALLOW_TTL_HOURS = 24
# GUID validation pattern shared by all enforcement paths
$CONTAINER_ID_GUID_PATTERN = '^\{[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\}$'

# Script state
$script:StartTime = Get-Date
$script:Whitelist = @()
$script:ThreatMap = @{}
$script:HIDVendors = @()
$script:ReadOnlyMode = $false
$script:SafeMode = $false
$script:RegWatcher = $null
$script:Metrics = @{
    TotalBlocks     = 0
    TotalLearned    = 0
    TotalAllowed    = 0
    ThreatsDetected = 0
    StartupTime     = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
}

# ============================================================================
#   TRUSTED HID VENDORS (Keyboards, Mice, Game Controllers)
# ============================================================================

$TRUSTED_HID_VENDORS = @(
    "VID_046D",  # Logitech
    "VID_045E",  # Microsoft
    "VID_1532",  # Razer
    "VID_05AC",  # Apple
    "VID_1038",  # SteelSeries
    "VID_1B1C",  # Corsair
    "VID_046A",  # Cherry
    "VID_24F0",  # Zowie (BenQ)
    "VID_258A",  # Bloody Gaming
    "VID_04D9",  # Holtek Semiconductor
    "VID_413C",  # Dell
    "VID_047C",  # 4Tech
    "VID_03F0",  # HP
    "VID_17E9",  # DisplayLink
    "VID_0B05",  # ASUS
    "VID_1D27",  # Xenta
    "VID_0486",  # ASUS Wireless
    "VID_2821",  # ASRock
    "VID_17AA",  # Lenovo
    "VID_04B3",  # IBM
    "VID_0502",  # Acer
    "VID_04A5",  # Acer Peripherals
    "VID_5986",  # Acer Crystal Eye Webcam
    "VID_0738",  # Mad Catz
    "VID_0DB0",  # Micro Star (MSI)
    "VID_1462",  # MSI
    "VID_0E8F",  # GreenAsia
    "VID_1019",  # Elitegroup
    "VID_0955",  # NVIDIA
    "VID_1043",  # ASUS
    "VID_04F2",  # Chicony Electronics
    "VID_0D62",  # Darfon Electronics
    "VID_093A",  # Pixart Imaging
    "VID_062A",  # MosArt Semiconductor
    "VID_04F3",  # Elan Microelectronics
    "VID_0461",  # Primax Electronics
    "VID_0E6A",  # Megawin
    "VID_1BCF",  # Sunplus Innovation
    "VID_0603",  # Novatek
    "VID_1A2C",  # China Resource Semico
    "VID_27C6",  # Shenzhen Goodix
    "VID_0B57",  # Beijing Zhongyuanhuadian
    "VID_04CA",  # Lite-On Technology
    "VID_1EA7",  # SHARKOON Technologies
    "VID_0C45",  # Microdia
    "VID_3938",  # MOSART Semi.
    "VID_28BD",  # XP-PEN
    "VID_256C",  # Huion
    "VID_056A",  # Wacom
    "VID_0EB7",  # Endor AG (Fanatec)
    "VID_044F",  # ThrustMaster
    "VID_0D8C",  # C-Media Electronics
    "VID_1A34",  # ACRUX
    "VID_09DA",  # A4Tech
    "VID_1C4F",  # SiGma Micro
    "VID_0458",  # KYE Systems (Genius)
    "VID_05FE",  # Chic Technology
    "VID_1A81",  # Holtek Semiconductor
    "VID_2717",  # Xiaomi
    "VID_0C76",  # JMTek
    "VID_18D1",  # Google
    "VID_2886",  # Seeed Technology
    "VID_04B4",  # Cypress Semiconductor
    "VID_2149",  # Advanced Silicon
    "VID_1044",  # Chu Yuen
    "VID_1A7C",  # Evoluent
    "VID_0B33",  # Contour Design
    "VID_1B47",  # CoolerMaster
    "VID_056E",  # Elecom
    "VID_04D8",  # Microchip
    "VID_10C4",  # Silicon Labs
    "VID_0557",  # ATEN International
    "VID_0424",  # Standard Microsystems
    "VID_2516",  # Cooler Master
    "VID_0411",  # BUFFALO
    "VID_0789",  # Logitec
    "VID_046E",  # Behavior Tech
    "VID_1C0D",  # Siig
    "VID_1267",  # Logic Controls
    "VID_0566",  # PixArt
    "VID_0A5C",  # Broadcom (Bluetooth)
    "VID_0A12",  # Cambridge Silicon Radio
    "VID_8087",  # Intel (Bluetooth)
    "VID_04E8",  # Samsung
    "VID_054C",  # Sony
    "VID_0930",  # Toshiba
    "VID_0409",  # NEC
    "VID_0483",  # STMicroelectronics
    "VID_10D5",  # Uni Class Technology
    "VID_04FC",  # Sunplus
    "VID_1B96",  # N-Trig (Surface Pen)
    "VID_222A",  # IGM
    "VID_0416",  # Winbond Electronics
    "VID_1C4A",  # Enesys
    "VID_0764",  # Cyber Power System
    "VID_1B80",  # Afatech
    "VID_1D57",  # Xenta (UK)
    "VID_15D9",  # Trust International
    "VID_1050",  # Yubico (YubiKey)
    "VID_20A0",  # Clay Logic
    "VID_FEED",  # QMK/VIA Custom Keyboards
    "VID_C1ED",  # ZSA Technology Labs
    "VID_3297"   # ZSA Moonlander
)

# ============================================================================
#   ALWAYS ALLOWED USB VENDORS (Critical Infrastructure)
#   These devices bypass blocking - always allowed regardless of mode
# ============================================================================

$ALWAYS_ALLOWED_USB_VENDORS = @(
    "VID_0403",  # FTDI (Future Technology Devices International) - Relay Antenna / Serial Converters
    "VID_322B"   # JAC (Shanghai JAC) - 5G Cellular USB Dongle
)

# ============================================================================
#   THREAT DATABASE (Known Attack Devices)
# ============================================================================

$THREAT_DATABASE = @{
    "VID_03EB&PID_2403" = @{ Name = "USB Rubber Ducky"; Threat = "HID Injection"; Severity = "CRITICAL" }
    "VID_16D0&PID_0A8B" = @{ Name = "Rubber Ducky Clone"; Threat = "Keystroke Injection"; Severity = "CRITICAL" }
    "VID_04D8&PID_F5F5" = @{ Name = "Bash Bunny"; Threat = "Multi-Attack Platform"; Severity = "CRITICAL" }
    "VID_1209&PID_5BF1" = @{ Name = "O.MG Cable"; Threat = "Implant Device"; Severity = "CRITICAL" }
    "VID_1209&PID_2302" = @{ Name = "P4wnP1 ALOA"; Threat = "Attack Platform"; Severity = "CRITICAL" }
    "VID_16C0&PID_0483" = @{ Name = "Teensy"; Threat = "Programmable HID"; Severity = "HIGH" }
    "VID_16C0&PID_05DF" = @{ Name = "DigiSpark"; Threat = "Scriptable HID"; Severity = "HIGH" }
    "VID_03EB&PID_2067" = @{ Name = "Arduino Leonardo"; Threat = "HID Emulation"; Severity = "HIGH" }
    "VID_2341&PID_8036" = @{ Name = "Arduino Micro"; Threat = "HID Emulation"; Severity = "HIGH" }
    "VID_2341&PID_8037" = @{ Name = "Arduino Micro Alt"; Threat = "HID Emulation"; Severity = "HIGH" }
    "VID_1B4F&PID_9206" = @{ Name = "USB Armory"; Threat = "Pentesting Tool"; Severity = "HIGH" }
    "VID_258A&PID_0001" = @{ Name = "BadUSB Emulator"; Threat = "Command Injection"; Severity = "CRITICAL" }
    "VID_FFFF&PID_FFFF" = @{ Name = "Spoofed Device"; Threat = "ID Spoofing"; Severity = "CRITICAL" }
    "VID_1209&PID_C101" = @{ Name = "Generic HID Attack"; Threat = "Custom Payload"; Severity = "HIGH" }
    "VID_0525&PID_A4A7" = @{ Name = "Linux USB Gadget"; Threat = "Network Emulation"; Severity = "HIGH" }
    "VID_04E8&PID_685D" = @{ Name = "Samsung Knox Bypass"; Threat = "Mobile Exploit"; Severity = "MEDIUM" }
}

# ============================================================================
#   HID VENDOR VERIFICATION (Port-Change Detection Fix)
# ============================================================================

function Test-TrustedHIDVendor {
    <#
    .SYNOPSIS
        Checks if device VID matches a trusted HID vendor.
        Fixes port-change detection issue for keyboards/mice.
    #>
    param([string]$InstanceId)
    
    if (-not $InstanceId) { return $false }
    
    $idUpper = $InstanceId.ToUpper()
    
    # Check against loaded HID vendors or fallback to global list
    $vendors = if ($script:HIDVendors.Count -gt 0) { $script:HIDVendors } else { $TRUSTED_HID_VENDORS }
    
    foreach ($vendor in $vendors) {
        if ($idUpper -like "*$vendor*") {
            return $true
        }
    }
    return $false
}

function Test-AlwaysAllowedUSB {
    <#
    .SYNOPSIS
        Checks if device VID matches an always-allowed infrastructure vendor.
        These devices bypass blocking regardless of mode (e.g., FTDI relay, JAC 5G dongle).
    #>
    param([string]$InstanceId)
    
    if (-not $InstanceId) { return $false }
    
    $idUpper = $InstanceId.ToUpper()
    
    foreach ($vendor in $ALWAYS_ALLOWED_USB_VENDORS) {
        if ($idUpper -like "*$vendor*") {
            return $true
        }
    }
    return $false
}

# ============================================================================
#   CORE UTILITY FUNCTIONS
# ============================================================================

function Test-SafeMode {
    try {
        $safeMode = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\Option" -ErrorAction SilentlyContinue).OptionValue
        if ($safeMode -eq 1) { return "Safe Mode" }
        elseif ($safeMode -eq 2) { return "Safe Mode with Networking" }
        return $null
    }
    catch { return $null }
}

function Test-DiskSpace {
    param([string]$Path = $BasePath, [int]$RequiredMB = $MinDiskSpaceMB)
    try {
        $drive = (Get-Item $Path -ErrorAction Stop).PSDrive
        if ($drive.Free -lt ($RequiredMB * 1MB)) {
            Write-LogMessage "CRITICAL: Low disk space on $($drive.Name):" -Level "ERROR"
            return $false
        }
        return $true
    }
    catch { return $true }
}

function Test-PathSafe {
    param([string]$Path)
    if (Test-Path $Path) {
        try {
            $item = Get-Item $Path -Force -ErrorAction Stop
            if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                Write-LogMessage "SECURITY: Path $Path is a symlink - BLOCKED" -Level "ERROR"
                return $false
            }
            $fullPath = $item.FullName.ToLower()
            if ($fullPath.StartsWith("c:\windows") -or $fullPath.StartsWith($env:windir.ToLower())) {
                return $false
            }
        }
        catch { return $false }
    }
    return $true
}

function Get-MonotonicTimestamp { return [Environment]::TickCount64 }

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SUCCESS", "WARNING", "ERROR", "BLOCK", "LEARNED", "DEBUG")]
        [string]$Level = "INFO"
    )
    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $line = "[$timestamp] [$Level] $Message"
        
        if (-not (Test-Path $BasePath)) {
            New-Item -Path $BasePath -ItemType Directory -Force | Out-Null
        }
        
        if (-not $script:ReadOnlyMode -and -not (Test-DiskSpace)) {
            $script:ReadOnlyMode = $true
            return
        }
        
        if (Test-Path $LogFile) {
            $logSize = (Get-Item $LogFile).Length / 1MB
            if ($logSize -gt $MaxLogSizeMB) {
                for ($i = $MaxLogFiles; $i -ge 1; $i--) {
                    $oldLog = "$LogFile.$i"
                    $newLog = "$LogFile.$($i + 1)"
                    if (Test-Path $oldLog) {
                        if ($i -eq $MaxLogFiles) { Remove-Item $oldLog -Force -ErrorAction SilentlyContinue }
                        else { Move-Item $oldLog $newLog -Force -ErrorAction SilentlyContinue }
                    }
                }
                if (Test-Path $LogFile) { Move-Item $LogFile "$LogFile.1" -Force -ErrorAction SilentlyContinue }
            }
        }
        
        Add-Content -Path $LogFile -Value $line -Force -ErrorAction Stop
        

        
        if (-not $Monitor -and -not $Silent) {
            $color = switch ($Level) {
                "BLOCK" { "Red" }
                "ERROR" { "Red" }
                "WARNING" { "Yellow" }
                "SUCCESS" { "Green" }
                "LEARNED" { "Cyan" }
                default { "White" }
            }
            Write-Host $line -ForegroundColor $color
        }
    }
    catch {
        Write-EventLog -LogName Application -Source "AutoLockdown" -EntryType Error -EventId 1001 -Message "LOG FAILURE: $Message" -ErrorAction SilentlyContinue
    }
}

function Protect-Data {
    param([string]$Plaintext)
    try {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
        $encrypted = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $null, $DPAPI_SCOPE)
        return [Convert]::ToBase64String($encrypted)
    }
    catch {
        Write-LogMessage "Encryption failed: $_" -Level "ERROR"
        return $null
    }
}

function Unprotect-Data {
    param([string]$Ciphertext)
    try {
        $bytes = [Convert]::FromBase64String($Ciphertext)
        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, $DPAPI_SCOPE)
        return [System.Text.Encoding]::UTF8.GetString($decrypted)
    }
    catch {
        Write-LogMessage "Decryption failed: $_" -Level "ERROR"
        return $null
    }
}

function Export-JsonSafe {
    param([object]$Data, [string]$Path, [switch]$Encrypt)
    if ($script:ReadOnlyMode) { return $false }
    
    # Create backup with rotation (keep 3 levels)
    if (Test-Path $Path) {
        if (Test-Path "$Path.bak2") { Remove-Item "$Path.bak2" -Force -ErrorAction SilentlyContinue }
        if (Test-Path "$Path.bak1") { Move-Item "$Path.bak1" "$Path.bak2" -Force -ErrorAction SilentlyContinue }
        Copy-Item $Path "$Path.bak1" -Force -ErrorAction SilentlyContinue
    }
    
    try {
        $json = $Data | ConvertTo-Json -Depth 10 -Compress
        
        if ($Encrypt) {
            $content = Protect-Data -Plaintext $json
            if (-not $content) { throw "Encryption returned null" }
        }
        else {
            $content = $json
        }
        
        $content | Out-File $Path -Encoding UTF8 -Force
        return $true
    }
    catch {
        Write-LogMessage "Failed to save JSON to $Path : $_" -Level "ERROR"
        return $false
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
                        Write-LogMessage "Warning: Loading unencrypted file as encrypted source: $file" -Level "WARNING"
                    }
                    else {
                        $decrypted = Unprotect-Data -Ciphertext $content
                        if (-not $decrypted) { continue }
                        $content = $decrypted
                    }
                }
                
                $data = $content | ConvertFrom-Json
                if ($file -ne $Path) { Write-LogMessage "Loaded $Path from backup $file" -Level "WARNING" }
                return $data
            }
            catch { continue }
        }
    }
    return $null
}

function Show-TimerForm {
    <#
    .SYNOPSIS
        Displays a blocking GUI timer with progress bar
    #>
    param(
        [string]$Title,
        [string]$Message,
        [int]$Seconds,
        [string]$CompleteMessage = "Completed",
        [switch]$AllowCancel,
        [string]$CancelButtonText = "Finish Early",
        [switch]$AllowExtend,
        [int]$ExtendMinutes = 5,
        [switch]$AllowImmediate,
        [string]$ImmediateText = "Do It Now"
    )
    
    # Form Setup
    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title
    $form.Size = New-Object System.Drawing.Size(480, 250)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    
    # Message Label
    $label = New-Object System.Windows.Forms.Label
    $label.Location = New-Object System.Drawing.Point(20, 15)
    $label.Size = New-Object System.Drawing.Size(430, 55)
    $label.Text = $Message
    $label.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($label)
    
    # Time Label
    $timeLabel = New-Object System.Windows.Forms.Label
    $timeLabel.Location = New-Object System.Drawing.Point(20, 75)
    $timeLabel.Size = New-Object System.Drawing.Size(430, 30)
    $timeLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $timeLabel.ForeColor = [System.Drawing.Color]::DarkBlue
    $form.Controls.Add($timeLabel)
    
    # Progress Bar
    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = New-Object System.Drawing.Point(20, 110)
    $progressBar.Size = New-Object System.Drawing.Size(420, 25)
    $progressBar.Maximum = $Seconds
    $progressBar.Value = 0
    $progressBar.Style = "Continuous"
    $form.Controls.Add($progressBar)
    
    # Button positions (centered row)
    $buttonY = 150
    $buttonSpacing = 10
    $buttons = @()
    
    # Cancel Button (left)
    if ($AllowCancel) {
        $btnCancel = New-Object System.Windows.Forms.Button
        $btnCancel.Size = New-Object System.Drawing.Size(130, 35)
        $btnCancel.Text = $CancelButtonText
        $btnCancel.DialogResult = "Cancel"
        $btnCancel.BackColor = [System.Drawing.Color]::LightGray
        $buttons += $btnCancel
    }
    
    # Extend Button (+5 Min) - center
    if ($AllowExtend) {
        $btnExtend = New-Object System.Windows.Forms.Button
        $btnExtend.Size = New-Object System.Drawing.Size(130, 35)
        $btnExtend.Text = "+$ExtendMinutes Minutes"
        $btnExtend.BackColor = [System.Drawing.Color]::LightGreen
        $btnExtend.Tag = @{ Form = $form; ExtendSeconds = $ExtendMinutes * 60; ProgressBar = $progressBar }
        $btnExtend.Add_Click({
                $state = $this.Tag.Form.Tag
                $state.Remaining += $this.Tag.ExtendSeconds
                $state.TotalSeconds += $this.Tag.ExtendSeconds
                $this.Tag.ProgressBar.Maximum = $state.TotalSeconds
            })
        $buttons += $btnExtend
    }
    
    # Immediate Action Button (right)
    if ($AllowImmediate) {
        $btnImmediate = New-Object System.Windows.Forms.Button
        $btnImmediate.Size = New-Object System.Drawing.Size(130, 35)
        $btnImmediate.Text = $ImmediateText
        $btnImmediate.BackColor = [System.Drawing.Color]::LightCoral
        $btnImmediate.DialogResult = "Yes"
        $buttons += $btnImmediate
    }
    
    # Position buttons centered
    $totalWidth = ($buttons.Count * 130) + (($buttons.Count - 1) * $buttonSpacing)
    $startX = (460 - $totalWidth) / 2
    for ($i = 0; $i -lt $buttons.Count; $i++) {
        $buttons[$i].Location = New-Object System.Drawing.Point(($startX + ($i * (130 + $buttonSpacing))), $buttonY)
        $form.Controls.Add($buttons[$i])
    }
    
    # Store state in Form.Tag
    $form.Tag = @{
        Remaining       = $Seconds
        TotalSeconds    = $Seconds
        TimeLabel       = $timeLabel
        ProgressBar     = $progressBar
        Label           = $label
        CompleteMessage = $CompleteMessage
    }
    
    # Set initial display
    $ts = [TimeSpan]::FromSeconds($Seconds)
    $timeLabel.Text = "Time Remaining: $($ts.ToString('hh\:mm\:ss'))"
    
    # Timer Logic
    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = 1000
    
    $timer.Add_Tick({
            $state = $this.Tag.Form.Tag
            $state.Remaining--
        
            $elapsed = $state.TotalSeconds - $state.Remaining
            # Clamp value to valid range to prevent ArgumentOutOfRangeException after extend
            $clampedElapsed = [Math]::Max(0, [Math]::Min($elapsed, $state.ProgressBar.Maximum))
            $state.ProgressBar.Value = $clampedElapsed
        
            $ts = [TimeSpan]::FromSeconds([Math]::Max(0, $state.Remaining))
            $state.TimeLabel.Text = "Time Remaining: $($ts.ToString('hh\:mm\:ss'))"
        
            if ($state.Remaining -le 0) {
                $this.Stop()
                $state.Label.Text = $state.CompleteMessage
                $this.Tag.Form.DialogResult = "OK"
                $this.Tag.Form.Close()
            }
        })
    
    # Store form reference in timer for access in tick event
    $timer.Tag = @{ Form = $form }
    
    # Handle Cancel/Close with ESC
    $form.KeyPreview = $true
    $form.Add_KeyDown({
            if ($_.KeyCode -eq "Escape") {
                $this.DialogResult = "Cancel"
                $this.Close()
            }
        })
    
    $timer.Start()
    $result = $form.ShowDialog()
    $timer.Stop()
    $timer.Dispose()
    $form.Dispose()
    
    # Return: OK=timer finished, Yes=immediate, Cancel=cancelled
    if ($result -eq "Yes") { return "Immediate" }
    if ($result -eq "OK") { return $true }
    return $false
}

function Show-StatusDashboard {
    <#
    .SYNOPSIS
        Displays a comprehensive security status dashboard with detailed USB port and device information.
        Shows learned devices vs blocked, HID always-allowed policy, and export capability.
    #>
    
    # ===== DATA GATHERING =====
    
    # Network Adapters
    $allAdapters = Get-NetAdapter -ErrorAction SilentlyContinue
    $wifiAdapters = $allAdapters | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless|802\.11" }
    $ethAdapters = $allAdapters | Where-Object { $_.InterfaceDescription -match "Ethernet" -and $_.InterfaceDescription -notmatch "Virtual|VMware|VirtualBox|Hyper-V" }
    $btAdapters = $allAdapters | Where-Object { $_.InterfaceDescription -match "Bluetooth" }
    $cellularAdapters = $allAdapters | Where-Object { $_.InterfaceDescription -match "Mobile|WWAN|Cellular|LTE|5G|4G|Sierra|Huawei|Quectel" }
    
    # USB Controllers - Comprehensive categorization
    $allUSBControllers = Get-PnpDevice -Class USB -ErrorAction SilentlyContinue
    $usb32Controllers = $allUSBControllers | Where-Object { $_.FriendlyName -match "USB 3\.2|SuperSpeedPlus" }
    $usb31Controllers = $allUSBControllers | Where-Object { $_.FriendlyName -match "USB 3\.1" -and $_.FriendlyName -notmatch "USB 3\.2" }
    $usb30Controllers = $allUSBControllers | Where-Object { $_.FriendlyName -match "USB 3\.0|xHCI|eXtensible Host" -and $_.FriendlyName -notmatch "USB 3\.[12]" }
    $usb20Controllers = $allUSBControllers | Where-Object { $_.FriendlyName -match "USB 2\.0|EHCI|Enhanced Host" -and $_.FriendlyName -notmatch "USB 3" }
    $usb11Controllers = $allUSBControllers | Where-Object { $_.FriendlyName -match "USB 1\.|UHCI|OHCI|Universal Host|Open Host" }
    $rootHubs = $allUSBControllers | Where-Object { $_.FriendlyName -match "Root Hub" }
    $usbHubs = $allUSBControllers | Where-Object { $_.FriendlyName -match "Generic.*Hub|USB Hub" -and $_.FriendlyName -notmatch "Root" }
    $thunderboltCtrl = Get-PnpDevice -ErrorAction SilentlyContinue | Where-Object { $_.FriendlyName -match "Thunderbolt" -and $_.Status -eq "OK" }
    
    # All USB Devices
    $usbDevices = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '^USB\\' }
    
    # Load configuration
    $learningState = Import-JsonSafe -Path $LearningFile -IsEncrypted:$true
    $whitelist = Import-JsonSafe -Path $USBWhitelist
    $whitelistDevices = if ($whitelist -and $whitelist.Devices) { $whitelist.Devices } else { @() }
    $threatDB = Import-JsonSafe -Path $ThreatDBFile
    $threatSignatures = if ($threatDB -and $threatDB.Threats) { $threatDB.Threats } else { @{} }
    $mode = if ($learningState) { $learningState.Mode } else { "Unknown" }
    
    # Disk and log info
    $diskFree = [math]::Round((Get-PSDrive C -ErrorAction SilentlyContinue).Free / 1GB, 1)
    $logSize = if (Test-Path $LogFile) { [math]::Round((Get-Item $LogFile).Length / 1KB, 1) } else { 0 }
    $monitorRunning = Test-Path $LockFile
    
    # ===== FORM SETUP =====
    $form = New-Object System.Windows.Forms.Form
    $form.Text = "AutoLockdown - Security Status Dashboard"
    $form.Size = New-Object System.Drawing.Size(780, 780)
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "FixedDialog"
    $form.MaximizeBox = $false
    $form.MinimizeBox = $false
    $form.TopMost = $true
    $form.BackColor = [System.Drawing.Color]::FromArgb(20, 20, 30)
    
    # Colors
    $colorPanel = [System.Drawing.Color]::FromArgb(30, 30, 45)
    $colorHeader = [System.Drawing.Color]::FromArgb(80, 160, 255)
    $colorOK = [System.Drawing.Color]::FromArgb(50, 205, 50)
    $colorBlocked = [System.Drawing.Color]::FromArgb(255, 80, 80)
    $colorHID = [System.Drawing.Color]::FromArgb(180, 130, 255)
    $colorWarn = [System.Drawing.Color]::FromArgb(255, 180, 0)
    $colorInfo = [System.Drawing.Color]::FromArgb(100, 200, 255)
    $colorText = [System.Drawing.Color]::White
    $colorDim = [System.Drawing.Color]::FromArgb(140, 140, 160)
    
    # ===== HEADER =====
    $lblTitle = New-Object System.Windows.Forms.Label
    $lblTitle.Location = New-Object System.Drawing.Point(15, 10)
    $lblTitle.Size = New-Object System.Drawing.Size(550, 32)
    $lblTitle.Text = "AutoLockdown Security Dashboard"
    $lblTitle.Font = New-Object System.Drawing.Font("Segoe UI", 17, [System.Drawing.FontStyle]::Bold)
    $lblTitle.ForeColor = $colorText
    $form.Controls.Add($lblTitle)
    
    $lblVersion = New-Object System.Windows.Forms.Label
    $lblVersion.Location = New-Object System.Drawing.Point(600, 18)
    $lblVersion.Size = New-Object System.Drawing.Size(150, 20)
    $lblVersion.Text = "v$ScriptVersion"
    $lblVersion.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblVersion.ForeColor = $colorDim
    $lblVersion.TextAlign = [System.Drawing.ContentAlignment]::TopRight
    $form.Controls.Add($lblVersion)
    
    # ===== MODE PANEL =====
    $pnlMode = New-Object System.Windows.Forms.Panel
    $pnlMode.Location = New-Object System.Drawing.Point(15, 48)
    $pnlMode.Size = New-Object System.Drawing.Size(735, 50)
    $pnlMode.BackColor = $colorPanel
    $form.Controls.Add($pnlMode)
    
    $modeColor = if ($mode -eq "Enforced") { $colorOK } elseif ($mode -eq "Learning") { $colorWarn } else { $colorDim }
    $modeIcon = if ($mode -eq "Enforced") { "[LOCK]" } elseif ($mode -eq "Learning") { "[MEMO]" } else { "[?]" }
    
    $lblModeIcon = New-Object System.Windows.Forms.Label
    $lblModeIcon.Location = New-Object System.Drawing.Point(15, 12)
    $lblModeIcon.Size = New-Object System.Drawing.Size(40, 28)
    $lblModeIcon.Text = $modeIcon
    $lblModeIcon.Font = New-Object System.Drawing.Font("Segoe UI", 16)
    $lblModeIcon.ForeColor = $modeColor
    $pnlMode.Controls.Add($lblModeIcon)
    
    $lblModeText = New-Object System.Windows.Forms.Label
    $lblModeText.Location = New-Object System.Drawing.Point(50, 8)
    $lblModeText.Size = New-Object System.Drawing.Size(200, 35)
    $lblModeText.Text = "MODE: $(if ($mode) { $mode.ToUpper() } else { 'UNKNOWN' })"
    $lblModeText.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
    $lblModeText.ForeColor = $modeColor
    $pnlMode.Controls.Add($lblModeText)
    
    # Learning time remaining or policy description
    $policyText = if ($mode -eq "Learning") {
        $expires = [DateTime]::Parse($learningState.Expires)
        if ($learningState.ExpiresUTC) { $expires = $expires.ToLocalTime() }
        $remaining = $expires - (Get-Date)
        if ($remaining.TotalSeconds -gt 0) { "Expires in: $($remaining.ToString('hh\:mm\:ss'))" } else { "Expired - Pending enforcement" }
    }
    else { "All non-whitelisted USB blocked (except HID)" }
    
    $lblPolicy = New-Object System.Windows.Forms.Label
    $lblPolicy.Location = New-Object System.Drawing.Point(280, 15)
    $lblPolicy.Size = New-Object System.Drawing.Size(440, 22)
    $lblPolicy.Text = $policyText
    $lblPolicy.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $lblPolicy.ForeColor = $colorInfo
    $pnlMode.Controls.Add($lblPolicy)
    
    # ===== SCROLLABLE CONTENT PANEL =====
    $panel = New-Object System.Windows.Forms.Panel
    $panel.Location = New-Object System.Drawing.Point(15, 105)
    $panel.Size = New-Object System.Drawing.Size(735, 575)
    $panel.AutoScroll = $true
    $panel.BackColor = $colorPanel
    $form.Controls.Add($panel)
    
    $script:yPos = 8
    
    # Helper: Add section header
    $addHeader = {
        param($text, $icon)
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = New-Object System.Drawing.Point(8, $script:yPos)
        $lbl.Size = New-Object System.Drawing.Size(700, 26)
        $lbl.Text = "$icon  $text"
        $lbl.Font = New-Object System.Drawing.Font("Segoe UI", 12, [System.Drawing.FontStyle]::Bold)
        $lbl.ForeColor = $colorHeader
        $panel.Controls.Add($lbl)
        $script:yPos += 28
    }
    
    # Helper: Add item line
    $addItem = {
        param($text, $color, $indent = 18)
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Location = New-Object System.Drawing.Point($indent, $script:yPos)
        $lbl.Size = New-Object System.Drawing.Size((700 - $indent), 18)
        $lbl.Text = $text
        $lbl.Font = New-Object System.Drawing.Font("Consolas", 9)
        $lbl.ForeColor = $color
        $panel.Controls.Add($lbl)
        $script:yPos += 19
    }
    
    # Helper: Add separator
    $addSep = { $script:yPos += 8 }
    
    # ===== USB PORTS SECTION =====
    & $addHeader "USB PORTS & CONTROLLERS" "[!]"
    
    # USB 3.2
    if ($usb32Controllers) {
        & $addItem "+-- USB 3.2 (SuperSpeed+ 20Gbps)" $colorInfo
        foreach ($c in $usb32Controllers) {
            $st = if ($c.Status -eq "OK") { "[OK]" } else { "[X]" }
            $cl = if ($c.Status -eq "OK") { $colorOK } else { $colorBlocked }
            & $addItem "|  $st $($c.FriendlyName)" $cl 28
        }
    }
    
    # USB 3.1
    if ($usb31Controllers) {
        & $addItem "+-- USB 3.1 (SuperSpeed+ 10Gbps)" $colorInfo
        foreach ($c in $usb31Controllers) {
            $st = if ($c.Status -eq "OK") { "[OK]" } else { "[X]" }
            $cl = if ($c.Status -eq "OK") { $colorOK } else { $colorBlocked }
            & $addItem "|  $st $($c.FriendlyName)" $cl 28
        }
    }
    
    # USB 3.0
    if ($usb30Controllers) {
        & $addItem "+-- USB 3.0 (SuperSpeed 5Gbps)" $colorInfo
        foreach ($c in $usb30Controllers) {
            $st = if ($c.Status -eq "OK") { "[OK]" } else { "[X]" }
            $cl = if ($c.Status -eq "OK") { $colorOK } else { $colorBlocked }
            & $addItem "|  $st $($c.FriendlyName)" $cl 28
        }
    }
    
    # USB 2.0
    if ($usb20Controllers) {
        & $addItem "+-- USB 2.0 (Hi-Speed 480Mbps)" $colorInfo
        foreach ($c in $usb20Controllers) {
            $st = if ($c.Status -eq "OK") { "[OK]" } else { "[X]" }
            $cl = if ($c.Status -eq "OK") { $colorOK } else { $colorBlocked }
            & $addItem "|  $st $($c.FriendlyName)" $cl 28
        }
    }
    
    # USB 1.1
    if ($usb11Controllers) {
        & $addItem "+-- USB 1.1 (Full-Speed 12Mbps)" $colorDim
        foreach ($c in $usb11Controllers) {
            $st = if ($c.Status -eq "OK") { "[OK]" } else { "[X]" }
            $cl = if ($c.Status -eq "OK") { $colorDim } else { $colorBlocked }
            & $addItem "|  $st $($c.FriendlyName)" $cl 28
        }
    }
    
    # Thunderbolt
    if ($thunderboltCtrl) {
        & $addItem "+-- Thunderbolt (40Gbps)" $colorInfo
        foreach ($c in $thunderboltCtrl) {
            & $addItem "|  [OK] $($c.FriendlyName)" $colorOK 28
        }
    }
    
    # Root Hubs & Hubs
    $hubCount = ($rootHubs | Measure-Object).Count + ($usbHubs | Measure-Object).Count
    & $addItem "+-- USB Hubs: $hubCount active (Root + External)" $colorDim
    
    & $addSep
    
    # ===== USB DEVICES SECTION =====
    & $addHeader "USB DEVICES" "[PLUG]"
    
    # Categorize devices
    $learnedDevs = @()
    $blockedDevs = @()
    $hidDevs = @()
    $systemDevs = @()
    $infraDevs = @()  # Infrastructure devices (FTDI relay, JAC 5G)
    
    foreach ($dev in $usbDevices) {
        $idUpper = $dev.InstanceId.ToUpper()
        $vidpid = $null
        if ($idUpper -match "VID[_]([0-9A-F]{4})[&_]PID[_]([0-9A-F]{4})") {
            $vidpid = "VID_$($Matches[1])&PID_$($Matches[2])"
        }
        
        if ($dev.FriendlyName -match "USB Root Hub|Generic USB Hub|USB Host Controller|USB Composite") {
            $systemDevs += $dev
        }
        elseif (Test-AlwaysAllowedUSB -InstanceId $dev.InstanceId) {
            $infraDevs += $dev  # Infrastructure - always allowed
        }
        elseif ($dev.Status -eq "Error") {
            $blockedDevs += $dev
        }
        elseif ($dev.Class -in @("Keyboard", "Mouse", "HIDClass") -or (Test-TrustedHIDVendor -InstanceId $dev.InstanceId)) {
            $hidDevs += $dev
        }
        elseif ($vidpid -and $whitelistDevices -contains $vidpid) {
            $learnedDevs += $dev
        }
        else {
            $blockedDevs += $dev  # Unknown = will be blocked in enforced mode
        }
    }
    
    & $addItem "+==============================================================================+" $colorDim 18
    & $addItem "| Learned: $($learnedDevs.Count)  Infra: $($infraDevs.Count)  HID: $($hidDevs.Count)  Blocked: $($blockedDevs.Count)  Sys: $($systemDevs.Count)" $colorText 18
    & $addItem "+==============================================================================+" $colorDim 18
    
    # Infrastructure devices (FTDI relay, JAC 5G dongle)
    if ($infraDevs.Count -gt 0) {
        & $addItem "[INFRA] INFRASTRUCTURE (Always Allowed - Relay/5G):" $colorInfo
        foreach ($d in $infraDevs) {
            $name = if ($d.FriendlyName.Length -gt 50) { $d.FriendlyName.Substring(0, 47) + "..." } else { $d.FriendlyName }
            & $addItem "   [!] $name" $colorInfo 28
        }
    }
    
    # Learned devices
    if ($learnedDevs.Count -gt 0) {
        & $addItem "[LEARN] LEARNED DEVICES (Permanently Allowed):" $colorOK
        foreach ($d in $learnedDevs) {
            $name = if ($d.FriendlyName.Length -gt 50) { $d.FriendlyName.Substring(0, 47) + "..." } else { $d.FriendlyName }
            & $addItem "   [OK] $name" $colorOK 28
        }
    }
    
    # HID devices
    if ($hidDevs.Count -gt 0) {
        & $addItem "[HID] HID DEVICES (Always Allowed - Keyboard/Mouse):" $colorHID
        foreach ($d in $hidDevs) {
            $name = if ($d.FriendlyName.Length -gt 50) { $d.FriendlyName.Substring(0, 47) + "..." } else { $d.FriendlyName }
            & $addItem "   [KB] $name" $colorHID 28
        }
    }
    
    # Blocked devices
    if ($blockedDevs.Count -gt 0) {
        & $addItem "[BLOCK] BLOCKED DEVICES (Denied Access):" $colorBlocked
        foreach ($d in $blockedDevs) {
            $name = if ($d.FriendlyName.Length -gt 50) { $d.FriendlyName.Substring(0, 47) + "..." } else { $d.FriendlyName }
            & $addItem "   [X] $name" $colorBlocked 28
        }
    }
    
    if ($learnedDevs.Count -eq 0 -and $hidDevs.Count -eq 0 -and $blockedDevs.Count -eq 0 -and $infraDevs.Count -eq 0) {
        & $addItem "   (No user USB devices connected)" $colorDim 28
    }
    
    & $addSep
    
    # ===== NETWORK SECURITY =====
    & $addHeader "NETWORK SECURITY" "[NET]"
    
    # WiFi
    foreach ($a in $wifiAdapters) {
        $bl = $a.Status -eq "Disabled"
        $ic = if ($bl) { "[X]" } else { "[OK]" }
        $tx = if ($bl) { "BLOCKED" } else { "ACTIVE" }
        $cl = if ($bl) { $colorBlocked } else { $colorOK }
        & $addItem "$ic  WiFi: $($a.Name) [$tx]" $cl
    }
    
    # Ethernet
    foreach ($a in $ethAdapters) {
        $bl = $a.Status -eq "Disabled"
        $ic = if ($bl) { "[X]" } else { "[OK]" }
        $tx = if ($bl) { "BLOCKED" } else { "ACTIVE" }
        $cl = if ($bl) { $colorBlocked } else { $colorOK }
        & $addItem "$ic  Ethernet: $($a.Name) [$tx]" $cl
    }
    
    # Bluetooth
    foreach ($a in $btAdapters) {
        $bl = $a.Status -eq "Disabled"
        $ic = if ($bl) { "[X]" } else { "[OK]" }
        $tx = if ($bl) { "BLOCKED" } else { "ACTIVE" }
        $cl = if ($bl) { $colorBlocked } else { $colorOK }
        & $addItem "$ic  Bluetooth: $($a.Name) [$tx]" $cl
    }
    
    # Cellular (always allowed)
    foreach ($a in $cellularAdapters) {
        & $addItem "[OK]  Cellular: $($a.Name) [ALLOWED - Policy Exception]" $colorOK
    }
    
    if (-not $wifiAdapters -and -not $ethAdapters -and -not $btAdapters -and -not $cellularAdapters) {
        & $addItem "   (No network adapters detected)" $colorDim 28
    }
    
    & $addSep
    
    # ===== THREAT INTELLIGENCE =====
    & $addHeader "THREAT INTELLIGENCE" "[LOCK]"
    
    $threatCount = if ($threatSignatures -is [hashtable]) { $threatSignatures.Count } else { ($threatSignatures.PSObject.Properties | Measure-Object).Count }
    & $addItem "Threat Signatures Loaded: $threatCount" $colorOK
    & $addItem "Whitelisted Device IDs: $($whitelistDevices.Count)" $colorOK
    & $addItem "HID Trusted Vendors: $($TRUSTED_HID_VENDORS.Count)" $colorInfo
    & $addItem "Threats Detected This Session: $($script:Metrics.ThreatsDetected)" $(if ($script:Metrics.ThreatsDetected -gt 0) { $colorBlocked } else { $colorOK })
    
    & $addSep
    
    # ===== SYSTEM HEALTH =====
    & $addHeader "SYSTEM HEALTH" "[PC]"
    
    & $addItem "Disk Space (C:): $diskFree GB free" $(if ($diskFree -lt 5) { $colorWarn } else { $colorOK })
    & $addItem "Log File Size: $logSize KB" $(if ($logSize -gt 5000) { $colorWarn } else { $colorOK })
    $monStatus = if ($monitorRunning) { "[OK] Running" } else { "[!!] Not Running" }
    $monColor = if ($monitorRunning) { $colorOK } else { $colorWarn }
    & $addItem "Monitor Service: $monStatus" $monColor
    
    # ===== BUTTONS =====
    $btnExport = New-Object System.Windows.Forms.Button
    $btnExport.Location = New-Object System.Drawing.Point(250, 690)
    $btnExport.Size = New-Object System.Drawing.Size(130, 38)
    $btnExport.Text = "Export Report"
    $btnExport.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $btnExport.ForeColor = $colorText
    $btnExport.FlatStyle = "Flat"
    $btnExport.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($btnExport)
    
    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Location = New-Object System.Drawing.Point(400, 690)
    $btnClose.Size = New-Object System.Drawing.Size(130, 38)
    $btnClose.Text = "Close"
    $btnClose.DialogResult = "OK"
    $btnClose.BackColor = [System.Drawing.Color]::FromArgb(50, 50, 70)
    $btnClose.ForeColor = $colorText
    $btnClose.FlatStyle = "Flat"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 10)
    $form.Controls.Add($btnClose)
    
    # Export Report Handler
    $btnExport.Add_Click({
            $reportPath = Join-Path $BasePath "SecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
            $report = @"
================================================================================
                    AUTOLOCKDOWN SECURITY STATUS REPORT
================================================================================
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Script Version: $ScriptVersion
Mode: $mode

--- USB CONTROLLERS ---
USB 3.2: $($usb32Controllers.Count)
USB 3.1: $($usb31Controllers.Count)
USB 3.0: $($usb30Controllers.Count)
USB 2.0: $($usb20Controllers.Count)
USB 1.1: $($usb11Controllers.Count)
Thunderbolt: $(@($thunderboltCtrl).Count)
Hubs: $hubCount

--- USB DEVICES ---
Learned (Whitelisted): $($learnedDevs.Count)
$($learnedDevs | ForEach-Object { "  - $($_.FriendlyName)" } | Out-String)
HID (Always Allowed): $($hidDevs.Count)
$($hidDevs | ForEach-Object { "  - $($_.FriendlyName)" } | Out-String)
Blocked: $($blockedDevs.Count)
$($blockedDevs | ForEach-Object { "  - $($_.FriendlyName)" } | Out-String)

--- NETWORK ADAPTERS ---
WiFi: $($wifiAdapters.Count) - $(if ($wifiAdapters | Where-Object { $_.Status -eq 'Disabled' }) { 'BLOCKED' } else { 'ACTIVE' })
Ethernet: $($ethAdapters.Count) - $(if ($ethAdapters | Where-Object { $_.Status -eq 'Disabled' }) { 'BLOCKED' } else { 'ACTIVE' })
Bluetooth: $($btAdapters.Count) - $(if ($btAdapters | Where-Object { $_.Status -eq 'Disabled' }) { 'BLOCKED' } else { 'ACTIVE' })
Cellular: $($cellularAdapters.Count) - ALLOWED

--- THREAT INTELLIGENCE ---
Threat Signatures: $threatCount
Whitelisted Devices: $($whitelistDevices.Count)
HID Vendors: $($TRUSTED_HID_VENDORS.Count)

--- SYSTEM HEALTH ---
Disk Space: $diskFree GB free
Log Size: $logSize KB
Monitor: $(if ($monitorRunning) { 'Running' } else { 'Not Running' })

================================================================================
                              END OF REPORT
================================================================================
"@
            $report | Out-File -FilePath $reportPath -Encoding UTF8
            [System.Windows.Forms.MessageBox]::Show("Report saved to:`n$reportPath", "Export Complete", "OK", "Information")
        })
    
    # ESC to close
    $form.KeyPreview = $true
    $form.Add_KeyDown({
            if ($_.KeyCode -eq "Escape") { $this.Close() }
        })
    
    $form.ShowDialog() | Out-Null
    $form.Dispose()
}

# ============================================================================
#   DEPLOYMENT STATE MANAGEMENT
# ============================================================================

function Get-DeploymentState {
    $meta = Import-JsonSafe -Path $MetaFile
    if ($meta) { return $meta.State }
    return "NotInitialized"
}

function Set-DeploymentState {
    param([string]$State)
    $meta = @{
        State = $State; Version = $ScriptVersion; Author = $ScriptAuthor
        Product = $ProductName; LastUpdated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); UpdatedUTC = $true
    }
    if (Export-JsonSafe -Data $meta -Path $MetaFile) {
        Write-LogMessage "Deployment state: $State" -Level "INFO"
        return $true
    }
    return $false
}

# ============================================================================
#   LEARNING MODE MANAGEMENT
# ============================================================================

function Get-LearningState {
    $state = Import-JsonSafe -Path $LearningFile -IsEncrypted
    if ($state -and $state.ExpiresUTC) {
        # Return a copy with local-time Expires to avoid mutating the imported object
        $localExpires = ([DateTime]::Parse($state.Expires)).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
        $state = $state.PSObject.Copy()
        $state.Expires = $localExpires
        # Clear the UTC flag so callers do not double-convert the already-local value
        $state.ExpiresUTC = $false
    }
    return $state
}

function Set-LearningState {
    param([string]$Mode, [DateTime]$Started, [DateTime]$Expires)
    # Compute actual duration in minutes from the Expires parameter so that
    # Invoke-ExtendLearning with a custom -ExtendMinutes value is handled correctly
    # (previously $LearningWindowMinutes was used, which always defaulted to 180).
    $actualMinutes = [math]::Max(1, [int](($Expires - (Get-Date)).TotalMinutes))
    $state = @{
        Mode = $Mode
        Started = $Started.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Expires = $Expires.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        ExpiresUTC = $true
        ExpiresTicks = (Get-MonotonicTimestamp) + ([long]$actualMinutes * 60000)
        Version = $ScriptVersion; Author = $ScriptAuthor; Duration = $actualMinutes
    }
    if (Export-JsonSafe -Data $state -Path $LearningFile -Encrypt) {
        Write-LogMessage "Learning state: $Mode" -Level "INFO"
        return $true
    }
    return $false
}

function Update-LearningMode {
    param([switch]$Silent)
    $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_Learning")
    try {
        if ($mutex.WaitOne($MutexTimeout)) {
            $learning = Get-LearningState
            if ($learning -and $learning.Mode -eq "Learning") {
                $expires = [DateTime]::Parse($learning.Expires)
                if ($learning.ExpiresUTC) { $expires = $expires.ToLocalTime() }
                $now = Get-Date
                $ticksNow = Get-MonotonicTimestamp
                if ($now -ge $expires -or $ticksNow -ge $learning.ExpiresTicks) {
                    $current = Get-LearningState
                    if ($current.Mode -eq "Learning") {
                        $started = [DateTime]::Parse($current.Started)
                        if (Set-LearningState -Mode "Enforced" -Started $started -Expires $expires) {
                            if (-not $Silent) { Write-LogMessage "Learning EXPIRED - ENFORCED mode" -Level "SUCCESS" }
                        }
                    }
                    return "Enforced"
                }
                return "Learning"
            }
            return "Enforced"
        }
        return "Enforced"
    }
    catch { return "Enforced" }
    finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
}

# ============================================================================
#   USB WHITELIST MANAGEMENT
# ============================================================================

function Add-ToWhitelist {
    param([string]$VidPid, [string]$DeviceName = "Unknown")
    $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_Whitelist")
    try {
        if ($mutex.WaitOne($MutexTimeout)) {
            $data = Import-JsonSafe -Path $USBWhitelist
            $whitelist = if ($data) { $data.Devices } else { @() }
            if ($whitelist.Count -ge $MaxWhitelistDevices) {
                Write-LogMessage "Whitelist limit reached" -Level "WARNING"
                return $false
            }
            if ($whitelist -notcontains $VidPid) {
                $whitelist += $VidPid
                $whitelist = $whitelist | Select-Object -Unique
                $data = @{
                    Created = if ($data) { $data.Created } else { (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss") }
                    Version = $ScriptVersion; Author = $ScriptAuthor; Devices = $whitelist
                }
                if (Export-JsonSafe -Data $data -Path $USBWhitelist) {
                    Write-LogMessage "LEARNED $DeviceName - $VidPid" -Level "LEARNED"
                    return $true
                }
            }
            return $false
        }
        return $false
    }
    catch { return $false }
    finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
}

# ============================================================================
#   HID & THREAT DATABASE
# ============================================================================

function Save-HIDVendors {
    $data = @{ Updated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); Version = $ScriptVersion; Author = $ScriptAuthor; Vendors = $TRUSTED_HID_VENDORS }
    if (Export-JsonSafe -Data $data -Path $HIDVendorsFile) {
        Write-LogMessage "HID vendors saved ($($TRUSTED_HID_VENDORS.Count) vendors)" -Level "SUCCESS"
        return $true
    }
    return $false
}



function Save-ThreatDatabase {
    $data = @{ Updated = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); Version = $ScriptVersion; Author = $ScriptAuthor; Threats = $THREAT_DATABASE }
    if (Export-JsonSafe -Data $data -Path $ThreatDBFile) {
        Write-LogMessage "Threat database saved ($($THREAT_DATABASE.Count) signatures)" -Level "SUCCESS"
        return $true
    }
    return $false
}

# ============================================================================
#   SYSTEM BACKUP & SECURITY
# ============================================================================

function Backup-SystemState {
    if (Test-Path $BackupFile) { Write-LogMessage "Backup exists - skipping" -Level "INFO"; return $true }
    try {
        $backup = @{
            Timestamp = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
            Version = $ScriptVersion; Author = $ScriptAuthor
            NetworkAdapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, InterfaceGuid, MacAddress, Status)
            USBDevices = @(Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '^USB\\' } | Select-Object FriendlyName, InstanceId, Status, Class)
            PowerPlan = (powercfg /GETACTIVESCHEME)
            RegistryKeys = @{ AutoPlay = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -ErrorAction SilentlyContinue).NoDriveTypeAutoRun }
        }
        if (Export-JsonSafe -Data $backup -Path $BackupFile) {
            Write-LogMessage "System backup created" -Level "SUCCESS"
            return $true
        }
    }
    catch { Write-LogMessage "Backup failed: $_" -Level "WARNING" }
    return $false
}

function Set-HardenedACLs {
    try {
        if (-not (Test-Path $BasePath)) { New-Item -Path $BasePath -ItemType Directory -Force | Out-Null }
        $acl = Get-Acl $BasePath
        $acl.SetAccessRuleProtection($true, $false)
        $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
        $acl.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow")))
        Set-Acl -Path $BasePath -AclObject $acl
        Write-LogMessage "ACLs hardened" -Level "SUCCESS"
        return $true
    }
    catch { Write-LogMessage "ACL hardening failed: $_" -Level "ERROR"; return $false }
}

function Register-SystemMetadata {
    try {
        $reg = "HKLM:\SOFTWARE\AutoLockdown"
        if (-not (Test-Path $reg)) { New-Item -Path $reg -Force | Out-Null }
        Set-ItemProperty -Path $reg -Name "Version" -Value $ScriptVersion -Force
        Set-ItemProperty -Path $reg -Name "Author" -Value $ScriptAuthor -Force
        Set-ItemProperty -Path $reg -Name "Product" -Value $ProductName -Force
        Set-ItemProperty -Path $reg -Name "DeploymentDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Force
        if (-not [System.Diagnostics.EventLog]::SourceExists("AutoLockdown")) {
            New-EventLog -LogName Application -Source "AutoLockdown" -ErrorAction SilentlyContinue
        }
        Write-LogMessage "System metadata registered" -Level "SUCCESS"
        return $true
    }
    catch { return $false }
}

# ============================================================================
#   POWER & POLICY MANAGEMENT
# ============================================================================

function Disable-PowerSaving {
    try {
        # Switch to High Performance plan
        & powercfg /SETACTIVE 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c 2>$null

        # Disable USB selective suspend (AC & DC)
        & powercfg /SETACVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2beb146644c 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null
        & powercfg /SETDCVALUEINDEX SCHEME_CURRENT 2a737441-1930-4402-8d77-b2beb146644c 48e6b7a6-50f5-4782-a5d4-53bb8f07e226 0 2>$null

        # Set display timeout to Never (0)
        & powercfg /SETACVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0 2>$null
        & powercfg /SETDCVALUEINDEX SCHEME_CURRENT 7516b95f-f776-4464-8c53-06167f40cc99 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e 0 2>$null

        # Set sleep timeout to Never (0)
        & powercfg /SETACVALUEINDEX SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0 2>$null
        & powercfg /SETDCVALUEINDEX SCHEME_CURRENT 238c9fa8-0aad-41ed-83f4-97be242c8f20 29f6c1db-86da-48c5-9fdb-f2b67b1f44da 0 2>$null

        # Apply changes to current scheme
        & powercfg /SETACTIVE SCHEME_CURRENT 2>$null
        Write-LogMessage "Power settings configured (display/sleep: Never)" -Level "SUCCESS"
        return $true
    }
    catch { return $false }
}

function Set-HardenedSystemPolicy {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    try {
        $path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
        if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }
        if ($PSCmdlet.ShouldProcess("AutoPlay Policy", "Disable")) {
            Set-ItemProperty -Path $path -Name "NoDriveTypeAutoRun" -Value 255 -Force -ErrorAction Stop
            Write-LogMessage "AutoPlay disabled" -Level "SUCCESS"
        }
        return $true
    }
    catch { return $false }
}

# ============================================================================
#   NETWORK ADAPTER MANAGEMENT
# ============================================================================

function Test-CellularAdapter { param([string]$Description); return ($Description -match "Mobile|WWAN|Cellular|LTE|5G|4G|3G|Modem|Sierra|Huawei|Quectel|Telit|Ericsson|Fibocom|JAC|NDIS|RNDIS|CDC") }
function Test-PhysicalEthernet { param([string]$Description); if ($Description -match "Ethernet" -and $Description -notmatch "Virtual|VMware|VirtualBox|Hyper-V|TAP|Bridge") { return $true }; return $false }
function Test-WiFiAdapter { param([string]$Description); return ($Description -match "Wireless|Wi-Fi|802.11|WiFi|WLAN") }
function Test-BluetoothAdapter { param([string]$Description); return ($Description -match "Bluetooth") }

function Initialize-NetworkWhitelist {
    try {
        $active = Get-NetAdapter -ErrorAction SilentlyContinue
        $cellularOnly = @()
        foreach ($nic in $active) {
            $desc = $nic.InterfaceDescription
            if (Test-CellularAdapter -Description $desc) {
                $cellularOnly += @{ Description = $desc; InterfaceGuid = $nic.InterfaceGuid.ToString(); MacAddress = $nic.MacAddress; Name = $nic.Name; Type = "Cellular" }
                Write-LogMessage "Trusted cellular: $($nic.Name)" -Level "SUCCESS"
            }
            elseif ($desc -match "Virtual|VMware|VirtualBox|Hyper-V|TAP") {
                $cellularOnly += @{ Description = $desc; InterfaceGuid = $nic.InterfaceGuid.ToString(); MacAddress = $nic.MacAddress; Name = $nic.Name; Type = "Virtual" }
            }
        }
        $data = @{ Created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); Version = $ScriptVersion; Author = $ScriptAuthor; Policy = "Cellular and Virtual only"; Adapters = $cellularOnly }
        if (Export-JsonSafe -Data $data -Path $NetWhitelist) {
            Write-LogMessage "Network whitelist saved ($($cellularOnly.Count) adapters)" -Level "SUCCESS"
            return $true
        }
    }
    catch { Write-LogMessage "Network whitelist error: $_" -Level "ERROR" }
    return $false
}

function Set-SecureRadios {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    try {
        $data = Import-JsonSafe -Path $NetWhitelist
        $allowedAdapters = if ($data) { $data.Adapters } else { @() }
        Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object {
            $current = $_
            $shouldEnable = $false
            if (Test-CellularAdapter -Description $current.InterfaceDescription) { $shouldEnable = $true }
            elseif ($allowedAdapters | Where-Object { $_.InterfaceGuid -eq $current.InterfaceGuid.ToString() }) { $shouldEnable = $true }
            if ($shouldEnable) {
                if ($current.Status -ne "Up") { Enable-NetAdapter -Name $current.Name -Confirm:$false -ErrorAction SilentlyContinue }
            }
            else {
                if ($current.Status -ne "Disabled") {
                    if ($PSCmdlet.ShouldProcess($current.Name, "Disable")) { Disable-NetAdapter -Name $current.Name -Confirm:$false -ErrorAction SilentlyContinue }
                }
            }
        }
        return $true
    }
    catch { return $false }
}

# ============================================================================
#   USB DEVICE MANAGEMENT
# ============================================================================

function Initialize-USBWhitelist {
    try {
        $connected = Get-PnpDevice -PresentOnly -ErrorAction Stop | Where-Object { $_.InstanceId -match '^USB\\' }
        $allowList = @()
        foreach ($dev in $connected) {
            $idUpper = $dev.InstanceId.ToUpper()
            $vidpid = $null
            if ($idUpper -match "VID[_]([0-9A-F]{4})[&_]PID[_]([0-9A-F]{4})") {
                $vidpid = "VID_$($Matches[1])&PID_$($Matches[2])"
            }
            if (-not $vidpid) { continue }
            if ($THREAT_DATABASE.ContainsKey($vidpid)) { continue }
            if ($allowList -notcontains $vidpid) {
                $allowList += $vidpid
                Write-LogMessage "Trusted USB: $($dev.FriendlyName) - $vidpid" -Level "SUCCESS"
            }
        }
        $allowList = $allowList | Select-Object -Unique
        $data = @{ Created = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"); Version = $ScriptVersion; Author = $ScriptAuthor; Devices = $allowList }
        if (Export-JsonSafe -Data $data -Path $USBWhitelist) {
            Write-LogMessage "USB whitelist saved ($($allowList.Count) devices)" -Level "SUCCESS"
            return $true
        }
    }
    catch { Write-LogMessage "USB whitelist error: $_" -Level "ERROR" }
    return $false
}

function Deny-Device {
    [CmdletBinding(SupportsShouldProcess)]
    param($Device, $Reason)
    try {
        if ($PSCmdlet.ShouldProcess($Device.FriendlyName, "Block USB Device")) {
            Disable-PnpDevice -InstanceId $Device.InstanceId -Confirm:$false -ErrorAction Stop
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$($Device.InstanceId)"
            if (Test-Path $regPath) { Set-ItemProperty -Path $regPath -Name "ConfigFlags" -Value 0x00000001 -Force -ErrorAction SilentlyContinue }
            Write-LogMessage "BLOCKED $($Device.FriendlyName) - $Reason" -Level "BLOCK"
            $script:Metrics.TotalBlocks++
            if ($Reason -match "Threat") { $script:Metrics.ThreatsDetected++ }
        }
    }
    catch { Write-LogMessage "Block failed: $_" -Level "ERROR" }
}

# ============================================================================
#   FAST-PATH REGISTRY WATCHER
# ============================================================================

function Start-RegistryWatcher {
    <#
    .SYNOPSIS
        Starts a background PowerShell runspace that polls the USB device registry
        hive every 250 ms and immediately blocks unauthorized devices BEFORE the
        OS has a chance to load any device driver.

    .DESCRIPTION
        Windows writes the device entry under
        HKLM:\SYSTEM\CurrentControlSet\Enum\USB\VID_XXXX&PID_YYYY\<serial>
        the instant a USB device is detected  -  well before Win32_PnPEntity is
        created and before driver installation begins.  By polling this hive at
        250 ms intervals the watcher catches new arrivals and calls
        Disable-PnpDevice on unauthorized devices, preventing drivers (USBSTOR,
        Apple MTP, Android MTP) from ever binding.

        HID vendor matching in this path also reads the early "Class" registry
        value so that devices with an Apple VID (VID_05AC) that present as
        "Image" or "WPD" (iPhones, iPads) are NOT granted the HID exemption  -
        they proceed to the whitelist/block decision instead.

    .PARAMETER Config
        Hashtable containing all paths and policy arrays the runspace needs.
    #>
    param([hashtable]$Config)

    $runspace = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspace()
    $runspace.Open()

    foreach ($key in $Config.Keys) {
        $runspace.SessionStateProxy.SetVariable($key, $Config[$key])
    }

    $ps = [System.Management.Automation.PowerShell]::Create()
    $ps.Runspace = $runspace

    [void]$ps.AddScript({
            Add-Type -AssemblyName System.Security
            $DPAPI_SCOPE = [System.Security.Cryptography.DataProtectionScope]::LocalMachine

            # Registry-friendly HID class names set early by Windows
            $HID_REGISTRY_CLASSES = @("HIDClass", "HID", "Keyboard", "Mouse", "Human Interface Device", "Bluetooth")

            # Well-known HID ClassGUIDs (keyboard, mouse/pointer, generic HID).
            # ClassGUID is written to the registry slightly before the human-readable Class
            # string, so it serves as a reliable early-classification fallback.
            $HID_CLASS_GUIDS = @(
                "{4D36E96B-E325-11CE-BFC1-08002BE10318}",  # Keyboard
                "{4D36E96F-E325-11CE-BFC1-08002BE10318}",  # Mouse / Pointer
                "{745A17A0-74D3-11D0-B6FE-00A0C90F57DA}"   # Human Interface Device
            )

            $knownInstanceIds = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase)

            # Pre-populate with devices already present so the watcher does not
            # re-evaluate (and potentially double-block) devices connected before
            # the monitor started.
            try {
                $existing = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue |
                Where-Object { $_.InstanceId -match '^USB\\' }
                foreach ($dev in $existing) { [void]$knownInstanceIds.Add($dev.InstanceId) }
            }
            catch {}

            function Write-WatcherLog {
                param([string]$Message, [string]$Level = "INFO")
                $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                $line = "[$ts] [$Level] [FastPath] $Message"
                Add-Content -Path $LogPath -Value $line -Force -ErrorAction SilentlyContinue
            }

            function Get-WhitelistFast {
                try {
                    $raw = Get-Content $USBWhitelistPath -Raw -Encoding UTF8 -ErrorAction Stop
                    if (-not $raw.Trim().StartsWith("{")) {
                        $bytes = [Convert]::FromBase64String($raw)
                        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
                            $bytes, $null, $DPAPI_SCOPE)
                        $raw = [System.Text.Encoding]::UTF8.GetString($dec)
                    }
                    return @(($raw | ConvertFrom-Json).Devices)
                }
                catch { return @() }
            }

            function Get-LearningActiveFast {
                try {
                    $raw = Get-Content $LearningFilePath -Raw -Encoding UTF8 -ErrorAction Stop
                    if (-not $raw.Trim().StartsWith("{")) {
                        $bytes = [Convert]::FromBase64String($raw)
                        $dec = [System.Security.Cryptography.ProtectedData]::Unprotect(
                            $bytes, $null, $DPAPI_SCOPE)
                        $raw = [System.Text.Encoding]::UTF8.GetString($dec)
                    }
                    $state = $raw | ConvertFrom-Json
                    if ($state.Mode -eq "Learning") {
                        $expires = [DateTime]::Parse($state.Expires)
                        if ($state.ExpiresUTC) { $expires = $expires.ToLocalTime() }
                        return (Get-Date) -lt $expires
                    }
                    return $false
                }
                catch { return $false }
            }

            # ---------------------------------------------------------------------------
            # Container-based allow cache (in-memory + disk, keyed by ContainerId GUID)
            # Used to allow mode-switched devnodes that share the same physical device
            # ContainerId as a trusted VID_322B seed device.
            # ---------------------------------------------------------------------------
            # In-memory: hashtable ContainerId (uppercase) -> expiry DateTime
            $containerCache = @{}

            function Test-ValidContainerGuid {
                param([string]$Id)
                if (-not $Id) { return $false }
                return $Id -match $ContainerGuidPattern
            }

            function Load-ContainerCacheFast {
                $attempts = @($ContainerAllowCachePath, "$ContainerAllowCachePath.bak1", "$ContainerAllowCachePath.bak2")
                $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
                try {
                    if ($mutex.WaitOne(5000)) {
                        foreach ($file in $attempts) {
                            if (Test-Path $file) {
                                try {
                                    $raw = Get-Content $file -Raw -Encoding UTF8
                                    $data = $raw | ConvertFrom-Json
                                    $containerCache.Clear()
                                    foreach ($c in $data.Containers) {
                                        $exp = [DateTime]::Parse($c.Expires)
                                        if ($c.ExpiresUTC) { $exp = $exp.ToLocalTime() }
                                        $containerCache[$c.ContainerId.ToUpper()] = $exp
                                    }
                                    return
                                }
                                catch { Write-WatcherLog "ContainerAllow: cache load error from $file" -Level "WARNING" }
                            }
                        }
                    }
                }
                catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
            }

            function Add-ContainerToCache {
                param([string]$ContainerId, [string]$SeedInstanceId)
                $now = Get-Date
                $exp = $now.AddHours($ContainerAllowTTLHours)
                $cidUpper = $ContainerId.ToUpper()
                $containerCache[$cidUpper] = $exp
                Write-WatcherLog "Seeded Jac ContainerId $cidUpper from seed $SeedInstanceId" -Level "SUCCESS"
            
                $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
                try {
                    if ($mutex.WaitOne(5000)) {
                        $entries = @()
                        foreach ($k in $containerCache.Keys) {
                            if ($containerCache[$k] -gt $now) {
                                $entries += @{
                                    ContainerId = $k
                                    Expires     = $containerCache[$k].ToUniversalTime().ToString("o")
                                    ExpiresUTC  = $true
                                }
                            }
                        }
                        $wrap = @{ Containers = $entries }
                        $json = $wrap | ConvertTo-Json -Depth 3
                    
                        if (Test-Path $ContainerAllowCachePath) {
                            if (Test-Path "$ContainerAllowCachePath.bak1") { Copy-Item "$ContainerAllowCachePath.bak1" "$ContainerAllowCachePath.bak2" -Force -ErrorAction SilentlyContinue }
                            Copy-Item $ContainerAllowCachePath "$ContainerAllowCachePath.bak1" -Force -ErrorAction SilentlyContinue
                        }
                        $json | Out-File $ContainerAllowCachePath -Force -Encoding UTF8
                    }
                }
                catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
            }

            # Initial load
            Load-ContainerCacheFast

            $usbEnumPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\USB"

            while ($true) {
                try {
                    if (-not (Test-Path $usbEnumPath)) { Start-Sleep -Milliseconds 250; continue }

                    $vidpidKeys = Get-ChildItem $usbEnumPath -ErrorAction SilentlyContinue
                    foreach ($vidpidKey in $vidpidKeys) {
                        $vidpidName = $vidpidKey.PSChildName  # e.g. "VID_05AC&PID_12A8"

                        # Only process standard VID&PID keys (skip ROOT_HUB, USB*, etc.)
                        if ($vidpidName -notmatch '^VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}') { continue }

                        $instanceKeys = Get-ChildItem $vidpidKey.PSPath -ErrorAction SilentlyContinue
                        foreach ($instanceKey in $instanceKeys) {
                            $instanceId = "USB\$vidpidName\$($instanceKey.PSChildName)"

                            if ($knownInstanceIds.Contains($instanceId)) { continue }
                            [void]$knownInstanceIds.Add($instanceId)

                            # Extract normalised VID_XXXX&PID_YYYY
                            $vidpid = $null
                            if ($vidpidName -match 'VID_([0-9A-Fa-f]{4})&PID_([0-9A-Fa-f]{4})') {
                                $vidpid = "VID_$($Matches[1].ToUpper())&PID_$($Matches[2].ToUpper())"
                            }
                            if (-not $vidpid) { continue }

                            $idUpper = $vidpidName.ToUpper()

                            # --- Check emergency bypass ---
                            if (Test-Path $EmergencyBypassPath) {
                                $bypassAge = ((Get-Date) - (Get-Item $EmergencyBypassPath).CreationTime).TotalMinutes
                                if ($bypassAge -lt 30) {
                                    Write-WatcherLog "ALLOWED $vidpid - Emergency bypass" -Level "WARNING"
                                    continue
                                }
                            }

                            # --- Check always-allowed infrastructure devices ---
                            $isInfra = $false
                            foreach ($vendor in $AlwaysAllowedVendors) {
                                if ($idUpper -match [regex]::Escape($vendor.ToUpper())) { $isInfra = $true; break }
                            }
                            if ($isInfra) {
                                Write-WatcherLog "ALLOWED $vidpid - Infrastructure" -Level "SUCCESS"
                                # Seed the container allow cache when a trusted VID_322B device is seen
                                # so that its mode-switched modem devnodes (different VID/PID, same
                                # physical device ContainerId) are automatically allowed below.
                                if ($instanceId -imatch '^USB\\VID_322B') {
                                    try {
                                        $cidRaw = (Get-ItemProperty $instanceKey.PSPath -ErrorAction SilentlyContinue).ContainerID
                                        if ($cidRaw -and (Test-ValidContainerGuid $cidRaw)) {
                                            Add-ContainerToCache -ContainerId $cidRaw -SeedInstanceId $instanceId
                                        }
                                        else {
                                            Write-WatcherLog "ContainerAllow: ContainerId unavailable for $instanceId (not seeded)" -Level "INFO"
                                        }
                                    }
                                    catch {
                                        Write-WatcherLog "ContainerAllow: error reading ContainerId for $instanceId : $_" -Level "INFO"
                                    }
                                }
                                continue
                            }

                            # --- Check trusted HID vendors with registry-class guard ---
                            # Read the "Class" and "ClassGUID" values written early by Windows
                            # (before driver binds).  ClassGUID is typically written slightly before
                            # the human-readable Class string, so it serves as a reliable fallback.
                            $regClass = $null
                            $regClassGuid = $null
                            try {
                                $regProps = Get-ItemProperty $instanceKey.PSPath -ErrorAction SilentlyContinue
                                $regClass = $regProps.Class
                                $regClassGuid = $regProps.ClassGUID
                            }
                            catch {}

                            # --- Allow USB infrastructure by registry class (hubs, root hubs) ---
                            # Blocking a USB hub disables every downstream port on that hub, which
                            # can render all connected devices unreachable ("bricks" the system).
                            if ($regClass -and ($regClass -eq "USB" -or $regClass -eq "HUBClass")) {
                                Write-WatcherLog "ALLOWED $vidpid - USB hub/infrastructure (class: $regClass)" -Level "SUCCESS"
                                continue
                            }

                            $isHIDVendor = $false
                            foreach ($vendor in $HIDVendors) {
                                if ($idUpper -match [regex]::Escape($vendor.ToUpper())) { $isHIDVendor = $true; break }
                            }

                            # Allow: trusted vendor + Class string confirms HID
                            if ($isHIDVendor -and $regClass -and $HID_REGISTRY_CLASSES -contains $regClass) {
                                Write-WatcherLog "ALLOWED $vidpid - Trusted HID vendor (class=$regClass)" -Level "SUCCESS"
                                continue
                            }

                            # Allow: trusted vendor + ClassGUID confirms HID (fallback when Class
                            # string is not yet written, e.g. some USB-C controllers on first plug-in)
                            if ($isHIDVendor -and $regClassGuid -and $HID_CLASS_GUIDS -contains $regClassGuid) {
                                Write-WatcherLog "ALLOWED $vidpid - Trusted HID vendor (ClassGUID=$regClassGuid)" -Level "SUCCESS"
                                continue
                            }
                            # If vendor is in the HID list but Class is not yet set (device still
                            # enumerating), retry briefly to give Windows time to populate the value.
                            if ($isHIDVendor -and (-not $regClass)) {
                                for ($classWait = 0; $classWait -lt 5 -and (-not $regClass); $classWait++) {
                                    Start-Sleep -Milliseconds 100
                                    try {
                                        $regClass = (Get-ItemProperty $instanceKey.PSPath -Name "Class" -ErrorAction SilentlyContinue).Class
                                    }
                                    catch {}
                                }
                                if ($regClass -and $HID_REGISTRY_CLASSES -contains $regClass) {
                                    Write-WatcherLog "ALLOWED $vidpid - Trusted HID vendor" -Level "SUCCESS"
                                    continue
                                }
                                # Class still absent after retries: allow any non-Apple HID vendor.
                                # Apple (VID_05AC) can present as "Image" or "WPD" for iPhones/iPads
                                # so those must fall through to the whitelist/block decision.
                                if ($idUpper -notmatch 'VID_05AC') {
                                    Write-WatcherLog "ALLOWED $vidpid - Trusted HID vendor (class pending)" -Level "SUCCESS"
                                    continue
                                }
                            }
                            # If vendor is in the HID list but:
                            #   - Class is non-HID (e.g. Apple iPhone: VID_05AC, class=Image/WPD), OR
                            #   - Apple device with class still unset
                            # fall through to the whitelist/block decision.

                            # --- Check container allow cache ---
                            $cidRaw2 = $null
                            try { $cidRaw2 = (Get-ItemProperty $instanceKey.PSPath -ErrorAction SilentlyContinue).ContainerID } catch {}
                            if ($cidRaw2 -and (Test-ValidContainerGuid $cidRaw2)) {
                                $cidUpper2 = $cidRaw2.ToUpper()
                                # Periodically reload cache from disk
                                Load-ContainerCacheFast
                                if ($containerCache.ContainsKey($cidUpper2) -and $containerCache[$cidUpper2] -gt (Get-Date)) {
                                    Write-WatcherLog "ALLOWED $vidpid - ContainerId match ($cidUpper2)" -Level "SUCCESS"
                                    continue
                                }
                            }

                            # --- Check learning mode ---
                            if (Get-LearningActiveFast) {
                                Write-WatcherLog "ALLOWED $vidpid - Learning mode" -Level "SUCCESS"
                                continue
                            }

                            # --- Check whitelist ---
                            $whitelist = Get-WhitelistFast
                            if ($whitelist -contains $vidpid) {
                                Write-WatcherLog "ALLOWED $vidpid - Whitelisted" -Level "SUCCESS"
                                continue
                            }

                            # --- Not whitelisted in enforcement mode: BLOCK immediately ---
                            Write-WatcherLog "BLOCKING $vidpid ($instanceId) before driver install" -Level "BLOCK"

                            # Retry up to 5 x 100 ms while the devnode is being created
                            $blocked = $false
                            for ($attempt = 0; $attempt -lt 5; $attempt++) {
                                try {
                                    $pnpDev = Get-PnpDevice -InstanceId $instanceId -ErrorAction SilentlyContinue
                                    if ($pnpDev) {
                                        if ($pnpDev.Status -eq "Error") {
                                            # Already disabled (possibly by a prior attempt)
                                            $blocked = $true; break
                                        }
                                        Disable-PnpDevice -InstanceId $instanceId -Confirm:$false -ErrorAction Stop
                                        # Set ConfigFlags = 1 (disabled) to survive reboot
                                        $regPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\$instanceId"
                                        if (Test-Path $regPath) {
                                            Set-ItemProperty -Path $regPath -Name "ConfigFlags" `
                                                -Value 0x00000001 -Force -ErrorAction SilentlyContinue
                                        }
                                        Write-WatcherLog "BLOCKED $vidpid ($instanceId) - enforcement (fast-path)" -Level "BLOCK"
                                        $blocked = $true; break
                                    }
                                }
                                catch {}
                                Start-Sleep -Milliseconds 100
                            }

                            if (-not $blocked) {
                                Write-WatcherLog "WARN: devnode not ready for $vidpid  -  WMI handler will catch it" -Level "WARNING"
                            }
                        }
                    }
                }
                catch {
                    # Swallow all watcher-loop errors; never let the runspace exit
                }
                Start-Sleep -Milliseconds 250
            }
        })

    $asyncResult = $ps.BeginInvoke()
    return @{ PS = $ps; Runspace = $runspace; AsyncResult = $asyncResult }
}

# ============================================================================
#   REAL-TIME MONITORING
# ============================================================================

function Start-RealtimeMonitoring {
    $depState = Get-DeploymentState
    if ($depState -ne "Initialized") { Write-LogMessage "Not initialized - Exiting" -Level "ERROR"; exit 1 }
    
    if (Test-Path $LockFile) {
        try {
            $lockContent = Get-Content $LockFile -Raw
            if ($lockContent -match "PID:(\d+)") {
                $existingPid = [int]$Matches[1]
                $process = Get-Process -Id $existingPid -ErrorAction SilentlyContinue
                if ($process) { Write-LogMessage "Monitor already running at PID $existingPid" -Level "WARNING"; exit 0 }
                else { Remove-Item $LockFile -Force }
            }
        }
        catch {}
    }
    
    "PID:$PID|Mode:Monitor|Started:$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')|Author:$ScriptAuthor|Version:$ScriptVersion" | Out-File $LockFile -Force
    
    $script:SafeMode = Test-SafeMode
    if ($script:SafeMode) { Write-LogMessage "Running in $script:SafeMode" -Level "WARNING" }
    
    Write-LogMessage "$ProductName monitoring started v$ScriptVersion" -Level "SUCCESS"
    
    Get-EventSubscriber -SourceIdentifier "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue | Unregister-Event
    Get-Job -Name "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue | Remove-Job -Force
    
    $data = Import-JsonSafe -Path $USBWhitelist
    $script:Whitelist = if ($data) { $data.Devices } else { @() }
    $threatData = Import-JsonSafe -Path $ThreatDBFile
    $script:ThreatMap = if ($threatData) { $threatData.Threats } else { $THREAT_DATABASE }
    $hidData = Import-JsonSafe -Path $HIDVendorsFile
    $script:HIDVendors = if ($hidData) { $hidData.Vendors } else { $TRUSTED_HID_VENDORS }
    
    $learningMode = Update-LearningMode -Silent
    Write-LogMessage "Mode: $learningMode | Whitelist: $($script:Whitelist.Count)" -Level "INFO"
    
    Write-LogMessage "Startup device scan..." -Level "INFO"
    $devs = Get-PnpDevice -PresentOnly -ErrorAction SilentlyContinue | Where-Object { $_.InstanceId -match '^USB\\' }
    foreach ($d in $devs) { Protect-USBDevice -Device $d -IsStartup $true }
    
    # Start the fast-path registry watcher.  It polls HKLM:\...\Enum\USB every
    # 250 ms and blocks unknown devices before any driver can bind.
    Write-LogMessage "Starting fast-path registry watcher (250 ms)..." -Level "INFO"
    $watcherConfig = @{
        LogPath                 = $LogFile
        USBWhitelistPath        = $USBWhitelist
        LearningFilePath        = $LearningFile
        EmergencyBypassPath     = $EmergencyBypassFile
        AlwaysAllowedVendors    = $ALWAYS_ALLOWED_USB_VENDORS
        HIDVendors              = if ($script:HIDVendors.Count -gt 0) { $script:HIDVendors } else { $TRUSTED_HID_VENDORS }
        ContainerAllowCachePath = $ContainerAllowCacheFile
        ContainerAllowTTLHours  = $CONTAINER_ALLOW_TTL_HOURS
        ContainerGuidPattern    = $CONTAINER_ID_GUID_PATTERN
    }
    $script:RegWatcher = Start-RegistryWatcher -Config $watcherConfig
    Write-LogMessage "Fast-path registry watcher started" -Level "SUCCESS"

    Write-LogMessage "Registering WMI event subscription..." -Level "SUCCESS"
    
    # WITHIN 1: secondary catch-all fires every 1 s (after Win32_PnPEntity exists,
    # i.e. after driver install); the registry watcher above handles pre-driver blocking.
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE TargetInstance ISA 'Win32_PnPEntity' AND TargetInstance.DeviceID LIKE 'USB\\VID%'"
    $messageData = @{ LogPath = $LogFile; USBWhitelistPath = $USBWhitelist; ThreatDBPath = $ThreatDBFile; HIDVendorsPath = $HIDVendorsFile; LearningFilePath = $LearningFile; BasePath = $BasePath; ScriptAuthor = $ScriptAuthor; ScriptVersion = $ScriptVersion; MaxWhitelistDevices = $MaxWhitelistDevices; MutexTimeout = $MutexTimeout; AlwaysAllowedVendors = $ALWAYS_ALLOWED_USB_VENDORS; EmergencyBypassPath = $EmergencyBypassFile; ContainerAllowCachePath = $ContainerAllowCacheFile; ContainerAllowTTLHours = $CONTAINER_ALLOW_TTL_HOURS; ContainerGuidPattern = $CONTAINER_ID_GUID_PATTERN }
    
    Register-WmiEvent -Query $query -SourceIdentifier "AutoLockdown_USBWatch" -MessageData $messageData -Action {
        $data = $Event.MessageData
        try {
            $device = $Event.SourceEventArgs.NewEvent.TargetInstance
            $deviceId = $device.DeviceID
            $vidpid = $null
            if ($deviceId -match "VID[_]([0-9A-F]{4})[&_]PID[_]([0-9A-F]{4})") { $vidpid = "VID_$($Matches[1])&PID_$($Matches[2])" }
            if (-not $vidpid) { return }
            
            $fullDev = Get-PnpDevice -InstanceId $deviceId -ErrorAction SilentlyContinue
            if (-not $fullDev) { return }
            
            # Fast-path dedup: if the registry watcher already disabled this device,
            # skip all further processing to avoid redundant log entries.
            if ($fullDev.Status -eq "Error") {
                Add-Content -Path $data.LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [INFO] [WMI] Already blocked by fast-path: $($fullDev.FriendlyName)" -Force
                return
            }

            $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

            # Check emergency bypass (allows all devices for 30 min)
            if (Test-Path $data.EmergencyBypassPath) {
                $bypassAge = ((Get-Date) - (Get-Item $data.EmergencyBypassPath).CreationTime).TotalMinutes
                if ($bypassAge -lt 30) {
                    Add-Content -Path $data.LogPath -Value "[$ts] [WARNING] ALLOWED $($fullDev.FriendlyName) - Emergency bypass active" -Force
                    return
                }
            }

            # Read whitelist with DPAPI decryption support
            $whitelist = @()
            if (Test-Path $data.USBWhitelistPath) {
                try {
                    $wlContent = Get-Content $data.USBWhitelistPath -Raw -Encoding UTF8
                    if (-not $wlContent.Trim().StartsWith("{")) {
                        $wlBytes = [Convert]::FromBase64String($wlContent)
                        $wlDecrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($wlBytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                        $wlContent = [System.Text.Encoding]::UTF8.GetString($wlDecrypted)
                    }
                    $wlData = $wlContent | ConvertFrom-Json
                    $whitelist = $wlData.Devices
                }
                catch { $whitelist = @() }
            }
            $threats = @{}; if (Test-Path $data.ThreatDBPath) { $thrData = Get-Content $data.ThreatDBPath -Raw | ConvertFrom-Json; $threats = $thrData.Threats }
            $hidVendors = @(); if (Test-Path $data.HIDVendorsPath) { $hidD = Get-Content $data.HIDVendorsPath -Raw | ConvertFrom-Json; $hidVendors = $hidD.Vendors }
            
            $class = $fullDev.Class
            # Untrusted HID devices (potential BadUSB) intentionally fall through to whitelist/block logic below
            if ($class -in @("Keyboard", "Mouse", "HIDClass")) {
                $idUpper = $deviceId.ToUpper()
                foreach ($vendor in $hidVendors) { if ($idUpper -match [regex]::Escape($vendor)) { Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] ALLOWED $($fullDev.FriendlyName) - Trusted HID" -Force; return } }
            }
            
            # Check always-allowed infrastructure devices from messageData
            $idUpper = $deviceId.ToUpper()
            $isWmiInfra = $false
            foreach ($alVendor in $data.AlwaysAllowedVendors) {
                if ($idUpper -match [regex]::Escape($alVendor)) {
                    $isWmiInfra = $true; break
                }
            }
            if ($isWmiInfra) {
                Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] ALLOWED $($fullDev.FriendlyName) - Infrastructure device" -Force
                # Seed container allow cache when a VID_322B device is seen via WMI
                if ($deviceId -imatch '^USB\\VID_322B') {
                    try {
                        $cidProp = Get-PnpDeviceProperty -InstanceId $deviceId -KeyName "DEVPKEY_Device_ContainerId" -ErrorAction SilentlyContinue
                        $cidVal = if ($cidProp) { $cidProp.Data } else { $null }
                        $cidStr = if ($cidVal -is [System.Guid]) { "{$cidVal}" } elseif ($cidVal) { $cidVal.ToString() } else { $null }
                        if ($cidStr -and $cidStr -match $data.ContainerGuidPattern) {
                            $cidUpper = $cidStr.ToUpper()
                            $now = Get-Date
                            $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
                            try {
                                if ($mutex.WaitOne($data.MutexTimeout)) {
                                    $cacheEntries = @()
                                    if (Test-Path $data.ContainerAllowCachePath) {
                                        $attempts = @($data.ContainerAllowCachePath, "$($data.ContainerAllowCachePath).bak1", "$($data.ContainerAllowCachePath).bak2")
                                        foreach ($f in $attempts) {
                                            if (Test-Path $f) {
                                                try { $cacheEntries = @((Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).Containers); break } catch {}
                                            }
                                        }
                                    }

                                    # Keep non-expired entries, unless it's our newly seeded ContainerId
                                    $updated = @(); $found = $false
                                    $expNew = $now.AddHours($data.ContainerAllowTTLHours)
                                    foreach ($e in $cacheEntries) {
                                        $entryExp = [DateTime]::Parse($e.Expires)
                                        if ($e.ExpiresUTC) { $entryExp = $entryExp.ToLocalTime() }
                                        if ($entryExp -gt $now -and $e.ContainerId -ne $cidUpper) { $updated += $e }
                                        if ($e.ContainerId -eq $cidUpper) { $found = $true }
                                    }
                                    $updated += @{
                                        ContainerId = $cidUpper
                                        Expires     = $expNew.ToUniversalTime().ToString("o")
                                        ExpiresUTC  = $true
                                    }
                                    $json = @{ Containers = $updated } | ConvertTo-Json -Depth 3
                                    if (Test-Path $data.ContainerAllowCachePath) {
                                        if (Test-Path "$($data.ContainerAllowCachePath).bak1") { Copy-Item "$($data.ContainerAllowCachePath).bak1" "$($data.ContainerAllowCachePath).bak2" -Force -ErrorAction SilentlyContinue }
                                        Copy-Item $data.ContainerAllowCachePath "$($data.ContainerAllowCachePath).bak1" -Force -ErrorAction SilentlyContinue
                                    }
                                    $json | Out-File $data.ContainerAllowCachePath -Force -Encoding UTF8
                                    Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] Seeded Jac ContainerId $cidUpper from seed $deviceId via WMI" -Force
                                }
                            }
                            catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
                        }
                    }
                    catch {}
                }
                return
            }

            # Check container cache before checking whitelist
            try {
                if (Test-Path $data.ContainerAllowCachePath) {
                    $cidProp2 = Get-PnpDeviceProperty -InstanceId $deviceId -KeyName "DEVPKEY_Device_ContainerId" -ErrorAction SilentlyContinue
                    $cidVal2 = if ($cidProp2) { $cidProp2.Data } else { $null }
                    $cidStr2 = if ($cidVal2 -is [System.Guid]) { "{$cidVal2}" } elseif ($cidVal2) { $cidVal2.ToString() } else { $null }
                    if ($cidStr2 -and $cidStr2 -match $data.ContainerGuidPattern) {
                        $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
                        try {
                            if ($mutex.WaitOne($data.MutexTimeout)) {
                                $cacheRead = $null
                                $attempts = @($data.ContainerAllowCachePath, "$($data.ContainerAllowCachePath).bak1", "$($data.ContainerAllowCachePath).bak2")
                                foreach ($f in $attempts) {
                                    if (Test-Path $f) {
                                        try { $cacheRead = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; break } catch {}
                                    }
                                }
                                if ($cacheRead) {
                                    $cidUpper2 = $cidStr2.ToUpper()
                                    $now = Get-Date
                                    foreach ($c in $cacheRead.Containers) {
                                        if ($c.ContainerId -eq $cidUpper2) {
                                            $expCache = [DateTime]::Parse($c.Expires)
                                            if ($c.ExpiresUTC) { $expCache = $expCache.ToLocalTime() }
                                            if ($expCache -gt $now) {
                                                Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] ALLOWED $($fullDev.FriendlyName) - ContainerId match ($cidUpper2)" -Force
                                                return
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
                    }
                }
            }
            catch {}
            
            if ($whitelist -contains $vidpid) { Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] ALLOWED $($fullDev.FriendlyName) - Whitelisted" -Force; return }
            # Handle PSCustomObject from JSON (not hashtable) with null-safe access
            $threatInfo = $null
            if ($threats -is [hashtable]) { if ($threats.ContainsKey($vidpid)) { $threatInfo = $threats[$vidpid] } }
            else { $prop = $threats.PSObject.Properties.Match($vidpid); if ($prop.Count -gt 0) { $threatInfo = $prop[0].Value } }
            if ($threatInfo) { Add-Content -Path $data.LogPath -Value "[$ts] [BLOCK] BLOCKED $($fullDev.FriendlyName) - Threat: $($threatInfo.Name)" -Force; Disable-PnpDevice -InstanceId $deviceId -Confirm:$false -ErrorAction SilentlyContinue; return }
            
            $learningMode = "Enforced"
            if (Test-Path $data.LearningFilePath) {
                try {
                    $content = Get-Content $data.LearningFilePath -Raw -Encoding UTF8
                    # Handle DPAPI encryption (if content is not JSON, it's encrypted)
                    if (-not $content.Trim().StartsWith("{")) {
                        # Decrypt DPAPI
                        $bytes = [Convert]::FromBase64String($content)
                        $decrypted = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $null, [System.Security.Cryptography.DataProtectionScope]::LocalMachine)
                        $content = [System.Text.Encoding]::UTF8.GetString($decrypted)
                    }
                    $learning = $content | ConvertFrom-Json
                    if ($learning.Mode -eq "Learning") {
                        $expires = [DateTime]::Parse($learning.Expires)
                        if ($learning.ExpiresUTC) { $expires = $expires.ToLocalTime() }
                        if ((Get-Date) -lt $expires) { $learningMode = "Learning" }
                    }
                }
                catch { $learningMode = "Enforced" }
            }
            
            if ($learningMode -eq "Learning") {
                $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_Whitelist")
                try {
                    if ($mutex.WaitOne($data.MutexTimeout)) {
                        if ($whitelist.Count -lt $data.MaxWhitelistDevices -and $whitelist -notcontains $vidpid) {
                            $whitelist += $vidpid; $whitelist = $whitelist | Select-Object -Unique
                            # Safely re-read Created timestamp (guards against future encryption changes)
                            $existingCreated = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            try { if (Test-Path $data.USBWhitelistPath) { $wlRaw = Get-Content $data.USBWhitelistPath -Raw -Encoding UTF8; if ($wlRaw.Trim().StartsWith("{")) { $existingCreated = ($wlRaw | ConvertFrom-Json).Created } } } catch {}
                            $wlData = @{ Created = $existingCreated; Version = $data.ScriptVersion; Author = $data.ScriptAuthor; Devices = $whitelist }
                            $wlData | ConvertTo-Json -Depth 3 | Out-File $data.USBWhitelistPath -Force -Encoding UTF8
                            Add-Content -Path $data.LogPath -Value "[$ts] [LEARNED] LEARNED $($fullDev.FriendlyName) - $vidpid" -Force
                        }
                    }
                }
                finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
                Add-Content -Path $data.LogPath -Value "[$ts] [SUCCESS] ALLOWED $($fullDev.FriendlyName) - Learning mode" -Force
            }
            else {
                Add-Content -Path $data.LogPath -Value "[$ts] [BLOCK] BLOCKED $($fullDev.FriendlyName) - Not whitelisted" -Force
                Disable-PnpDevice -InstanceId $deviceId -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
        catch { Add-Content -Path $data.LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [ERROR] Event error: $_" -Force }
    } | Out-Null
    
    Write-LogMessage "WMI event subscription registered" -Level "SUCCESS"
    
    try {
        while ($true) {
            Start-Sleep -Seconds 60
            Update-LearningMode -Silent | Out-Null
            # Periodically reload whitelist so startup-scan stays current
            $data = Import-JsonSafe -Path $USBWhitelist
            $script:Whitelist = if ($data) { $data.Devices } else { @() }
            if (-not (Test-DiskSpace)) { $script:ReadOnlyMode = $true }
            if (Test-Path $LockFile) {
                # Rewrite lockfile with fixed format to prevent unbounded growth
                $heartbeat = "PID:$PID|Mode:Monitor|Started:$($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))|Author:$ScriptAuthor|Version:$ScriptVersion|LastHeartbeat:$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
                $heartbeat | Out-File $LockFile -Force
            }
        }
    }
    finally {
        Get-EventSubscriber -SourceIdentifier "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue | Unregister-Event
        Get-Job -Name "AutoLockdown_USBWatch" -ErrorAction SilentlyContinue | Remove-Job -Force
        # Stop the fast-path registry watcher runspace
        if ($script:RegWatcher) {
            try { $script:RegWatcher.PS.Stop() } catch {}
            try { $script:RegWatcher.PS.Dispose() } catch {}
            try { $script:RegWatcher.Runspace.Close() } catch {}
            try { $script:RegWatcher.Runspace.Dispose() } catch {}
            $script:RegWatcher = $null
        }
        if (Test-Path $LockFile) { Remove-Item $LockFile -Force -ErrorAction SilentlyContinue }
        Write-LogMessage "Monitor stopped" -Level "INFO"
    }
}

function Protect-USBDevice {
    param($Device, [bool]$IsStartup = $false)
    # Emergency bypass allows all devices for 30 min
    if (Test-EmergencyBypass) { Write-LogMessage "ALLOWED $($Device.FriendlyName) - Emergency bypass" -Level "WARNING"; return }
    $idUpper = $Device.InstanceId.ToUpper()
    $vidpid = $null
    if ($idUpper -match "VID[_]([0-9A-F]{4})[&_]PID[_]([0-9A-F]{4})") { $vidpid = "VID_$($Matches[1])&PID_$($Matches[2])" }
    if ($Device.FriendlyName -match "USB Root Hub|Generic USB Hub|USB Host Controller") { Write-LogMessage "ALLOWED $($Device.FriendlyName) - System" -Level "SUCCESS"; return }
    # Wait for device enumeration only for hot-plugged devices, not during startup scan
    if (-not $IsStartup -and (-not $Device.Class -or $Device.Status -eq "Unknown")) { for ($i = 0; $i -lt 20; $i++) { Start-Sleep -Milliseconds 500; $Device = Get-PnpDevice -InstanceId $Device.InstanceId -ErrorAction SilentlyContinue; if ($Device -and $Device.Class -and $Device.Status -ne "Unknown") { break } } }
    if (($Device.Class -eq "Keyboard" -or $Device.Class -eq "Mouse" -or $Device.Class -eq "HIDClass") -and (Test-TrustedHIDVendor -InstanceId $Device.InstanceId)) { Write-LogMessage "ALLOWED $($Device.FriendlyName) - Trusted HID" -Level "SUCCESS"; $script:Metrics.TotalAllowed++; return }
    # Check for always-allowed infrastructure devices (FTDI relay, JAC 5G dongle)
    if (Test-AlwaysAllowedUSB -InstanceId $Device.InstanceId) {
        Write-LogMessage "ALLOWED $($Device.FriendlyName) - Infrastructure" -Level "SUCCESS"
        $script:Metrics.TotalAllowed++
        # Seed container allow cache when a VID_322B device is seen
        if ($Device.InstanceId -imatch '^USB\\VID_322B') {
            try {
                $cidProp = Get-PnpDeviceProperty -InstanceId $Device.InstanceId -KeyName "DEVPKEY_Device_ContainerId" -ErrorAction SilentlyContinue
                $cidVal = if ($cidProp) { $cidProp.Data } else { $null }
                $cidStr = if ($cidVal -is [System.Guid]) { "{$cidVal}" } elseif ($cidVal) { $cidVal.ToString() } else { $null }
                if ($cidStr -and $cidStr -match $CONTAINER_ID_GUID_PATTERN) {
                    $cidUpper = $cidStr.ToUpper()
                    $now = Get-Date
                    $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
                    try {
                        if ($mutex.WaitOne($MutexTimeout)) {
                            $cacheEntries = @()
                            if (Test-Path $ContainerAllowCacheFile) {
                                $attempts = @($ContainerAllowCacheFile, "$ContainerAllowCacheFile.bak1", "$ContainerAllowCacheFile.bak2")
                                foreach ($f in $attempts) {
                                    if (Test-Path $f) {
                                        try { $cacheEntries = @((Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json).Containers); break } catch {}
                                    }
                                }
                            }

                            # Keep non-expired entries, unless it's our newly seeded ContainerId
                            $updated = @(); $found = $false
                            $expNew = $now.AddHours($CONTAINER_ALLOW_TTL_HOURS)
                            foreach ($e in $cacheEntries) {
                                $entryExp = [DateTime]::Parse($e.Expires)
                                if ($e.ExpiresUTC) { $entryExp = $entryExp.ToLocalTime() }
                                if ($entryExp -gt $now -and $e.ContainerId -ne $cidUpper) { $updated += $e }
                                if ($e.ContainerId -eq $cidUpper) { $found = $true }
                            }
                            $updated += @{
                                ContainerId = $cidUpper
                                Expires     = $expNew.ToUniversalTime().ToString("o")
                                ExpiresUTC  = $true
                            }
                            $json = @{ Containers = $updated } | ConvertTo-Json -Depth 3
                            if (Test-Path $ContainerAllowCacheFile) {
                                if (Test-Path "$ContainerAllowCacheFile.bak1") { Copy-Item "$ContainerAllowCacheFile.bak1" "$ContainerAllowCacheFile.bak2" -Force -ErrorAction SilentlyContinue }
                                Copy-Item $ContainerAllowCacheFile "$ContainerAllowCacheFile.bak1" -Force -ErrorAction SilentlyContinue
                            }
                            $json | Out-File $ContainerAllowCacheFile -Force -Encoding UTF8
                            Write-LogMessage "Seeded Jac ContainerId $cidUpper from seed $($Device.InstanceId)" -Level "SUCCESS"
                        }
                    }
                    catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
                }
            }
            catch {}
        }
        return
    }

    # Check container allow cache before denylist/whitelist
    try {
        $cidPropD = Get-PnpDeviceProperty -InstanceId $Device.InstanceId -KeyName "DEVPKEY_Device_ContainerId" -ErrorAction SilentlyContinue
        $cidValD = if ($cidPropD) { $cidPropD.Data } else { $null }
        $cidStrD = if ($cidValD -is [System.Guid]) { "{$cidValD}" } elseif ($cidValD) { $cidValD.ToString() } else { $null }
        if ($cidStrD -and $cidStrD -match $CONTAINER_ID_GUID_PATTERN) {
            $mutex = New-Object System.Threading.Mutex($false, "Global\AutoLockdown_ContainerCache")
            try {
                if ($mutex.WaitOne($MutexTimeout)) {
                    $cacheReadD = $null
                    $attempts = @($ContainerAllowCacheFile, "$ContainerAllowCacheFile.bak1", "$ContainerAllowCacheFile.bak2")
                    foreach ($f in $attempts) {
                        if (Test-Path $f) {
                            try { $cacheReadD = Get-Content $f -Raw -Encoding UTF8 | ConvertFrom-Json; break } catch {}
                        }
                    }
                    if ($cacheReadD) {
                        $cidUpperD = $cidStrD.ToUpper()
                        $now = Get-Date
                        foreach ($c in $cacheReadD.Containers) {
                            if ($c.ContainerId -eq $cidUpperD) {
                                $expCacheD = [DateTime]::Parse($c.Expires)
                                if ($c.ExpiresUTC) { $expCacheD = $expCacheD.ToLocalTime() }
                                if ($expCacheD -gt $now) {
                                    Write-LogMessage "ALLOWED $($Device.FriendlyName) - ContainerId match ($cidUpperD)" -Level "SUCCESS"
                                    $script:Metrics.TotalAllowed++; return
                                }
                            }
                        }
                    }
                }
            }
            catch {} finally { try { $mutex.ReleaseMutex() } catch {} finally { $mutex.Dispose() } }
        }
    }
    catch {}
    if ($vidpid -and $script:Whitelist -contains $vidpid) { Write-LogMessage "ALLOWED $($Device.FriendlyName) - Whitelisted" -Level "SUCCESS"; $script:Metrics.TotalAllowed++; return }
    # Handle PSCustomObject from JSON
    $threatInfo = $null
    if ($vidpid) { if ($script:ThreatMap -is [hashtable]) { if ($script:ThreatMap.ContainsKey($vidpid)) { $threatInfo = $script:ThreatMap[$vidpid] } } else { $prop = $script:ThreatMap.PSObject.Properties.Match($vidpid); if ($prop.Count -gt 0) { $threatInfo = $prop[0].Value } } }
    if ($threatInfo) { Deny-Device -Device $Device -Reason "Threat: $($threatInfo.Name)"; return }
    $learningMode = Update-LearningMode -Silent
    if ($learningMode -eq "Learning") {
        if ($vidpid) { if (Add-ToWhitelist -VidPid $vidpid -DeviceName $Device.FriendlyName) { $script:Metrics.TotalLearned++ }; $data = Import-JsonSafe -Path $USBWhitelist; $script:Whitelist = if ($data) { $data.Devices } else { @() }; Write-LogMessage "ALLOWED $($Device.FriendlyName) - Learning" -Level "SUCCESS"; $script:Metrics.TotalAllowed++ }
    }
    else { Deny-Device -Device $Device -Reason "Not whitelisted - Default Deny" }
}

# ============================================================================
#   SCHEDULED TASK
# ============================================================================

function Register-StartupTask {
    [CmdletBinding(SupportsShouldProcess)]
    param()
    try {
        $taskName = "AutoLockdown_Service"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($existingTask) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$DeployedScript`" -Monitor"
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        if ($PSCmdlet.ShouldProcess($taskName, "Register")) {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "AutoLockdown USB Security Monitor v$ScriptVersion" -ErrorAction Stop | Out-Null
            Write-LogMessage "Scheduled task created" -Level "SUCCESS"
            return $true
        }
    }
    catch { Write-LogMessage "Scheduled task creation failed: $_" -Level "ERROR"; return $false }
}

# ============================================================================
#   INITIALIZATION WORKFLOW
# ============================================================================

function Initialize-System {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  $ProductName v$ScriptVersion - SYSTEM INITIALIZATION" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  Author: $ScriptAuthor" -ForegroundColor White
    Write-Host "  Integrity Hash: $(Get-SystemConfig -Key 'Hash')" -ForegroundColor Gray
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $currentState = Get-DeploymentState
    if ($currentState -eq "Initialized") { Write-Host "Reinitializing..." -ForegroundColor Yellow }
    
    Write-LogMessage "Validating environment..." -Level "INFO"
    $safeMode = Test-SafeMode
    if ($safeMode) { throw "System is in Safe Mode - Cannot initialize" }
    if (-not (Test-PathSafe -Path $BasePath)) { throw "BasePath security validation failed" }
    if (-not (Test-DiskSpace -RequiredMB 50)) { throw "Insufficient disk space" }
    if (-not (Test-Path $BasePath)) { New-Item -Path $BasePath -ItemType Directory -Force | Out-Null }
    
    Write-LogMessage "Step 1/14: Creating system backup..." -Level "INFO"
    Backup-SystemState | Out-Null
    
    Write-LogMessage "Step 2/14: Saving HID vendors..." -Level "INFO"
    if (-not (Save-HIDVendors)) { throw "Failed to save HID vendors" }
    
    Write-LogMessage "Step 3/14: Saving threat database..." -Level "INFO"
    if (-not (Save-ThreatDatabase)) { throw "Failed to save threat database" }
    
    Write-LogMessage "Step 4/14: Scanning USB devices..." -Level "INFO"
    if (-not (Initialize-USBWhitelist)) { throw "Failed to initialize USB whitelist" }
    
    Write-LogMessage "Step 5/14: Learning network adapters..." -Level "INFO"
    if (-not (Initialize-NetworkWhitelist)) { throw "Failed to initialize network whitelist" }
    
    Write-LogMessage "Step 6/14: Enforcing network policy..." -Level "INFO"
    Set-SecureRadios
    
    Write-LogMessage "Step 7/14: Configuring power settings..." -Level "INFO"
    Disable-PowerSaving
    
    Write-LogMessage "Step 8/14: Hardening system policies..." -Level "INFO"
    if (-not (Set-HardenedSystemPolicy)) { throw "Failed to harden system policy" }
    
    Write-LogMessage "Step 9/14: Applying security ACLs..." -Level "INFO"
    Set-HardenedACLs
    
    Write-LogMessage "Step 10/14: Registering system metadata..." -Level "INFO"
    Register-SystemMetadata
    
    Write-LogMessage "Step 11/14: Setting learning window..." -Level "INFO"
    $StartedDT = Get-Date
    $ExpiresDT = $StartedDT.AddMinutes($LearningWindowMinutes)
    $state = @{
        Mode = "Learning"
        Started = $StartedDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        Expires = $ExpiresDT.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
        ExpiresUTC = $true
        ExpiresTicks = (Get-MonotonicTimestamp) + ([long]$LearningWindowMinutes * 60000)
        Version = $ScriptVersion; Author = $ScriptAuthor; Duration = $LearningWindowMinutes
    }
    if (Export-JsonSafe -Data $state -Path $LearningFile -Encrypt) {
        Write-LogMessage "Learning window active ($LearningWindowMinutes min)" -Level "SUCCESS"
    }
    else { throw "Failed to save learning state" }
    
    Write-LogMessage "Step 12/14: Deploying main script..." -Level "INFO"
    Copy-Item -Path $PSCommandPath -Destination $DeployedScript -Force
    
    Write-LogMessage "Step 13/14: Creating scheduled task..." -Level "INFO"
    Register-StartupTask | Out-Null
    
    Write-LogMessage "Step 14/14: Saving deployment metadata..." -Level "INFO"
    Set-DeploymentState -State "Initialized"
    
    Write-LogMessage "Deployment complete! (14/14 steps)" -Level "SUCCESS"
    
    # GUI Flow (default) - Skip if -Silent
    if (-not $Silent) {
        Write-Host ""
        Write-Host "Starting Interactive Learning Mode..." -ForegroundColor Cyan
        
        # 1. Learning Timer with +5 Minutes option
        $learningResult = Show-TimerForm -Title "AutoLockdown Learning Mode" `
            -Message "System is in LEARNING MODE.`n`nConnect all legitimate USB devices now.`nDevices connected after this window will be BLOCKED." `
            -Seconds ($LearningWindowMinutes * 60) `
            -AllowCancel -CancelButtonText "Finish Early" `
            -AllowExtend -ExtendMinutes 5
        
        # Transition learning state to Enforced now that the timer has ended.
        # This is critical when the user clicks "Finish Early" (returns $false):
        # without this, the learning state file still contains the original expiry
        # time, so the system remains in learning mode after the form closes.
        $startedDTForEnforce = $StartedDT
        $expiresDTForEnforce = Get-Date
        if (Set-LearningState -Mode "Enforced" -Started $startedDTForEnforce -Expires $expiresDTForEnforce) {
            if ($learningResult -eq $false) {
                Write-LogMessage "Learning finished early by user - transitioning to ENFORCED" -Level "SUCCESS"
            }
            else {
                Write-LogMessage "Learning timer completed - transitioning to ENFORCED" -Level "SUCCESS"
            }
        }
            
        # 2. Reboot with configurable delay + Reboot Now option
        $reboot = Show-TimerForm -Title "System Restart Required" `
            -Message "Configuration complete. System must restart to enforce security policies." `
            -Seconds $RebootDelaySeconds `
            -CompleteMessage "Restarting system..." `
            -AllowCancel -CancelButtonText "Cancel Reboot" `
            -AllowImmediate -ImmediateText "Reboot Now"
            
        if ($reboot -eq $true -or $reboot -eq "Immediate") {
            Write-LogMessage "Initiating forced reboot..." -Level "INFO"
            Restart-Computer -Force
        }
        else {
            Write-LogMessage "Reboot cancelled by user. Reboot required for enforcement." -Level "WARNING"
            Write-Host "WARNING: Reboot cancelled. Protection may not be fully active until restart." -ForegroundColor Yellow
            
            # Show security status dashboard
            Show-StatusDashboard
        }
    }
    else {
        # Silent mode - no GUI
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "  INITIALIZATION COMPLETE (Silent Mode)" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Learning Mode Active: $LearningWindowMinutes minutes" -ForegroundColor White
        Write-Host "  Expires: $($ExpiresDT.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor White
        Write-Host ""
        Write-Host "  ACTION REQUIRED:" -ForegroundColor Yellow
        Write-Host "  1. Connect all legitimate USB devices NOW." -ForegroundColor White
        Write-Host "  2. REBOOT this machine manually to start enforcement." -ForegroundColor White
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
    }
    $footerLine = "-" * 76
    Write-Host $footerLine -ForegroundColor DarkGray
    Write-Host "Deployed by: $ScriptAuthor" -ForegroundColor DarkGray
    Write-Host "System Integrity: $(Get-SystemConfig -Key 'Hash')" -ForegroundColor DarkGray
    Write-Host $footerLine -ForegroundColor DarkGray
}

# ============================================================================
#   NEW P0/P1 FEATURES
# ============================================================================

function Test-EmergencyBypass {
    <#
    .SYNOPSIS
        Checks for emergency bypass file (allows 30-min grace period)
    #>
    if (Test-Path $EmergencyBypassFile) {
        $created = (Get-Item $EmergencyBypassFile).CreationTime
        $age = ((Get-Date) - $created).TotalMinutes
        if ($age -lt 30) {
            Write-LogMessage "EMERGENCY BYPASS ACTIVE ($([math]::Round(30 - $age, 0)) min remaining)" -Level "WARNING"
            return $true
        }
        else {
            Remove-Item $EmergencyBypassFile -Force -ErrorAction SilentlyContinue
            Write-LogMessage "Emergency bypass expired - removed" -Level "INFO"
        }
    }
    return $false
}

function Write-SecurityEvent {
    <#
    .SYNOPSIS
        Writes security events to Windows Event Log
    #>
    param(
        [string]$Message,
        [ValidateSet("Information", "Warning", "Error")]
        [string]$Type = "Warning",
        [int]$EventId = 4001
    )
    
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists("AutoLockdown")) {
            New-EventLog -LogName Application -Source "AutoLockdown" -ErrorAction SilentlyContinue
        }
        Write-EventLog -LogName Application -Source "AutoLockdown" -EventId $EventId -EntryType $Type -Message $Message -ErrorAction SilentlyContinue
    }
    catch {
        # Fallback: log failure is non-fatal
        Write-LogMessage "Event log write failed: $_" -Level "WARNING"
    }
}

function Invoke-ExtendLearning {
    <#
    .SYNOPSIS
        Extends learning window without full reinitialize
    #>
    param([int]$Minutes = 60)
    
    $learning = Get-LearningState
    if (-not $learning) {
        Write-Host "Error: System not initialized" -ForegroundColor Red
        return $false
    }
    
    $now = Get-Date
    $newExpires = $now.AddMinutes($Minutes)
    
    if (Set-LearningState -Mode "Learning" -Started $now -Expires $newExpires) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "  LEARNING MODE EXTENDED" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  Duration: $Minutes minutes" -ForegroundColor Cyan
        Write-Host "  Expires:  $($newExpires.ToString('yyyy-MM-dd HH:mm:ss'))" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "  Connect any additional USB devices now." -ForegroundColor Yellow
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        
        Write-LogMessage "Learning extended: $Minutes minutes (expires $($newExpires.ToString('HH:mm:ss')))" -Level "SUCCESS"
        Write-SecurityEvent -Message "Learning mode extended by administrator for $Minutes minutes" -Type Information -EventId 4003
        return $true
    }
    
    Write-Host "Error: Failed to extend learning mode" -ForegroundColor Red
    return $false
}

function Invoke-AddDevice {
    <#
    .SYNOPSIS
        Manually adds device to whitelist
    #>
    param(
        [string]$VidPid,
        [string]$Name = "Manually Added"
    )
    
    if (-not $VidPid -or $VidPid -notmatch "^VID_[0-9A-Fa-f]{4}&PID_[0-9A-Fa-f]{4}$") {
        Write-Host ""
        Write-Host "Error: Invalid VID/PID format" -ForegroundColor Red
        Write-Host "Expected: VID_XXXX&PID_XXXX (e.g., VID_1234&PID_5678)" -ForegroundColor Yellow
        return $false
    }
    
    $VidPid = $VidPid.ToUpper()
    
    # Check if it's a known threat
    if ($THREAT_DATABASE.ContainsKey($VidPid)) {
        Write-Host ""
        Write-Host "ERROR: Device is in threat database!" -ForegroundColor Red
        Write-Host "Device: $($THREAT_DATABASE[$VidPid].Name)" -ForegroundColor Red
        Write-Host "Threat: $($THREAT_DATABASE[$VidPid].Threat)" -ForegroundColor Red
        Write-Host ""
        Write-Host "Cannot whitelist known attack devices." -ForegroundColor Yellow
        return $false
    }
    
    if (Add-ToWhitelist -VidPid $VidPid -DeviceName $Name) {
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host "  DEVICE ADDED TO WHITELIST" -ForegroundColor Green
        Write-Host "============================================================================" -ForegroundColor Green
        Write-Host ""
        Write-Host "  VID/PID: $VidPid" -ForegroundColor White
        Write-Host "  Name:    $Name" -ForegroundColor White
        Write-Host ""
        Write-Host "============================================================================" -ForegroundColor Green
        
        Write-SecurityEvent -Message "Device manually whitelisted by administrator: $VidPid ($Name)" -Type Information -EventId 4002
        return $true
    }
    else {
        Write-Host "Device may already be whitelisted or whitelist is full" -ForegroundColor Yellow
        return $false
    }
}

function Show-Status {
    <#
    .SYNOPSIS
        Shows current AutoLockdown status
    #>
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  $ProductName v$ScriptVersion - STATUS" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Deployment state
    $state = Get-DeploymentState
    $stateColor = if ($state -eq "Initialized") { "Green" } else { "Red" }
    Write-Host "  Deployment: " -NoNewline
    Write-Host $state -ForegroundColor $stateColor
    
    # Learning mode
    $learning = Get-LearningState
    if ($learning) {
        $mode = $learning.Mode
        $modeColor = if ($mode -eq "Enforced") { "Green" } else { "Yellow" }
        Write-Host "  Mode:       " -NoNewline
        Write-Host $mode -ForegroundColor $modeColor
        
        if ($mode -eq "Learning") {
            $expires = [DateTime]::Parse($learning.Expires)
            if ($learning.ExpiresUTC) { $expires = $expires.ToLocalTime() }
            $remaining = $expires - (Get-Date)
            if ($remaining.TotalSeconds -gt 0) {
                Write-Host "  Expires:    $($expires.ToString('HH:mm:ss')) ($([math]::Round($remaining.TotalMinutes, 0)) min)" -ForegroundColor Yellow
            }
        }
    }
    
    # Whitelist
    $wl = Import-JsonSafe -Path $USBWhitelist
    $wlCount = if ($wl) { $wl.Devices.Count } else { 0 }
    Write-Host "  Whitelisted: $wlCount devices"
    
    # Monitor
    $monitorRunning = Test-Path $LockFile
    Write-Host "  Monitor:    " -NoNewline
    Write-Host $(if ($monitorRunning) { "Running" } else { "Stopped" }) -ForegroundColor $(if ($monitorRunning) { "Green" } else { "Red" })
    
    # Emergency bypass
    if (Test-Path $EmergencyBypassFile) {
        $created = (Get-Item $EmergencyBypassFile).CreationTime
        $age = ((Get-Date) - $created).TotalMinutes
        if ($age -lt 30) {
            Write-Host "  BYPASS:     " -NoNewline
            Write-Host "ACTIVE ($([math]::Round(30 - $age, 0)) min)" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
}

# ============================================================================
#   MAIN EXECUTION
# ============================================================================

if ($Initialize) {
    Initialize-System
}
elseif ($Monitor) {
    # Check emergency bypass before monitoring
    if (Test-EmergencyBypass) {
        Write-LogMessage "Emergency bypass active - running in permissive mode" -Level "WARNING"
    }
    Start-RealtimeMonitoring
}
elseif ($ExtendLearning) {
    Invoke-ExtendLearning -Minutes $ExtendMinutes
}
elseif ($AddDevice) {
    Invoke-AddDevice -VidPid $DeviceVidPid -Name $DeviceName
}
elseif ($ShowStatus) {
    Show-Status
}
else {
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host "  $ProductName v$ScriptVersion" -ForegroundColor Cyan
    Write-Host "============================================================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Author: $ScriptAuthor" -ForegroundColor White
    Write-Host ""
    Write-Host "  Commands:" -ForegroundColor Yellow
    Write-Host "    -Initialize              Initialize system with learning mode" -ForegroundColor Gray
    Write-Host "    -Monitor                 Start real-time USB monitoring" -ForegroundColor Gray
    Write-Host "    -ShowStatus              Display current protection status" -ForegroundColor Gray
    Write-Host "    -ExtendLearning          Extend learning window" -ForegroundColor Gray
    Write-Host "    -AddDevice               Manually whitelist a device" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Options:" -ForegroundColor Yellow
    Write-Host "    -LearningWindowMinutes   Duration in minutes (default: 5)" -ForegroundColor Gray
    Write-Host "    -DeviceVidPid            VID_XXXX&PID_XXXX format" -ForegroundColor Gray
    Write-Host "    -DeviceName              Friendly name for device" -ForegroundColor Gray
    Write-Host "    -WhatIf                  Preview without changes" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Examples:" -ForegroundColor Yellow
    Write-Host "    .\AutoLockdown.ps1 -Initialize -LearningWindowMinutes 5" -ForegroundColor White
    Write-Host "    .\AutoLockdown.ps1 -ExtendLearning -ExtendMinutes 60" -ForegroundColor White
    Write-Host "    .\AutoLockdown.ps1 -AddDevice -DeviceVidPid VID_1234&PID_5678" -ForegroundColor White
    Write-Host "    .\AutoLockdown.ps1 -ShowStatus" -ForegroundColor White
    Write-Host ""
    Write-Host "  Emergency Bypass:" -ForegroundColor Yellow
    Write-Host "    Create file: C:\ProgramData\AutoLockdown\EMERGENCY_BYPASS" -ForegroundColor Gray
    Write-Host "    Disables enforcement for 30 minutes" -ForegroundColor Gray
    Write-Host ""
    Write-Host "============================================================================" -ForegroundColor Cyan
}
