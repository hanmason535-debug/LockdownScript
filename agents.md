# AutoLockdown Suite - AI Engineering Guidelines & Agent Instructions

## Global Overview
AutoLockdown is a P0/Mission-Critical Enterprise USB Hardening Suite written in PowerShell 5.1 designed for Windows 11 Intel NUC machines. It enforces a strict device-allowlist policy via three distinct mechanisms:
1. **Background Scheduled Task Check** (`Protect-USBDevice` startup sweeps)
2. **Real-time WMI Polling** (`TargetInstance ISA 'Win32_PnPEntity'` event handler catching devices via driver hooks)
3. **Fast-Path Registry Watcher** (Asynchronous Runspace loop scanning `HKLM:\...\Enum\USB` every 250ms)

## 1. Architectural Rules
* **Language/Encoding**: All scripts MUST be written in PowerShell 5.1 and saved STRICTLY with **UTF-8 encoding**. 
  * Do not introduce non-ASCII characters (e.g., smart quotes `“” / ‘’`, em dashes `—`) as they will corrupt execution when ingested by restrictive local execution policies.
* **Persistent Cache Management**: 
  * Never use standard `Out-File` blindly for `.json` caches without `.bak1` staging.
  * You MUST use an iterative fallback structure for any critical JSON storage: `.json` -> `.bak1` -> `.bak2`.
  * Ensure `Import-JsonSafe` and `Export-JsonSafe` wrappers are heavily favored over raw `ConvertFrom-Json` everywhere except within isolated runspaces.
* **Logging Standards**: All log lines must include exact timestamps `[$ts]` and categorized tags (`[INFO]`, `[SUCCESS]`, `[WARNING]`, `[BLOCK]`).
* **Cryptographic Scope**: API Keys, network whitelists, or secure USB signatures MUST be encrypted via `[System.Security.Cryptography.ProtectedData]` under the `LocalMachine` scope.
* **Concurrency Locking (Race Conditions)**: Accessing shared collections or cache `.json` files across threads (like between the background WMI listener and the registry runspace) MUST be explicitly protected by globally scoped named Mutexes (`New-Object System.Threading.Mutex($false, "Global\AutoLockdown_XY")`). Always use safe deterministic closing blocks (`try { ... } finally { try { $mutex.ReleaseMutex() } catch{} finally{ $mutex.Dispose() } }`).

## 2. Test Cases & Validation Patterns
When modifying enforcement policies or deploying component updates, automatically assume you must design against these test cases:
* **The "Mode-Switching" Test**: Cellular modems (e.g., JAC 5G Dongle `VID_322B`) act as composite endpoints that initially map over mass-storage to spawn entirely distinct sub-virtual devices. Ensure any changes safely honor `DEVPKEY_Device_ContainerId` caching across hotplug AND cold boot phases.
* **Event Deduplication Test**: Since the Fast-Path registry watcher queries endpoint connections significantly faster (250ms) than the WMI listener (1000ms interval), block logs will duplicate if not checked. The WMI event handler should always query the hardware `.Status` (i.e., `Error` or `Degraded`) to bypass logging an already-blocked target.
* **Trusted HID Fallback**: Ensure parsing logic accounts for `Class` AND `ClassGUID` fallbacks. Devices with unlisted classes should never accidentally masquerade as generic `HIDClass` objects (e.g., Apple iOS Image/WPD endpoints).

## 3. Known Edge Cases
* **Missing `Class` Data on Fast-Path Entry**: Windows severely delays populating `.Class` string values in the PnP Registry during the initial 50-100ms hardware sweep. The Registry Runspace must iteratively loop-sleep (e.g., 5 attempts) to await `Class` registry writes rather than firing an immediate false-positive block.
* **The "Startup-Scan" Bug Constraint**: During a hard system reboot event or the launching of the primary listener service, the `-IsStartup $true` initialization flag triggers. It intentionally skips `.Class` waiting times to prevent deadlocking system boots. If caching conditions exist, they must be validated *independently* of the `-IsStartup` conditional loop logic.
* **Silent JSON Death**: Missing catch blocks around `ConvertFrom-Json` inside WMI Action handlers will irreversibly crash the hidden background WMI process. Wrap JSON operations religiously.

## 4. Code Edits Checklist
When processing change execution tasks via AI agent locally, perform these checks:
- Do your local script variables correctly align with `$script:` scoping when passed over from isolated functions? 
- Did you update the `PATCH_CHECKLIST.md` test patterns with specific regex parameters to confirm the latest patches apply correctly?
- Did you increment build versions in `$ScriptVersion` headers and the changelog correctly?

_Written: April 2026. Ensure agents review logic securely before editing critical enforcement parameters._
