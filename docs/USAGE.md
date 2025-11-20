# WuTF Usage Guide

**Windows Update Toolkit Friend (WuTF)** is a menu-driven PowerShell script for diagnosing and repairing common Windows Update issues.

This document is aimed at:

- Systems administrators
- Operations engineers
- Anyone asked to “fix Windows Update” on a server or workstation

It assumes you are comfortable with:

- Running PowerShell as an administrator  
- Taking a VM snapshot or backup before invasive changes  

---

## 1. Getting started

### 1.1 Files

The toolkit consists primarily of a single script:

- `WuTF.ps1` – the main menu-driven tool

Place it somewhere sensible, for example:

```text
C:\Tools\WuTF\WuTF.ps1
```

### 1.2 Launching the toolkit

From an elevated PowerShell session:

```powershell
cd C:\Tools\WuTF
.\WuTF.ps1
```

If you forget to run as administrator, the script will try to re-launch itself with:

- `-ExecutionPolicy Bypass`
- `-Verb RunAs` (UAC prompt)

It does **not** change the machine-wide execution policy.

### 1.3 First screen

On start, WuTF shows a banner similar to:

```text
================ Windows Update Toolkit Friend ================
Computer Name     : SERVER01
OS Version        : 10.0.17763 (Build 17763)
Edition           : ServerStandard
Update Source     : WSUS
Log File          : C:\Users\admin\Desktop\WindowsUpdateToolkit_Log_2025-10-14_201530.txt
Maintenance Time  : 04:00 (local)
===============================================================
  1.  Clear Windows Update cache
  2.  Disable WSUS (switch to Microsoft Update)
  ...
 26.  Exit Toolkit Friend
================================================================
Select an option (1-26):
```

Each action writes to the log file shown on the banner.

---

## 2. Logging

WuTF writes a text log for each run:

- Primary location: the current user’s **Desktop**
- Fallback: `%TEMP%` if the Desktop path cannot be resolved

File naming pattern:

```text
WindowsUpdateToolkit_Log_yyyy-MM-dd_HHmmss.txt
```

Everything of interest is logged, including:

- Each operation selected from the menu
- Commands run (SFC, DISM, WSUS changes, etc.)
- Service restart attempts and outcomes
- Any errors caught inside the script where possible

If you hit an unexpected error, the log is the first place to look.

---

## 3. Configuration

WuTF has a single configuration block at the top of the script:

```powershell
$ToolkitConfig = [ordered]@{
    VerboseLogging = $true    # log in detail or keep it quieter

    WsusServerName  = 'my.wsus.server.contoso.com'
    WsusTargetGroup = ''
    WsusUseSsl      = $false  # http or https

    Maintenance = [ordered]@{
        WindowStart        = '03:30'
        WindowEnd          = '04:30'
        DefaultRebootTime  = '04:00'
        JitterMinutes      = 0
        OnlyIfRebootNeeded = $true
        TaskPath           = '\WindowsUpdateToolkitFriend\Reboots\'
        TaskPrefix         = 'WindowsUpdateToolkitFriend-Reboot'
    }
}
```

### 3.1 Logging

- `VerboseLogging = $true`  
  - Writes detailed output to the log file
  - The main console view remains relatively clean

If you prefer minimal logs, set it to `$false`. The script will still log high-level actions.

### 3.2 WSUS settings

Used by **Enable WSUS**:

- `WsusServerName` – hostname of your WSUS server  
  e.g. `my.wsus.server.contoso.com`
- `WsusUseSsl` – set to `$true` if your WSUS uses HTTPS
- `WsusTargetGroup` – optional; sets the TargetGroup registry value

If `WsusServerName` is left empty, WuTF will still set `UseWUServer = 1` but will not stamp WUServer/WUStatusServer URLs.

### 3.3 Maintenance window

Used by **Schedule reboot for maintenance window**:

- `WindowStart` / `WindowEnd` – defines the acceptable window  
  e.g. `03:30` to `04:30`
- `DefaultRebootTime` – the time WuTF aims for by default  
  e.g. `04:00`
- `JitterMinutes` – random offset applied to the scheduled reboot (±N minutes)  
  - `0` disables jitter
- `OnlyIfRebootNeeded` – when `true`, WuTF will only schedule a reboot if a reboot is actually pending  
- `TaskPath` / `TaskPrefix` – define where and how reboot scheduled tasks are named

Adjust these to align with your change windows, then save the script.

---

## 4. Menu reference

### 4.1 Core tools

These are the day-to-day options most people will use.

**1. Clear Windows Update cache**

- Stops `wuauserv` and `bits`
- Deletes contents of `%windir%\SoftwareDistribution`
- Restarts `wuauserv` and `bits`
- Logs the number of items queued for deletion

Useful when:

- Updates are stuck “downloading” or “installing”
- The SoftwareDistribution folder has grown large over time

**2. Disable WSUS (switch to Microsoft Update)**

- Sets `UseWUServer = 0` under:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
- Restarts `wuauserv`
- Logs the previous value and the effective source afterwards

Useful for testing whether a failure is WSUS-specific.

**3. Enable WSUS**

- Ensures the following keys exist:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU`
- Sets:
  - `UseWUServer = 1`
  - `WUServer` / `WUStatusServer` if `WsusServerName` is configured
  - `TargetGroup` if `WsusTargetGroup` is configured
- Restarts `wuauserv`

Use this to move a machine back under WSUS control after testing on Microsoft Update.

**4. Run SFC scan**

Runs:

```powershell
sfc /scannow
```

The toolkit:

- Suppresses the noisy percentage progress lines in the console
- Logs the full output

The console warns that the operation can be slow and appear idle.

**5. Run DISM /ScanHealth**

Runs:

```powershell
DISM /Online /Cleanup-Image /ScanHealth
```

Progress bar lines are suppressed to keep the log readable. This is a read-only integrity check.

**6. Run DISM /RestoreHealth**

Runs:

```powershell
DISM /Online /Cleanup-Image /RestoreHealth
```

Attempts to repair detected component store corruption.

As with all DISM operations, allow plenty of time.

**7. Trigger Windows Update scan**

Runs:

```powershell
UsoClient StartScan
```

WuTF records:

- Last detect timestamp before the command
- Last detect timestamp afterwards (if updated)

Useful for checking that the Windows Update engine is responding.

**8. Restart Windows Update services**

Restarts:

- `wuauserv`
- `bits`

Each service restart is logged, along with whether it reached `Running` within the timeout.

**9. Show current update source**

Simply reports:

- `WSUS` or `Microsoft Update`

Based on the usual `UseWUServer` registry value.

**10. Open CBS.log**

Opens:

```text
%windir%\Logs\CBS\CBS.log
```

in Notepad if present.

**11. Open DISM.log**

Opens:

```text
%windir%\Logs\DISM\dism.log
```

in Notepad if present.

**12. Export WindowsUpdate.log**

Runs:

```powershell
Get-WindowsUpdateLog -LogPath <Desktop>\WindowsUpdate.log
```

Notes:

- This can take a while
- The script logs the file size on completion

**13. Open WindowsUpdate.log**

Opens `WindowsUpdate.log` from the Desktop (if already exported).

**14. Remove pending updates**

Performs a more aggressive clean-up:

- Stops `wuauserv`, `bits` and `trustedinstaller`
- Deletes `%windir%\WinSxS\pending.xml` if present
- Clears `%windir%\SoftwareDistribution\Download`
- Removes the `RebootPending` registry key under:
  - `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing`
- Restarts the stopped services

This is more invasive than clearing the cache alone. Treat as a “last resort before snapshot revert” option.

---

### 4.2 Diagnostics

**15. Show CU / SSU / UBR status (read-only)**

Collects and presents:

- OS version
- Registry UBR
- Latest `Package_for_RollupFix` (LCU) from DISM
- Latest `Package_for_ServicingStack_*` (SSU), if present
- Derived effective build from the LCU identity
- Reboot pending status
- Last detect and install times from the Windows Update results keys
- Update source
- DISM parsing time in seconds

It also prints advisories if:

- The registry UBR differs from the LCU’s UBR
- No SSU package can be found in DISM output
- SSU level appears significantly older than the LCU
- Detect/install times are missing

No changes are made – this is purely a reporting panel.

**16. Export CU / SSU CSV (this device)**

Writes a CSV to the Desktop containing the same CU/SSU information as the panel.

Typical use:

- Collect evidence for a specific host
- Feed into a broader inventory or spreadsheet

**17. Show Health Summary (read-only)**

Shows:

- Update source (WSUS vs Microsoft Update)
- State of key services:
  - `wuauserv`, `bits`, `dosvc`, `waasmedicsvc`, `cryptsvc`, `trustedinstaller`
- WinHTTP proxy configuration
- Free space on C:
- Reboot pending flag

Useful as a quick “sanity check” before doing anything more invasive.

**18. Show Servicing Snapshot**

Reports:

- Latest Servicing Stack mention from:

  ```powershell
  DISM /Online /Get-Packages /English | findstr /i ServicingStack
  ```

- How many staged packages are reported by:

  ```powershell
  Get-WindowsPackage -Online | Where-Object { $_.PackageState -eq 'Staged' }
  ```

This is intended as a quick “what does servicing look like?” view before you consider more aggressive options.

---

### 4.3 Reboot scheduling

**19. Schedule reboot for maintenance window**

- Calculates the next `DefaultRebootTime` (e.g. 04:00 today or tomorrow)
- Applies jitter if configured
- Warns if the resulting time falls outside `WindowStart` / `WindowEnd`
- If `OnlyIfRebootNeeded` is `true`, checks for a pending reboot:
  - If none is pending, it will not schedule unless you adjust the config

Creates a scheduled task:

- Under the configured `TaskPath` (defaults to `\WindowsUpdateToolkitFriend\Reboots\`)
- Named using `TaskPrefix`, machine name and datetime

The task runs:

```text
shutdown.exe /r /t 120 /c "<reason>"
```

**20. List Windows Update Toolkit Friend reboot tasks**

Shows any tasks under the toolkit’s task path:

- TaskName
- State
- LastRunTime
- NextRunTime

**21. Cancel a Windows Update Toolkit Friend reboot task**

Prompts for an exact task name (as shown by option 20) and removes it.

---

### 4.4 Advanced tools (handle with care)

The remaining tools are intended for:

- Cloned VMs
- Test systems
- Situations where you already have a fallback (snapshot or full backup) and are dealing with broken servicing state.

They all include explicit confirmation prompts.

**22. Remove all staged packages (DISM)**

- Uses `Get-WindowsPackage -Online` to find packages where `PackageState -eq 'Staged'`
- For each package, runs:

  ```powershell
  Remove-WindowsPackage -Online -PackageName <name> -NoRestart
  ```

Notes:

- You must type `REMOVE` to confirm.
- Some packages may refuse to be removed; failures are logged.
- Use only when you fully understand the risk, typically with a VM snapshot taken beforehand.

**23. Backup + relax CBS\Packages ACL**

- Exports the registry branch:

  ```text
  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages
  ```

  to a `.reg` file under a `WindowsUpdateToolkit_RegistryBackups` folder on the Desktop.

- Sets the owner to `Everyone` and grants `Everyone: FullControl` on:
  - The `Packages` key
  - All subkeys

Designed to mirror the common manual “take ownership of CBS\Packages” step, but with an automatic backup beforehand.

You must type `ACLFIX` to proceed.

If in doubt, prefer the documented manual method in the registry editor with a snapshot.

**24. Reset CBS\Packages CurrentState flags**

Walks all `CBS\Packages` subkeys and:

- Reads the `CurrentState` value
- For specific problematic values (e.g. `0x50`, `0x40`, `0x60`, `0x5`, `0x65`), sets `CurrentState` to `0`

You must type `CURRENTSTATE` to proceed.

This is a “last resort” option when dealing with broken package states under guidance. Always ensure you have:

- A current backup or snapshot
- A clear plan to revert if the outcome is not as expected

---

### 4.5 Help

**25. Open README / Help**

Opens `USAGE.md` (this file) in Notepad if it is located next to the script.

Use this on a jump box or remote session when you need to remind yourself what each option does or in what order to run them.

**26. Exit Toolkit Friend**

Closes the menu loop and exits the script.

---

## 5. Suggested workflows

### 5.1 General “Windows Update is stuck” on a server

A common run-through might look like:

1. Run WuTF.
2. Check **Health Summary** (17).
3. Check **CU / SSU / UBR status** (15) to see where the OS thinks it is.
4. If appropriate, **Disable WSUS** (2) and test against Microsoft Update.
5. **Clear Windows Update cache** (1).
6. **Trigger Windows Update scan** (7).
7. If the update completes but a reboot is required, **Schedule reboot in maintenance window** (19).

Take a fresh log each time and attach it to any ticket.

### 5.2 Component store issues

When DISM or SFC reports corruption:

1. Run **SFC** (4).
2. Run **DISM /ScanHealth** (5).
3. Run **DISM /RestoreHealth** (6).

Only move towards **Remove pending updates** (14) or the advanced tools once you’re convinced normal servicing is not progressing.

---

## 6. Troubleshooting

### 6.1 Script won’t start

- Ensure you’re launching from a local path, not directly from an untrusted network share.
- If the file is blocked, run:

  ```powershell
  Unblock-File .\WuTF.ps1
  ```

- Run from an elevated PowerShell session if the auto-elevation fails.

### 6.2 Scheduled reboot task not created

Check the log:

- Look for lines beginning with `Failed to schedule reboot`.
- Common causes:
  - Insufficient rights to register scheduled tasks
  - Group policy restrictions on scheduled tasks
  - An unusual security context for the current user

You can always schedule manually if needed, but the log should indicate why the automated attempt failed.

### 6.3 WSUS changes don’t stick

If options 2 or 3 appear to run but the client doesn’t behave as expected:

- Check for other tools or GPOs overwriting:
  - `HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate`
- Use `gpresult /h` on a domain-joined machine to confirm linked policies.

### 6.4 DISM or SFC appear “stuck”

Both tools can pause for long periods without updating the console. This is normal. Unless they are clearly hung for an unreasonable time (for example, many hours with no CPU or disk activity), allow them to complete.

WuTF deliberately suppresses most of the noisy percentage updates but the operations themselves are unchanged.

---

## 7. Notes and future ideas

Current behaviour:

- WuTF runs locally on the machine where you invoke it.
- It is menu-driven, with no non-interactive mode in the script at present.

It is entirely possible to:

- Wrap it in a remote PowerShell session (`Enter-PSSession`, `Invoke-Command`)
- Call individual functions programmatically if you are comfortable editing the script

For now, WuTF is intended as a hands-on tool: something you run on a console or via a jump host while you work through an update issue.

---

If you’re using WuTF in anger and find gaps in this guide, feel free to expand `USAGE.md` with additional “recipes”, screenshots, or environment-specific notes.
