# Windows Update Toolkit Friend (WuTF)

**WuTF** is a PowerShell-based toolkit for troubleshooting and maintaining Windows Update on servers and workstations.

It focuses on:

- Cleaning out stuck or corrupt Windows Update state
- Inspecting CU / SSU / UBR levels
- Scheduling controlled reboots inside a maintenance window
- Providing a small set of advanced “break glass” tools when servicing gets messy

It’s designed to be:

- Safe by default  
- Verbose in logging, quiet on screen  
- Usable directly on a console session or via a support call

---

## Why this exists

Most Windows Update issues tend to show up at awkward times:

- CUs stuck in “staged” or “pending” state  
- Reboots required but not planned  
- WSUS vs Microsoft Update misconfiguration  
- Servicing stack mismatches that don’t show up cleanly in the GUI  

WuTF gives you a single, menu-driven script that:

- Shows you what the OS thinks is installed  
- Clears common update state safely  
- Schedules reboots in a predictable way  
- Logs everything it does to a text file on the desktop  

The advanced options are there for those rare cases where you’re already in “lab VM + snapshot” territory.

---

## Key features

**Core tools**

- Clear `SoftwareDistribution` cache
- Switch between WSUS and Microsoft Update
- Run `sfc /scannow`
- Run `DISM /Online /Cleanup-Image /ScanHealth`
- Run `DISM /Online /Cleanup-Image /RestoreHealth`
- Trigger Windows Update detection (`UsoClient StartScan`)
- Restart core Windows Update services
- Export and open `WindowsUpdate.log`, `CBS.log` and `DISM.log`

**Diagnostics**

- CU / SSU / UBR panel using:
  - `DISM /Online /Get-Packages /English`
  - Registry UBR
  - Windows Update Result keys (Last Detect / Install time)
- Health summary:
  - Update source (WSUS vs Microsoft Update)
  - Key services and their state
  - WinHTTP proxy
  - C: drive free space
- Servicing snapshot:
  - Latest Servicing Stack entry from DISM
  - Summary of staged packages (via `Get-WindowsPackage` if available)

**Reboot scheduling**

- Maintenance window aware reboot scheduling:
  - Configurable start, end and default time (e.g. 03:30–04:30, default 04:00)
  - Optional jitter (±N minutes)
  - “Only schedule if reboot is actually pending” behaviour by default
- Reboot tasks created as scheduled tasks:
  - Named per machine and run time
  - Easy to list and cancel from the menu

**Advanced (opt-in, clearly marked)**

- Remove all `Staged` packages (using `Get-WindowsPackage` + `Remove-WindowsPackage`)
- Backup and relax ACLs on `CBS\Packages` (sets owner + Everyone:FullControl)
- Reset `CurrentState` on selected CBS package keys  
  *(intended only for use with snapshots and a clear rollback plan)*

---

## Requirements

WuTF is designed for:

- **PowerShell**: 5.1 (Windows PowerShell)
- **Operating systems**:
  - Windows Server 2016 and newer
  - Windows 10 / Windows 11
  - Should also function on Windows Server 2012 R2 for most features, though some advanced options may be unavailable
- **Permissions**:
  - Local administrator on the target machine

The script will:

- Detect if it’s not running elevated
- Relaunch itself with `-ExecutionPolicy Bypass` and `RunAs`  
  *(it does **not** change the machine-wide execution policy)*

---

## Quick start

1. Copy `WuTF.ps1` to a folder on the target machine (for example `C:\Tools\WuTF\`).
2. Optionally unblock the script if it was downloaded:

   ```powershell
   Unblock-File .\WuTF.ps1
   ```

3. Launch from an elevated PowerShell prompt or simply run it and let it auto-elevate:

   ```powershell
   cd C:\Tools\WuTF
   .\WuTF.ps1
   ```

4. You’ll see a menu similar to:

   ```text
   ================== Windows Update Toolkit Friend ==================
   Computer Name     : SERVER01
   OS Version        : 10.0.17763 (Build 17763)
   Edition           : ServerStandard
   Update Source     : WSUS
   Log File          : C:\Users\...\Desktop\WindowsUpdateToolkit_Log_2025-10-14_123456.txt
   Maintenance Time  : 04:00 (local)
   ==================================================================
     1.  Clear Windows Update cache
     2.  Disable WSUS (switch to Microsoft Update)
     3.  Enable WSUS
     ...
   ```

5. Choose an option using the number and follow any prompts.

---

## Configuration

At the top of the script you’ll find a single configuration block:

```powershell
$ToolkitConfig = [ordered]@{
    VerboseLogging = $true

    WsusServerName  = 'my.wsus.server.contoso.com'
    WsusTargetGroup = ''
    WsusUseSsl      = $false

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

You can safely edit:

- `VerboseLogging` – whether the script logs in detail to the log file  
- `WsusServerName`, `WsusUseSsl`, `WsusTargetGroup` – used when enabling WSUS  
- `Maintenance.*` – to match your local change window

Change these values, save the script, and re-run. No other code changes are required for normal use.

---

## Safety and scope

- The **core** menu items are intended to be safe on production machines when used sensibly.
- The **advanced** menu is for:
  - Lab VMs
  - Cloned or test systems
  - Situations where you already have a snapshot/backup and know you’re dealing with broken servicing state

Every advanced option prompts clearly before doing anything.

If in doubt, don’t run the advanced options on a live, irreplaceable server.

---

## Documentation

Operational use is documented in **USAGE.md**:

- Detailed option walkthrough
- Suggested workflows
- Logging and troubleshooting
- Notes on the advanced menu

For day-to-day operations, start there:

> See **USAGE.md** for full usage details.

---

## Status and contributions

WuTF is very much a practical toolkit rather than a polished framework.

If you’re using it and spot:

- Additional checks that would be useful
- Safer defaults for particular environments
- Bugs in the logging or scheduling behaviour

feel free to open an issue or suggest improvements.

---

## Licence

                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work.

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute
      the Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and do
          not modify the License. You may add Your own attribution notices
          within Derivative Works that You distribute, alongside or as an
          addendum to the NOTICE text from the Work, provided that such
          additional attribution notices cannot be construed as modifying
          the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of Your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

