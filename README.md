<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://docs.google.com/document/d/1gdAdV0vCQR3jxjWiuLNfVDi4hJtbukwMJYvajzVRtZ8/edit?tab=t.0)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceEventsTable for ANY ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.5.exe". Based on the logs returned , at 2026-02-15T02:09:59.5491633Z , the user mk triggered a silent installation of the Tor Browser (version 15.0.5) on device mk-thrt-hntg-to

**Query used to locate events:**

```kql
DeviceFileEvents
|where DeviceName == "mk-thrt-hntg-to"
|where FileName contains "tor"
|where Timestamp >= datetime(2026-02-15T02:10:32.015663Z)
|order by Timestamp desc
|project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account= InitiatingProcessAccountName`

```
<img width="1166" height="346" alt="image" src="https://github.com/user-attachments/assets/53e2ad4e-185c-4161-bd6b-012e28f3d750" />
>

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceEventsTable for ANY ProcessCommandLine that contained the string "tor-browser-windows-x86_64-portable-15.0.5.exe". Based on the logs returned , at 2026-02-15T02:09:59.5491633Z , the user mk triggered a silent installation of the Tor Browser (version 15.0.5) on device mk-thrt-hntg-to.The command ran from the Downloads folder using the /S switch, which bypassed all setup windows while logging a specific SHA256 hash for the file execution.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName == "mk-thrt-hntg-to"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.5.exe"
|project Timestamp, DeviceName,AccountName, ActionType, FolderPath, SHA256, ProcessCommandLine
```
<img width="1237" height="143" alt="image" src="https://github.com/user-attachments/assets/ddf31e6c-ef11-4d40-a7b3-4a2b48ef0bf8" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the tor browser. There was evidence that the user  did open it at  2026-02-15T02:09:59.5491633Z. There were multip[le other instances of firefox.exe (Tor) that were generated afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName == "mk-thrt-hntg-to"
|where FileName has_any ("tor-browser-windows-x86_64-portable-15.0.5.exe", "tor.exe", "firefox.exe", "obfs4proxy.exe")
|project Timestamp,DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
|order by Timestamp desc 
```

<img width="1324" height="372" alt="image" src="https://github.com/user-attachments/assets/c3a7dd74-8108-4ffb-8af1-14ce2fb42ee6"/>


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports On 2026-02-15T02:15:16.2444277Z the user mk on device mk-thrt-hntg-to successfully established an outbound network connection. The core Tor process, tor.exe, running from a folder on the desktop, connected to the remote IP address 217.154.169.30 via the standard Tor relay port 9001. There were other connections to sites over port 80 and 443,


**Query used to locate events:**

```kql
   DeviceNetworkEvents
|where DeviceName == "mk-thrt-hntg-to"
|where InitiatingProcessAccountName != "system"
|where InitiatingProcessFileName in ("tor-browser-windows-x86_64-portable-15.0.5.exe", "tor.exe", "firefox.exe", "obfs4proxy.exe")
|where RemotePort in ("9001", "9030", "9050", "9150", "9051", "443", "80")
|project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
|order by Timestamp desc
```

<img width="1356" height="308" alt="image" src="https://github.com/user-attachments/assets/af050db4-7b9f-4b0c-9624-8da47875af7b" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer.

- **File Download:** - TOR Installer.
- **Timestamp:** '2026-02-15T02:10:32.015663Z'
- **Event:** The user "mk" downloaded a file named tor-browser-windows-x86_64-portable-14.0.1.exe to the Downloads folder.
- **Action:** File download detected.
- **File Path:** C:\Users\mk\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe.


### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2026-02-15T02:09:59.5491633Z`
- **Event:** The user "mk" executed the file `tor-browser-windows-x86_64-portable-15.0.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.5.exe'
- **File Path:** `C:\Users\mk\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "mk" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\mk\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-02-15T02:15:16.2444277Z`
- **Event:** A network connection to IP `127.0.0.13` on port `9150` by user "mk" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\mk\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-02-15T02:15:19.9656581Z` - Connected to `51.81.93.109` on port `443`.
  - `2026-02-15T04:07:12.6487302Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "mk" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-02-15T02:09:59.5491633Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\mk\Desktop\tor-shopping-list.txt`

---

## Summary

The investigation into the device mk-thrt-hntg-to reveals a deliberate and successful attempt to bypass standard security monitoring through the use of the Tor Browser. On February 14, 2026, the user MK performed a silent installation of a portable version of Tor, placing it in a non-standard directory (Desktop) to avoid detection.
The logs confirm active browsing sessions that utilized local proxying (port 9150) and established connections to known Tor relays (port 9001). Furthermore, the activity was not limited to a single user, as account josh1 was also observed interacting with the Tor profile data. This suggests that the device was being used as a gateway for covert, unmonitored internet access by multiple parties within the environment.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
