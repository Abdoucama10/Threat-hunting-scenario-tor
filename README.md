<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Abdoucama10/Threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md) 

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

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-08-13T18:21:35.8270353Z`. These events began at `2025-08-13T17:50:41.7934455Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where FileName startswith "tor"
| where DeviceName == "rgaucho"
| where Timestamp >= datetime(2025-08-13T17:50:41.7934455Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA1, Account = InitiatingProcessAccountName

```
<img width="926" height="255" alt="image" src="https://github.com/user-attachments/assets/94bbb77a-917b-4ce3-b43d-b606df5579bd" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.5.5.exe". Based on the logs returned, at `2025-08-13T17:55:07.9485569Z`, an employee on the "rgaucho" device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "rgaucho"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1137" height="100" alt="image" src="https://github.com/user-attachments/assets/6d5e52d4-2af3-44e1-adaf-4d32065e2cd3" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "rgaucho" actually opened the TOR browser. There was evidence that he did open it at `2025-08-13T17:56:31.6210735Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "rgaucho"
| where FileName has_any("tor.exe","firefox.exe","tor-browser.exe")
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1177" height="303" alt="image" src="https://github.com/user-attachments/assets/c5e996dd-0c39-47d2-84d1-25e59cfe6590" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-08-13T17:57:24.9168124Z`, an employee on the "rgaucho" device successfully established a connection to the remote IP address `148.251.85.195` on port `9030`. The connection was initiated by the process `tor.exe`, located in the folder `c:\Users\rgaucho\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "rgaucho"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe") 
| where RemotePort in (9001,9030,9050,9051,9150,9151)
| project Timestamp, DeviceName, ActionType, RemoteIP, RemotePort, InitiatingProcessFileName
```
<img width="1171" height="270" alt="image" src="https://github.com/user-attachments/assets/70ab821a-8588-4266-904a-1eda8afa36fe" />


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-13T17:50:41.7934455Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.5.5.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\rgaucho\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-13T17:55:07.9485569Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.5.5.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.5.5.exe /S`
- **File Path:** `C:\Users\rgaucho\Downloads\tor-browser-windows-x86_64-portable-14.5.5.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-13T17:56:31.6210735Z`
- **Event:** User "rgaucho" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\rgaucho\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-13T17:57:23.5496352Z`
- **Event:** A network connection to IP `86.2.246.205` on port `9001` by user "rgaucho" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `C:\Users\rgaucho\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-08-13T17:57:23.5480274Z` - Connected to `157.90.92.115` on port `9001`.
  - `2025-08-13T17:56:40.7198008Z` - Local connection to `127.0.0.1` on port `9151`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-08-13T18:21:35.8270353Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\rgaucho\Desktop\tor-shopping-list.txt`

---

## Summary

The user "rgaucho" on the "rgaucho" device initiated and completed the installation of the TOR browser. He proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `rgaucho` by the user `rgaucho`. The device was isolated, and the user's direct manager was notified.

---
