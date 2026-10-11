# Incident Report: Phishing & Andromeda Trojan Analysis (IR-2020-001)

## Executive Summary
This report details the technical analysis of a malicious email masquerading as a wire transfer document. Initial automated triage using a custom Python script identified spoofed sender infrastructure and a suspicious `.iso` container. Manual forensic extraction via CyberChef bypassed the email's evasion layers, revealing an embedded PE32 executable. Threat intelligence validation confirmed the payload as a variant of the Andromeda (Androm/Ejzz) Trojan. 

---

## 1. Initial Triage & Infrastructure Analysis

Automated header analysis was conducted to establish the origin and authenticity of the email. 

* **Spoofing Detected:** The email claimed to originate from `moss.it`, but authentication checks resulted in a hard SPF failure.
* **Originating IP:** `213[.]227[.]154[.]65` (LeaseWeb Netherlands B.V., AS 60781). This suggests the use of a compromised hosting server or open relay to bypass static IP blacklists.

![Email Authentication Analysis](../../images/P01-IOC-1.png)
*Figure 1: Custom Python script output detailing SPF failure and spoofed domain.*

The script successfully parsed the MIME boundaries and isolated the attached container without detonating the payload.

![Attachment Parsing](../images/P01-IOC-2.png)
*Figure 2: Script output fingerprinting the malicious quotation.iso attachment.*

---

## 2. Container Analysis (Surface Level)

The attachment was delivered as an ISO 9660 disk image (`quotation.iso`). Attackers frequently use `.iso` files to bypass Mark-of-the-Web (MotW) protections in Windows environments. 

* **Container Hash (SHA-256):** `75fdb848eac332b4ca7d88f497e7ba7ebbb9a798d825b28cf1f87b9d7149e87f`
* **Threat Intelligence:** A scan of the container hash returned a 40/61 detection rate, confirming the outer layer as malicious.

![VirusTotal ISO Scan](../images/P01-IOC-3.png)
*Figure 3: VirusTotal detection confirming the .iso container is weaponized.*

---

## 3. Payload Extraction & Deobfuscation

To safely isolate the true payload, manual deobfuscation was performed using CyberChef. The raw email file (`.eml`) was parsed to extract the Base64-encoded attachment block. 

A targeted recipe (`From Base64` -> `Extract Files`) was applied to decode the text, virtually mount the ISO, and filter out decoy files (such as `.mp3` and `.bmp` artifacts), leaving only the primary executable.

![CyberChef Extraction](../images/P01-IOC-4.png)
*Figure 4: CyberChef file carving isolating the embedded executable.*

---

## 4. Threat Intelligence & Payload Analysis

The extracted binary (`extracted_at_0xf000.exe`) was analyzed to determine its capabilities and threat classification. 

* **Target Filename:** `TRAPFALL.exe`
* **File Size:** 52.00 KB (53,248 bytes)
* **Architecture:** PE32 executable (GUI) for Intel 386 / Win32
* **Compiler:** Microsoft Visual Basic v5.0/v6.0
* **Compilation Timestamp:** `2004-12-23 21:25:56 UTC`. *Note: This legacy timestamp indicates either deliberate timestomping to evade heuristic detection or the use of an outdated malware builder.*

![VirusTotal Payload Scan](../images/P01-IOC-5.png)
*Figure 5: VirusTotal scan of the extracted binary confirming the Andromeda Trojan.*

---

## 5. Indicators of Compromise (IOCs)

**File Hashes (SHA-256)**
* `quotation.iso` (Container): `75fdb848eac332b4ca7d88f497e7ba7ebbb9a798d825b28cf1f87b9d7149e87f`
* `TRAPFALL.exe` (Payload): `f74d3364ef9d3e3df4173a7f12d48348af44bf150c0ffcd01f0054e86ebb7e0e`

**Network Infrastructure (Defanged)**
* Originating IP: `213[.]227[.]154[.]65`
* Command & Control (C2): `hxxp://solouro[.]cf/makave/sab[.]php`
* Secondary Download/Abuse: `hxxps://onedrive[.]live[.]com/download?...`

---

## 6. MITRE ATT&CK Mapping

Based on behavioral sandbox execution, the payload exhibits the following tactics:
* **T1055 (Process Injection):** Executes process hollowing to inject malicious code into legitimate Windows processes.
* **T1497 (Virtualization/Sandbox Evasion):** Utilizes sleep loops and debug environment checks to avoid detonating inside analysis sandboxes.
* **T1143 (Hidden Window):** Executes with a hidden window to remain invisible to the end-user.
* **T1082 (System Information Discovery):** Conducts WMI queries to map the victim system architecture.
