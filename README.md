# Phishing Email Triage & Threat Intelligence Portfolio

## Project Objective
This repository serves as a practical demonstration of Security Operations Center (SOC) triage, email header forensics, and threat intelligence pivoting. The portfolio consists of five real-world phishing incidents analyzed from raw `.eml` files to final executive reports. It highlights my ability to manually investigate advanced evasion tactics, analyze malicious infrastructure, and communicate findings clearly to both technical and non-technical stakeholders.

## Tools & Technologies Used
* **Automation & Scripting:** Python 3 (`phishing_analyzer.py` custom extraction script), Linux CLI
* **Platform Triage:** PhishTool, AnyRun
* **Threat Intelligence & OSINT:** VirusTotal, URLScan.io
* **Blockchain Forensics:** Blockchain.com Explorer

---

## Portfolio Scenarios

**Case 01: Malware Delivery & Attachment Triage**
* **Focus:** Standard SOC email triage workflow with malicious payloads.
* **Skills:** Analyzing malicious file attachments (`quotation.iso`), manual extraction of MIME parts, and identification of spoofed display names versus envelope senders. 

**Case 02: Netflix Impersonation & Payload Obfuscation**
* **Focus:** Brand impersonation and malicious redirect analysis.
* **Skills:** Utilizing URLScan.io to capture dead drops, identifying compromised sender domains, and mapping attacker infrastructure used to harvest streaming credentials.

**Case 03: Binance Impersonation & Cloud Infrastructure Abuse**
* **Focus:** Bypassing security filters via trusted platforms.
* **Skills:** Investigating Amazon SES email routing, identifying AWS S3 bucket abuse for payload hosting, and explaining why malicious links return clean scores on traditional antivirus scanners.

**Case 04: Sextortion, Credential Stuffing & Blockchain Tracking**
* **Focus:** Fear-based social engineering and cryptocurrency extortion.
* **Skills:** Utilizing PhishTool for GUI triage, identifying self-spoofing tactics, recognizing credential stuffing (leaked passwords), and performing blockchain ledger investigations to track successful extortion payments.

**Case 05: CAA Impersonation & Bayesian Poisoning (Hash Busting)**
* **Focus:** Evasion tactics and psychological manipulation.
* **Skills:** Analyzing fear-based lures impersonating the Canadian Automobile Association (CAA), identifying DKIM signature failures, and recognizing "Hash Busting" (invisible randomized text) used to poison AI spam filters.

---

## Methodology & Data Provenance 
*The raw `.eml` artifacts analyzed in this portfolio were sourced from a sanitized honeypot repository. To ensure data privacy, the original recipient addresses were scrubbed and replaced with the `phishing@pot` placeholder prior to analysis. This sanitization does not affect the integrity of the attacker infrastructure, payload routing, or header forensics detailed in these reports.*

---

## Key SOC Skills Demonstrated
* **Forensic Header Analysis:** Parsing `Received` chains, identifying `Return-Path` anomalies, and evaluating SPF, DKIM, and DMARC failures.
* **Defense Evasion Recognition:** Spotting advanced attacker tactics including cloud infrastructure abuse, hash busting, and self-spoofing.
* **Threat Intelligence Pivoting:** Moving beyond simple link scanners to investigate underlying IP ownership, CDN abuse, and cryptocurrency movement.
* **Executive Reporting:** Translating technical forensic data into clear, actionable business intelligence mapped to the MITRE ATT&CK framework.
