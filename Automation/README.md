# SOC Automation: Phishing EML Analyzer

## Overview
This Python script automates Stage 1 of the phishing incident response pipeline. It is designed for Security Operations Center (SOC) environments to rapidly ingest raw `.eml` files, extract critical Indicators of Compromise (IOCs), and evaluate sender authentication without detonating malicious payloads.

By automating the initial triage, this tool reduces manual header analysis time and allows analysts to immediately pivot to Stage 2 threat intelligence validation and payload extraction.

## Core Capabilities
* **Authentication & Identity Verification:** Parses `Received` chains, evaluates SPF/DKIM/DMARC alignment, and checks for sender spoofing.
* **Safe IOC Extraction:** Extracts and automatically defangs all embedded HTTP/HTTPS and `mailto:` URLs to prevent accidental execution.
* **Attachment Fingerprinting:** Identifies risky file extensions (e.g., `.iso`, `.exe`) and generates MD5, SHA-1, and SHA-256 hashes for immediate threat intelligence queries.
* **...and more:** Including automated body text extraction, embedded routing analysis, and deceptive link-text mismatch detection.

## Usage
The script relies entirely on Python's standard library and requires no external dependencies. It supports both single-file analysis and bulk directory ingestion.

**Prerequisite:** Open your terminal and ensure you are in the root directory of the project before running the script.

**Analyze a single phishing sample:**
```bash
python3 Automation/phishing_analyzer.py Samples/Phish-01.eml
```

**Analyze an entire directory of samples:**
```bash
python3 Automation/phishing_analyzer.py Samples/
```

**Output results to a master triage log:**
```bash
python3 Automation/phishing_analyzer.py Samples/ > Reports/Master_Triage_Log.txt
```

## Security Note
This tool performs **static analysis only**. It does not execute attachments, nor does it resolve or interact with any extracted web infrastructure. All network indicators are safely defanged before being printed to the terminal.