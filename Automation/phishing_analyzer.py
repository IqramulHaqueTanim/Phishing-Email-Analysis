#!/usr/bin/env python3
"""
Phishing EML analyzer (static analysis only - it never opens links or runs attachments).

Usage:
    python phishing_analyzer.py file.eml             # one file
    python phishing_analyzer.py a.eml b.eml c.eml    # several files, one after another
    python phishing_analyzer.py ~/samples/           # every .eml in a folder
    python phishing_analyzer.py <URL>                # a raw .eml URL
"""

import email                                    # Python's standard library for parsing email messages
from email import policy                        # "policy.default" gives modern parsing (auto-decodes headers)
from email.utils import parseaddr, getaddresses # helpers to split 'Name <addr@domain>' into name + address
import urllib.request                           # used to download the .eml file from a URL
import hashlib                                  # used to compute MD5 / SHA1 / SHA256 file fingerprints
import re                                       # regular expressions for pattern matching
import sys                                      # lets us read command-line arguments
import os                                       # file / folder checks (is this path a file or a directory?)
import glob                                     # finds all *.eml files inside a folder
from html.parser import HTMLParser              # used to walk through HTML and pull out <a href> links
from urllib.parse import urlparse               # splits a URL into scheme, domain, path, etc.

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# File extensions that are commonly used to deliver malware. Used to flag attachments.
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".jse", ".vbs", ".vbe", ".wsf",
    ".ps1", ".jar", ".lnk", ".iso", ".img", ".html", ".htm", ".hta", ".docm",
    ".xlsm", ".pptm", ".zip", ".rar", ".7z", ".one", ".svg",
}

# Regex that finds http/https URLs. It stops at whitespace, quotes, and brackets.
URL_RE = re.compile(r'https?://[^\s<>"\'\]\[()]+', re.IGNORECASE)

# Regex that finds mailto: links.
MAILTO_RE = re.compile(r'mailto:[^\s<>"\'\]\[()]+', re.IGNORECASE)

# Regex that finds IPv4 addresses (used on the Received headers).
IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


# ---------------------------------------------------------------------------
# Small helper functions
# ---------------------------------------------------------------------------

def defang(text):
    """Make a URL/IP unclickable so you can't open it by accident when copying from the terminal."""
    text = text.replace("http", "hxxp")   # http -> hxxp (also turns https -> hxxps)
    text = text.replace(".", "[.]")       # example.com -> example[.]com
    return text                           # return the safe version


def domain_of(address):
    """Return the domain part of an email address ('bob@evil.com' -> 'evil.com')."""
    if "@" in address:                            # only if it really looks like an address
        return address.rsplit("@", 1)[1].lower().strip(">")  # take text after the last '@', lowercase it
    return ""                                     # otherwise there is no domain


def fetch_eml(source):
    """Load raw email bytes from a URL (http/https) or from a local file path."""
    if source.lower().startswith(("http://", "https://")):          # is the source a web URL?
        req = urllib.request.Request(source, headers={"User-Agent": "Mozilla/5.0"})  # pretend to be a browser
        with urllib.request.urlopen(req, timeout=30) as resp:       # download; give up after 30 seconds
            return resp.read()                                      # return the raw bytes of the file
    with open(source, "rb") as f:                                   # otherwise treat it as a local file
        return f.read()                                             # return its raw bytes


class LinkParser(HTMLParser):
    """Walks through HTML and records every link as (real_href, visible_text)."""

    def __init__(self):
        super().__init__()          # initialise the parent HTMLParser
        self.links = []             # final list of (href, text) tuples
        self._current_href = None   # href of the <a> tag we are currently inside
        self._current_text = []     # pieces of visible text inside that <a> tag

    def handle_starttag(self, tag, attrs):
        if tag == "a":                                  # we only care about anchor tags
            self._current_href = dict(attrs).get("href")  # grab the href="..." value (None if missing)
            self._current_text = []                     # reset the visible-text buffer

    def handle_data(self, data):
        if self._current_href is not None:              # only collect text while inside an <a> tag
            self._current_text.append(data)             # store the visible text fragment

    def handle_endtag(self, tag):
        if tag == "a" and self._current_href is not None:           # leaving an <a> tag
            text = " ".join("".join(self._current_text).split())    # join + collapse whitespace
            self.links.append((self._current_href.strip(), text))   # save the (href, visible text) pair
            self._current_href = None                               # we are no longer inside a link


# ---------------------------------------------------------------------------
# Main analysis
# ---------------------------------------------------------------------------

def analyze_eml(source):
    print("=" * 70)                                   # visual separator
    print(" PHISHING EMAIL ANALYSIS")
    print("=" * 70)

    # 1. LOAD + PARSE ------------------------------------------------------
    try:
        raw_bytes = fetch_eml(source)                 # get the raw bytes (URL or file)
    except Exception as e:                            # network error, file not found, etc.
        print(f"Error loading file: {e}")
        return                                        # nothing more we can do

    # policy.default -> headers are returned already decoded (e.g. "=?UTF-8?B?...?=" becomes readable text)
    msg = email.message_from_bytes(raw_bytes, policy=policy.default)

    # 2. CORE HEADERS ------------------------------------------------------
    print("\n[+] Core Headers")
    for name in ("Subject", "From", "To", "Cc", "Date", "Message-ID", "Reply-To", "Return-Path"):
        print(f"{name + ':':<13} {msg.get(name, 'None')}")   # print header or 'None' if absent
    for name in ("X-Originating-IP", "X-Mailer", "User-Agent", "X-Sender-IP"):
        if msg.get(name):                                    # optional headers: show only when present
            print(f"{name + ':':<13} {msg.get(name)}")

    # 3. SENDER IDENTITY CHECKS (spoofing indicators) ----------------------
    print("\n[+] Sender Consistency Checks")
    from_name, from_addr = parseaddr(str(msg.get("From", "")))               # split display name / address
    _, reply_addr = parseaddr(str(msg.get("Reply-To", "")))                  # address in Reply-To
    _, return_addr = parseaddr(str(msg.get("Return-Path", "")))              # envelope sender (bounce address)
    from_dom, reply_dom, return_dom = domain_of(from_addr), domain_of(reply_addr), domain_of(return_addr)
    print(f"From domain:        {from_dom or 'None'}")
    print(f"Reply-To domain:    {reply_dom or 'None'}")
    print(f"Return-Path domain: {return_dom or 'None'}")
    if reply_dom and reply_dom != from_dom:                                  # replies go somewhere else?
        print("  [!] Reply-To domain differs from From domain (common phishing trick)")
    if return_dom and return_dom != from_dom:                                # envelope sender differs?
        print("  [!] Return-Path domain differs from From domain (possible spoofing / third-party sender)")
    if "@" in from_name:                                                     # display name looks like an address
        print("  [!] Display name contains an email address (display-name spoofing)")

    # 4. AUTHENTICATION (SPF / DKIM / DMARC) -------------------------------
    print("\n[+] Email Authentication Results")
    auth_headers = [str(h) for h in msg.get_all("Authentication-Results", [])]   # all auth result headers
    received_spf = [str(h) for h in msg.get_all("Received-SPF", [])]             # older/alternate SPF header
    auth_text = "\n".join(auth_headers + received_spf)                           # join into one searchable string

    if auth_text:
        # Each regex captures the result word after "spf=", "dkim=", "dmarc="
        spf = re.search(r'\bspf=(pass|fail|softfail|neutral|none|temperror|permerror)\b', auth_text, re.I)
        dkim = re.search(r'\bdkim=(pass|fail|neutral|none|policy|temperror|permerror)\b', auth_text, re.I)
        dmarc = re.search(r'\bdmarc=(pass|fail|bestguesspass|none|temperror|permerror)\b', auth_text, re.I)
        if not spf and received_spf:                                             # fall back to Received-SPF
            spf = re.match(r'\s*(pass|fail|softfail|neutral|none|temperror|permerror)', received_spf[0], re.I)
        print(f"SPF:   {spf.group(1) if spf else 'Not found'}")
        print(f"DKIM:  {dkim.group(1) if dkim else 'Not found'}")
        print(f"DMARC: {dmarc.group(1) if dmarc else 'Not found'}")
        print("\n  Raw Authentication-Results:")
        for h in auth_headers + received_spf:
            print("  " + " ".join(h.split()))                                      # print on a single line
        print("  (Note: only trust headers added by YOUR receiving mail server, usually the topmost.)")
    else:
        print("No Authentication-Results / Received-SPF header found.")
        print("SPF/DKIM/DMARC cannot be confirmed from this EML.")

    # 5. DKIM SIGNATURE ----------------------------------------------------
    print("\n[+] DKIM Signature")
    dkim_sigs = msg.get_all("DKIM-Signature", [])
    if dkim_sigs:
        for sig in dkim_sigs:
            sig_text = " ".join(str(sig).split())                                # flatten to one line
            d = re.search(r'\bd=([^;\s]+)', sig_text)                            # d= is the signing domain
            s = re.search(r'\bs=([^;\s]+)', sig_text)                            # s= is the selector
            print(f"Signing domain (d=): {d.group(1) if d else '?'} | selector (s=): {s.group(1) if s else '?'}")
            if d and from_dom and not (d.group(1).lower() == from_dom or from_dom.endswith("." + d.group(1).lower())
                                       or d.group(1).lower().endswith("." + from_dom)):
                print("  [!] DKIM signing domain does not align with the From domain")
            print("  " + sig_text)                                                # show the full signature
    else:
        print("No DKIM-Signature header found.")

    # 6. RECEIVED CHAIN (the path the email travelled) ---------------------
    print("\n[+] Received Chain (oldest hop first)")
    received = [" ".join(str(h).split()) for h in msg.get_all("Received", [])]   # every Received header
    if received:
        for i, hop in enumerate(reversed(received), start=1):                    # headers are newest-first, so reverse
            print(f" {i}. {hop}")
        ips = []                                                                 # collect public-looking IPs
        for hop in received:
            for ip in IPV4_RE.findall(hop):
                if not ip.startswith(("10.", "127.", "192.168.")) and ip not in ips:   # skip private ranges (simplified)
                    ips.append(ip)
        print("\n  IPv4 addresses seen (defanged):", ", ".join(defang(i) for i in ips) if ips else "None")
    else:
        print("No Received headers found.")

    # 7. BODY EXTRACTION ---------------------------------------------------
    plain_text, html_text = "", ""                                               # buffers for the two body types
    for part in msg.walk():                                                      # visit every MIME part
        if part.get_content_maintype() == "multipart":                           # containers hold no content
            continue
        if part.get_filename() or part.get_content_disposition() == "attachment":  # attachments handled later
            continue
        ctype = part.get_content_type()                                          # e.g. text/plain, text/html
        if ctype in ("text/plain", "text/html"):
            try:
                content = part.get_content()                                     # auto-decodes base64 / quoted-printable
            except Exception:                                                    # bad charset etc.
                content = (part.get_payload(decode=True) or b"").decode("utf-8", errors="ignore")
            if ctype == "text/plain":
                plain_text += content + "\n"                                     # accumulate plain text
            else:
                html_text += content + "\n"                                      # accumulate HTML

    print("\n[+] Body Preview (plain text, first 500 chars)")
    preview = plain_text.strip() or re.sub(r"<[^>]+>", " ", html_text)           # fall back to HTML with tags stripped
    print(" ".join(preview.split())[:500] or "(empty body)")

    # 8. URL / LINK EXTRACTION --------------------------------------------
    print("\n[+] URLs / Links Found")
    urls, mailtos = set(), set()                                                 # sets avoid duplicates

    # Search the DECODED body text plus the raw headers. Searching the raw email bytes alone
    # (as the original code did) misses links hidden inside base64 / quoted-printable bodies.
    header_text = "\n".join(f"{k}: {v}" for k, v in msg.items())                 # headers as text (e.g. List-Unsubscribe)
    searchable = plain_text + "\n" + html_text + "\n" + header_text
    for u in URL_RE.findall(searchable):
        urls.add(u.rstrip(".,;:!?)]}>"))                                         # strip trailing punctuation
    for m in MAILTO_RE.findall(searchable):
        mailtos.add(m.rstrip(".,;:!?)]}>"))

    # Parse the HTML to compare what the link SAYS vs where it REALLY goes
    parser = LinkParser()
    parser.feed(html_text)                                                       # run the HTML through the parser
    for href, _text in parser.links:
        if href.lower().startswith("http"):
            urls.add(href)                                                       # include real hrefs
        elif href.lower().startswith("mailto:"):
            mailtos.add(href)

    if urls:
        print("\nHTTP/HTTPS URLs (defanged):")
        for i, u in enumerate(sorted(urls), start=1):
            print(f" {i}. {defang(u)}")
    else:
        print("\nNo HTTP/HTTPS URLs found.")
    if mailtos:
        print("\nEmail Links (mailto):")
        for i, m in enumerate(sorted(mailtos), start=1):
            print(f" {i}. {m.replace('@', '[@]')}")
    else:
        print("\nNo mailto links found.")

    # 9. LINK-TEXT MISMATCH DETECTION --------------------------------------
    mismatches = []
    for href, text in parser.links:
        shown = re.search(r'(?:https?://)?([a-z0-9-]+(?:\.[a-z0-9-]+)+)', text, re.I)   # domain-like visible text
        real_host = (urlparse(href).hostname or "").lower()                              # actual destination host
        if shown and real_host and shown.group(1).lower() not in real_host:
            mismatches.append((text, href))                                              # visible text lies about target
    if mismatches:
        print("\n[!] Link text does not match real destination:")
        for text, href in mismatches:
            print(f"   shown: {defang(text)}  ->  real: {defang(href)}")

    # 10. ATTACHMENTS + HASHES ---------------------------------------------
    print("\n[+] Attachments Found")
    count = 0
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":                           # skip containers
            continue
        filename = part.get_filename()                                           # attachment name (may be None)
        is_attachment = part.get_content_disposition() in ("attachment", "inline") and filename
        if not (filename or is_attachment):                                      # not a file -> skip
            continue                                                             # (also catches files with NO Content-Disposition)
        payload = part.get_payload(decode=True)                                  # decoded file bytes
        if not payload:
            continue
        count += 1
        ext = ("." + filename.rsplit(".", 1)[-1].lower()) if filename and "." in filename else ""
        print(f" - Filename:     {filename}")
        print(f"   Content-Type: {part.get_content_type()}")
        print(f"   Size:         {len(payload)} bytes")
        print(f"   MD5:          {hashlib.md5(payload).hexdigest()}")            # for older threat-intel feeds
        print(f"   SHA1:         {hashlib.sha1(payload).hexdigest()}")
        print(f"   SHA256:       {hashlib.sha256(payload).hexdigest()}")         # paste into VirusTotal
        if ext in SUSPICIOUS_EXTENSIONS:
            print(f"   [!] Risky file extension: {ext}")
        if filename and filename.lower().count(".") > 1:
            print("   [!] Multiple extensions (possible double-extension trick)")
    if count == 0:
        print(" - No attachments found. (Likely a link-based or text-based lure).")

    print("\n" + "=" * 70)
    print(" Analysis complete. Verify indicators in a sandbox / VirusTotal / URLScan.")
    print("=" * 70)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def collect_targets(args):
    """Turn the command-line arguments into a flat list of .eml files / URLs to analyze."""
    targets = []                                            # final list of things to analyze
    for arg in args:                                        # go through every argument the user typed
        if arg.lower().startswith(("http://", "https://")): # a URL -> use it as is
            targets.append(arg)
        elif os.path.isdir(arg):                            # a folder -> take every .eml inside it
            targets.extend(sorted(glob.glob(os.path.join(arg, "*.eml"))))
        elif os.path.isfile(arg):                           # a single file -> use it
            targets.append(arg)
        else:                                               # anything else (typo, missing file)
            print(f"[!] Skipping '{arg}': not a file, folder or URL")
    return targets


if __name__ == "__main__":
    # Ignore flags that Jupyter/Colab inject (e.g. "-f kernel.json") so notebooks don't crash.
    # Real file paths never start with "-" and the kernel.json path follows "-f", so drop both.
    raw_args = sys.argv[1:]
    if "-f" in raw_args:                                    # Colab/Jupyter kernel launch detected
        raw_args = []                                       # ignore everything it injected
    targets = collect_targets(raw_args)

    if not targets:                                         # nothing valid was given -> show help, don't guess
        print("Usage: python phishing_analyzer.py <file.eml | folder | URL> [more files ...]")
        print("Examples:")
        print("  python phishing_analyzer.py suspicious.eml")
        print("  python phishing_analyzer.py a.eml b.eml c.eml")
        print("  python phishing_analyzer.py ~/samples/            # every .eml in the folder")
        print("  python phishing_analyzer.py ~/samples/*.eml > report.txt")
        sys.exit(1)                                         # non-zero exit code = "something was wrong"

    for target in targets:                                  # analyze each email one after another
        print(f"\n\n##### FILE: {target} #####")            # header so you can tell reports apart
        analyze_eml(target)
