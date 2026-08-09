# soc-triage-tool

A browser-based first-pass triage assistant for SOC alerts. Paste a raw log line or alert — syslog, Windows Event Log, Suricata JSON, Zeek/Bro, CEF, DNS query log, or plain English — and it identifies the format, scores severity, maps the activity to MITRE ATT&CK, pulls out IOCs, and recommends a next action.

**[Live demo →](https://nicky-quist.github.io/soc-triage-tool/)**

## Why

Most of the "paste your alert into a chatbot" tools ship the alert to a third-party API. This one doesn't — every analysis runs through a rule-based engine in the browser, so nothing leaves the tab and there's no key or backend to configure. It trades LLM-style flexibility for deterministic, explainable output: every verdict traces back to a specific pattern match, not a black box.

## What it does

- **Format detection** — recognizes Syslog, Windows Event Log (Sysmon/Security), Suricata/eve.log JSON, Zeek `conn.log`-style TSV, CEF, DNS query logs, and free-form narrative
- **Severity scoring** — Critical / High / Medium / Low / Informational, with a confidence percentage
- **MITRE ATT&CK mapping** — tactic + technique (e.g. `T1110.001 - Brute Force: Password Guessing`, `T1059.001 - PowerShell`)
- **IOC extraction** — IPs, usernames, hostnames, and command lines pulled straight out of the input
- **Recommended action** — a concrete next step (block an IP, isolate a host, rotate credentials), not just a label
- **False-positive likelihood** — flags low-signal alerts instead of crying wolf
- **Input validation** — rejects inputs that don't have enough context to triage (URL-only, base64-only, too short) and explains why, instead of guessing
- **History + export** — keeps a session log of prior analyses and exports any result as a `.txt` report

### Detection logic covers

| Format | Example patterns detected |
|---|---|
| Syslog | SSH brute force (root/admin targeting, failure count), sudo/su privilege escalation |
| Windows Event Log | Malicious PowerShell (download cradles, `-EncodedCommand`), failed logons (4625), lateral movement, persistence via Run keys / scheduled tasks |
| Suricata / eve.log | Signature severity, category, C2/malware alerts |
| Zeek `conn.log` | Long-duration, low-variance connections consistent with beaconing |
| CEF | Vendor threat/block actions (Palo Alto, ArcSight-style exports) |
| DNS logs | High-entropy subdomains, base64-looking queries, exfil indicators |

## Stack

React 19 + Vite, no backend, no API key, no dependencies beyond React itself. Deployed to GitHub Pages via GitHub Actions on every push to `main`.

## Running locally

```bash
npm install
npm run dev
```

```bash
npm run build     # production build to dist/
npm run preview   # preview the production build
```

## Project structure

```
src/
├── SOCTriageTool.jsx   # UI + offline rule-based analysis engine
└── main.jsx            # entry point
```
