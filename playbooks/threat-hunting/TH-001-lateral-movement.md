# TH-001: Lateral Movement Detection

<div align="center">

| Field | Value |
|:---:|:---:|
| **Focus** | Network & Endpoint |
| **MITRE ATT&CK** | T1021 (Remote Services), T1076 (RDP), T1028 (WinRM), T1077 (Windows Admin Shares) |
| **Data Sources** | Microsoft Sentinel, EDR, Windows Event Logs, Zeek |
| **Last Updated** | March 2026 |
| **Author** | Ali AlEnezi (@SiteQ8) |

</div>

---

## 🎯 Objective

Proactively detect lateral movement activity within enterprise networks using hypothesis-driven hunting. Focuses on identifying attackers moving between systems after initial foothold, using both known and novel techniques.

---

## 🧠 Hunting Hypotheses

| # | Hypothesis | Data Source | Confidence |
|---|-----------|-------------|------------|
| H1 | Attackers are using pass-the-hash to move laterally | Windows Security Logs (4624 Type 3) | High |
| H2 | RDP is being used from unusual source hosts | Windows Security Logs (4624 Type 10) | High |
| H3 | WinRM/PSRemoting is being abused for remote execution | Windows Security Logs (4624 Type 3) + PowerShell logs | Medium |
| H4 | SMB admin shares (C$, ADMIN$) are being accessed anomalously | Windows Security Logs (5140, 5145) | High |
| H5 | PsExec or similar tools are creating remote services | System Event Log (7045) + Sysmon (Event 1) | High |

---

## 🔍 Hunting Queries

### H1: Pass-the-Hash Detection

```kql
// Detect NTLM authentication from unexpected sources
SecurityEvent
| where EventID == 4624
| where LogonType == 3
| where AuthenticationPackageName == "NTLM"
| where not(IpAddress in ("127.0.0.1", "::1", "-"))
| summarize LogonCount = count(), 
            TargetHosts = make_set(Computer),
            TargetHostCount = dcount(Computer)
            by IpAddress, Account, bin(TimeGenerated, 1h)
| where TargetHostCount > 3
| sort by TargetHostCount desc
```

### H2: Anomalous RDP Connections

```kql
// Find RDP sessions from non-standard jump hosts
SecurityEvent
| where EventID == 4624
| where LogonType == 10  // RemoteInteractive (RDP)
| where not(IpAddress in (dynamic(["10.0.1.50", "10.0.1.51"])))  // Known jump hosts
| summarize FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated),
            SessionCount = count()
            by IpAddress, Account, Computer
| sort by SessionCount desc
```

### H4: Suspicious Admin Share Access

```kql
// Monitor access to admin shares from non-admin workstations
SecurityEvent
| where EventID == 5140
| where ShareName in ("\\\\*\\C$", "\\\\*\\ADMIN$", "\\\\*\\IPC$")
| where not(SubjectUserName endswith "$")  // Exclude machine accounts
| summarize ShareAccessCount = count(),
            Shares = make_set(ShareName),
            SourceIPs = make_set(IpAddress)
            by SubjectUserName, Computer, bin(TimeGenerated, 1h)
| where ShareAccessCount > 5
```

### H5: Remote Service Creation (PsExec-like)

```kql
// Detect remote service creation typical of PsExec
Event
| where Source == "Service Control Manager"
| where EventID == 7045
| where tostring(EventData) matches regex @"PSEXE|paexec|remcom|csexec"
   or (tostring(EventData) has "cmd.exe" and tostring(EventData) has "%COMSPEC%")
| project TimeGenerated, Computer, EventData
```

---

## 📊 Analysis Workflow

```
     ┌──────────────┐
     │  Hypothesis   │
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │  Data Query   │──── No results ──── Document & close
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │  Analyze      │
     │  Results      │──── False positive ──── Tune baseline
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │  Investigate  │──── Confirm malicious ──── Escalate to IR
     │  Anomalies    │
     └──────┬───────┘
            ▼
     ┌──────────────┐
     │  Document     │
     │  Findings     │
     └──────────────┘
```

---

## 📋 Hunt Checklist

- [ ] Define hunting window (recommended: 30 days)
- [ ] Validate data source availability and quality
- [ ] Execute queries for each hypothesis
- [ ] Investigate anomalies against known baselines
- [ ] Cross-reference with threat intelligence
- [ ] Document all findings (positive and negative)
- [ ] Create new detection rules for confirmed techniques
- [ ] Update baseline of normal lateral movement patterns

---

## 📎 References

- [MITRE ATT&CK — Lateral Movement](https://attack.mitre.org/tactics/TA0008/)
- [SANS — Threat Hunting Techniques](https://www.sans.org/white-papers/)
- [Microsoft — Advanced Hunting](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-overview)

---

**Related Playbooks:** [IR-001 Ransomware](../incident-response/IR-001-ransomware.md) | [TH-003 Credential Access](TH-003-credential-access.md) | [TH-004 LOLBins](TH-004-lolbins.md)
