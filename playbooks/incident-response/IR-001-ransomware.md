# IR-001: Ransomware Incident Response Playbook

<div align="center">

| Field | Value |
|:---:|:---:|
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK** | T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1027 (Obfuscated Files) |
| **NIST Phase** | SP 800-61 Rev 2 — Full Lifecycle |
| **Last Updated** | March 2026 |
| **Author** | Ali AlEnezi (@SiteQ8) |

</div>

---

## 🎯 Objective

Provide a structured, repeatable process for responding to ransomware attacks across enterprise environments. This playbook covers the full incident lifecycle from initial detection through recovery and lessons learned, with specific guidance for financial sector environments.

---

## 🔍 Phase 1: Detection & Identification

### Indicators of Compromise (IoCs)

**Behavioral Indicators:**
- Mass file encryption events (high volume file modification alerts)
- Ransom notes appearing on endpoints (e.g., `README.txt`, `DECRYPT_FILES.html`)
- Abnormal process execution chains (e.g., `wscript.exe` → `cmd.exe` → `vssadmin.exe`)
- Volume Shadow Copy deletion attempts
- Unusual outbound traffic to known C2 infrastructure
- Endpoint Detection & Response (EDR) alerts for known ransomware families

**System Indicators:**
- File extensions changed to known ransomware patterns (`.encrypted`, `.locked`, `.crypt`)
- Registry modifications disabling recovery options
- Group Policy modifications propagating encryption
- Unusual service installations or scheduled tasks

### Detection Queries

**Microsoft Sentinel (KQL):**

```kql
// Detect mass file rename/encryption activity
DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed", "FileModified")
| summarize FileCount = dcount(FileName), 
            Extensions = make_set(tostring(split(FileName, ".")[-1])) 
            by DeviceName, InitiatingProcessFileName, bin(Timestamp, 5m)
| where FileCount > 100
| project Timestamp, DeviceName, InitiatingProcessFileName, FileCount, Extensions
| sort by FileCount desc
```

```kql
// Detect Volume Shadow Copy deletion
DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessCommandLine has_any ("vssadmin delete shadows", 
                                     "wmic shadowcopy delete",
                                     "bcdedit /set {default} recoveryenabled no",
                                     "wbadmin delete catalog")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, 
          InitiatingProcessFileName
```

**Splunk SPL:**

```spl
index=endpoint sourcetype=sysmon EventCode=11
| bucket _time span=5m
| stats dc(TargetFilename) as file_count by _time, Computer, Image
| where file_count > 100
| sort -file_count
```

### Severity Classification

| Criteria | Classification |
|----------|---------------|
| Single endpoint, no lateral movement | 🟡 Medium |
| Multiple endpoints, same subnet | 🟠 High |
| Cross-subnet propagation or domain controller affected | 🔴 Critical |
| Production systems / financial data affected | 🔴 Critical — Executive escalation |

---

## 🚧 Phase 2: Containment

### Immediate Actions (First 30 minutes)

> ⚠️ **Do NOT shut down infected machines** — this may destroy forensic evidence and encryption keys in memory.

1. **Network Isolation**
   - Isolate affected endpoints from the network via EDR or switch port shutdown
   - Block known C2 IPs/domains at firewall and proxy
   - Disable compromised accounts in Active Directory
   - Consider isolating entire affected VLANs if propagation is active

2. **Preserve Evidence**
   - Capture memory dumps from infected systems before any remediation
   - Snapshot affected VMs if in virtual environment
   - Begin chain-of-custody documentation
   - Preserve network flow data and relevant log sources

3. **Communications**
   - Activate incident response team and communication channel (out-of-band)
   - Notify CISO / Security leadership
   - Prepare internal communications (avoid email if compromise is suspected)
   - Engage legal counsel for regulatory notification requirements

### Short-Term Containment

4. **Scope Assessment**
   - Identify Patient Zero and initial infection vector
   - Map all affected systems and data
   - Determine ransomware variant (check [ID Ransomware](https://id-ransomware.malwarehunterteam.com/))
   - Assess backup integrity — are backups affected?

5. **Prevent Further Spread**
   - Deploy emergency GPO to block execution of ransomware binary (hash-based)
   - Enable enhanced logging on all endpoints
   - Block lateral movement protocols if feasible (SMB, RDP, WinRM)
   - Reset passwords for all privileged accounts

---

## 🧹 Phase 3: Eradication

1. **Root Cause Removal**
   - Identify and eliminate initial access vector (phishing email, RDP exposure, VPN vulnerability)
   - Remove all persistence mechanisms (scheduled tasks, services, registry keys)
   - Patch exploited vulnerabilities
   - Validate no remaining backdoors or secondary payloads

2. **Environment Hardening**
   - Reset all potentially compromised credentials (including service accounts)
   - Review and restrict Active Directory delegations
   - Implement network segmentation improvements
   - Deploy additional monitoring for ransomware-associated techniques

3. **Validation**
   - Run full endpoint scans with updated signatures
   - Conduct threat hunt for residual indicators
   - Validate clean state of all affected systems

---

## 🔄 Phase 4: Recovery

1. **System Restoration**
   - Restore from verified clean backups (test backup integrity first)
   - If no backups, check for available decryptors at [No More Ransom](https://www.nomoreransom.org/)
   - Rebuild systems from gold images if backups are unavailable
   - Prioritize recovery of critical business systems

2. **Staged Return to Production**
   - Restore systems in phases with enhanced monitoring
   - Validate application functionality after restoration
   - Monitor for re-infection indicators for minimum 72 hours
   - Gradually restore network connectivity

3. **Business Continuity**
   - Coordinate with business units on recovery timeline
   - Document any data loss
   - Engage with customers/partners as required

---

## 📝 Phase 5: Post-Incident Activities

1. **Lessons Learned**
   - Conduct post-incident review within 5 business days
   - Document timeline, decisions, and outcomes
   - Identify gaps in detection, response, and recovery
   - Update playbook based on findings

2. **Metrics**

| Metric | Target | Definition |
|--------|--------|------------|
| MTTD (Mean Time to Detect) | < 1 hour | Time from first encryption to SOC alert |
| MTTC (Mean Time to Contain) | < 4 hours | Time from detection to full network isolation |
| MTTR (Mean Time to Recover) | < 48 hours | Time from containment to business operations restored |

3. **Regulatory Reporting**
   - Kuwait Central Bank notification (if financial institution)
   - CITRA notification (Kuwait national CERT)
   - Data protection authority notification if personal data affected
   - Law enforcement engagement as required

---

## 📎 References

- [MITRE ATT&CK — T1486](https://attack.mitre.org/techniques/T1486/)
- [NIST SP 800-61 Rev 2 — Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [No More Ransom Project](https://www.nomoreransom.org/)

---

**Related Playbooks:** [IR-003 Data Exfiltration](IR-003-data-exfiltration.md) | [IR-006 Supply Chain Compromise](IR-006-supply-chain.md) | [TH-002 C2 Detection](../threat-hunting/TH-002-c2-detection.md)
