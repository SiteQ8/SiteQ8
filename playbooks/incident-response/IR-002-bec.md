# IR-002: Business Email Compromise (BEC) Response Playbook

<div align="center">

| Field | Value |
|:---:|:---:|
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK** | T1566.001 (Spearphishing Attachment), T1534 (Internal Spearphishing), T1114 (Email Collection) |
| **NIST Phase** | SP 800-61 Rev 2 — Full Lifecycle |
| **Last Updated** | March 2026 |
| **Author** | Ali AlEnezi (@SiteQ8) |

</div>

---

## 🎯 Objective

Detect, contain, and remediate Business Email Compromise attacks targeting financial transactions, executive impersonation, and vendor fraud schemes. Tailored for financial sector operations with emphasis on wire transfer fraud prevention.

---

## 🔍 Phase 1: Detection & Identification

### Indicators of Compromise

**Email-Based Indicators:**
- Inbox rules forwarding email externally (auto-forward, redirect)
- Login from anomalous geographic locations or unfamiliar IPs
- MFA bypass or legacy authentication protocol usage
- Mailbox delegation changes
- Consent grants to suspicious OAuth applications
- Email impersonation of executives or known vendors

**Financial Indicators:**
- Urgent requests for wire transfers or changes to payment details
- Vendor requesting bank account changes via email
- Invoice fraud with altered banking details
- Unusual payment authorization requests outside normal workflow

### Detection Queries

**Microsoft Sentinel (KQL):**

```kql
// Detect suspicious inbox rule creation
OfficeActivity
| where Operation in ("New-InboxRule", "Set-InboxRule", "Enable-InboxRule")
| where Parameters has_any ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo", 
                             "DeleteMessage", "MarkAsRead")
| extend RuleDetails = tostring(Parameters)
| project TimeGenerated, UserId, Operation, RuleDetails, ClientIP
| sort by TimeGenerated desc
```

```kql
// Detect impossible travel / anomalous sign-ins
SigninLogs
| where ResultType == 0
| summarize Locations = make_set(Location), 
            IPs = make_set(IPAddress),
            LocationCount = dcount(Location)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where LocationCount > 1
| project TimeGenerated, UserPrincipalName, Locations, IPs
```

```kql
// Detect OAuth consent grants to suspicious apps
AuditLogs
| where OperationName == "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, UserPrincipalName, AppName, 
          CorrelationId, OperationName
```

---

## 🚧 Phase 2: Containment

### Immediate Actions (First 15 minutes)

1. **Account Lockdown**
   - Reset compromised account password immediately
   - Revoke all active sessions and refresh tokens
   - Disable account if active attacker presence confirmed
   - Enable MFA if not already enabled (enforce phishing-resistant MFA)

2. **Email Containment**
   - Remove malicious inbox rules
   - Revoke suspicious OAuth application consents
   - Block attacker IP addresses in Conditional Access
   - Search for and purge phishing emails across all mailboxes

3. **Financial Containment**
   - Contact bank immediately to halt pending fraudulent wire transfers
   - Notify finance/accounting team of compromised account
   - Freeze payment processing for any instructions from compromised account
   - Verify all recent payment instructions via out-of-band communication (phone call to known number)

### Extended Containment

4. **Scope Assessment**
   - Review email audit logs for full scope of mailbox access
   - Check for data exfiltration (mail forwarding, PST export, eDiscovery abuse)
   - Identify all accounts targeted by internal phishing from compromised account
   - Review Azure AD sign-in logs for lateral movement to other cloud apps

---

## 🧹 Phase 3: Eradication

1. Remove all attacker persistence (inbox rules, app consents, delegations)
2. Rotate credentials for all potentially exposed service accounts
3. Review and revoke any unauthorized MFA devices
4. Block identified attacker infrastructure in email gateway and firewall
5. Deploy anti-phishing policies and enhanced mail flow rules

---

## 🔄 Phase 4: Recovery

1. Restore legitimate inbox rules and mailbox settings
2. Notify recipients of any fraudulent emails sent from compromised account
3. Work with financial institutions on fund recovery (IC3 filing if US-related)
4. Re-enable account with enhanced security controls
5. Monitor account for 30 days with enhanced logging

---

## 📝 Phase 5: Post-Incident

### Metrics

| Metric | Target |
|--------|--------|
| MTTD | < 30 minutes |
| Financial containment | < 1 hour |
| Account recovery | < 4 hours |

### Regulatory Reporting
- Kuwait Central Bank if financial institution
- Law enforcement if financial loss confirmed
- IC3 report (www.ic3.gov) for international wire fraud

---

## 📎 References

- [MITRE ATT&CK — T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [FBI IC3 — BEC Guidance](https://www.ic3.gov/Home/BEC)
- [Microsoft — Responding to BEC](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)

---

**Related Playbooks:** [IR-001 Ransomware](IR-001-ransomware.md) | [IR-004 Insider Threat](IR-004-insider-threat.md) | [TH-003 Credential Access](../threat-hunting/TH-003-credential-access.md)
