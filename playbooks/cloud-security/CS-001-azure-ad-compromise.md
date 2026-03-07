# CS-001: Azure AD / Entra ID Compromise Response

<div align="center">

| Field | Value |
|:---:|:---:|
| **Severity** | 🔴 Critical |
| **MITRE ATT&CK** | T1078.004 (Cloud Accounts), T1136.003 (Cloud Account Creation), T1098 (Account Manipulation) |
| **Platform** | Microsoft Azure / Entra ID |
| **Last Updated** | March 2026 |
| **Author** | Ali AlEnezi (@SiteQ8) |

</div>

---

## 🎯 Objective

Respond to confirmed or suspected compromise of Azure Active Directory / Microsoft Entra ID tenant, including unauthorized access to cloud identities, privilege escalation, and persistence establishment.

---

## 🔍 Phase 1: Detection

### Indicators of Compromise

- New federated domain added to tenant
- New privileged role assignment (Global Admin, Exchange Admin)
- Bulk credential reset or MFA manipulation
- Suspicious OAuth application consent grants
- Service Principal credential addition
- Conditional Access policy modifications
- Cross-tenant access settings changes

### Detection Queries

```kql
// Detect new Global Admin assignments
AuditLogs
| where OperationName == "Add member to role"
| extend RoleName = tostring(TargetResources[0].modifiedProperties[1].newValue)
| where RoleName has "Global Administrator" or RoleName has "Company Administrator"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, Actor, Target, RoleName, OperationName
```

```kql
// Detect suspicious app consent grants with high-privilege permissions
AuditLogs
| where OperationName == "Consent to application"
| extend Permissions = tostring(TargetResources[0].modifiedProperties)
| where Permissions has_any ("Mail.ReadWrite", "Files.ReadWrite.All", 
                              "Directory.ReadWrite.All", "RoleManagement.ReadWrite")
| extend AppName = tostring(TargetResources[0].displayName)
| extend User = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, User, AppName, Permissions
```

```kql
// Detect federated domain additions (Golden SAML prep)
AuditLogs
| where OperationName has "Set domain authentication"
| extend DomainName = tostring(TargetResources[0].displayName)
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, Actor, DomainName, OperationName
```

---

## 🚧 Phase 2: Containment

### Immediate Actions

1. **Identity Lockdown**
   - Revoke all refresh tokens for compromised accounts (`Revoke-AzureADUserAllRefreshToken`)
   - Reset passwords for all compromised identities
   - Disable suspicious service principals and app registrations
   - Remove unauthorized role assignments

2. **Tenant Hardening**
   - Enable Security Defaults or strengthen Conditional Access policies
   - Block legacy authentication protocols immediately
   - Require MFA for all admin accounts (phishing-resistant preferred)
   - Review and restrict user consent settings

3. **Investigation Scope**
   - Pull complete Azure AD Audit Logs and Sign-in Logs (90-day window)
   - Review all admin role assignments
   - Audit all OAuth application consents and permissions
   - Check for unauthorized federated domains
   - Review Conditional Access policy changes

---

## 🧹 Phase 3: Eradication

1. Remove unauthorized federated domains
2. Remove malicious OAuth applications and service principals
3. Rotate all service principal credentials and certificates
4. Remove unauthorized Conditional Access exclusions
5. Review and clean up all directory role assignments
6. Rotate SAML token signing certificates if Golden SAML suspected
7. Invalidate all active sessions tenant-wide if scope warrants

---

## 🔄 Phase 4: Recovery

1. Re-enable accounts with enforced phishing-resistant MFA
2. Implement Privileged Identity Management (PIM) for admin roles
3. Deploy Conditional Access policies requiring compliant devices
4. Enable continuous access evaluation (CAE)
5. Monitor sign-in and audit logs with enhanced alerting for 30 days

---

## 📊 Metrics

| Metric | Target |
|--------|--------|
| MTTD | < 1 hour |
| Admin access revocation | < 30 minutes |
| Full containment | < 4 hours |
| Tenant recovery | < 24 hours |

---

## 📎 References

- [Microsoft — Incident Response for Azure AD](https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app)
- [MITRE ATT&CK — T1078.004](https://attack.mitre.org/techniques/T1078/004/)
- [CISA — Detecting Post-Compromise Threat Activity in Microsoft Cloud](https://www.cisa.gov/news-events/cybersecurity-advisories)

---

**Related Playbooks:** [IR-002 BEC](../incident-response/IR-002-bec.md) | [TH-003 Credential Access](../threat-hunting/TH-003-credential-access.md)
