# Contributing to SecOps Playbooks

Thank you for your interest in contributing to SecOps Playbooks! This project thrives on community collaboration.

## How to Contribute

### Submitting a New Playbook

1. Fork the repository
2. Create a new branch (`git checkout -b playbook/IR-XXX-description`)
3. Use the [playbook template](templates/playbook-template.md) as your starting point
4. Place your playbook in the appropriate category folder
5. Ensure MITRE ATT&CK mapping is included
6. Submit a Pull Request with a clear description

### Playbook Requirements

Every playbook must include:

- **Metadata table** — Severity, MITRE techniques, author, date
- **Detection section** — IoCs, KQL/SPL queries, alert rules
- **Response phases** — Following NIST SP 800-61 lifecycle
- **Metrics** — MTTD, MTTR, escalation targets
- **References** — MITRE ATT&CK links, vendor documentation

### Improving Existing Playbooks

- Add detection queries for additional SIEM platforms
- Update MITRE ATT&CK mappings
- Add real-world case study references
- Translate playbooks to Arabic or other languages
- Fix typos, broken links, or outdated references

### Code of Conduct

- Be respectful and constructive
- Do not include proprietary or classified information
- Do not include actual IoCs from active investigations
- Ensure all queries are generic and safe to share publicly

## Questions?

Open an issue or reach out to [@SiteQ8](https://github.com/SiteQ8).
