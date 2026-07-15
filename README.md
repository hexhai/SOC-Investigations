# SOC Investigations

Hands-on security investigations documented the way a SOC actually expects findings written up — objective, evidence, timeline, indicators, MITRE ATT&CK mapping, and a verdict. Not lab answers, incident reports.

I'm a cybersecurity graduate (WGU, Cybersecurity and Information Assurance) with CompTIA CySA+, PenTest+, Security+, and Network+, targeting a Tier 1 SOC Analyst / Information Security Analyst role. This repo is where I keep full investigative write-ups — real evidence, real reasoning, not just bullet points on a resume.

📄 [Resume](#) &nbsp;|&nbsp; 💼 [LinkedIn](https://www.linkedin.com/in/hai-le-cybersecurity/)

---

## Investigations

| # | Investigation | Tools Used | Frameworks |
|---|---|---|---|
| 01 | [Phishing Campaign Investigation](./01-phishing-campaign-investigation) | Thunderbird, CyberChef, VirusTotal, sha256sum | NIST SP 800-61, MITRE ATT&CK |
| 02 | Full Attack Chain Investigation — *in progress* | EvtxECmd, Timeline Explorer, SysmonView, Wireshark, CyberChef, VirusTotal | NIST SP 800-61, MITRE ATT&CK |

More investigations in progress — this table grows as each one is completed and pushed.

Each folder contains a full write-up with screenshots, IOC tables, and a timeline reconstruction — click in to see the actual work, not just the summary.

## Skills Demonstrated Across This Repo

- **Email/phishing forensics** — header analysis, SPF/DKIM/DMARC validation, display-spoofing detection
- **Log correlation & timeline reconstruction** — Windows Event Logs, Sysmon telemetry
- **Threat intel enrichment** — VirusTotal, AbuseIPDB, URLScan
- **Malware/phishing kit analysis** — source code review, behavioral indicators
- **Incident documentation** — NIST SP 800-61 process, MITRE ATT&CK technique mapping

---
*Last updated: July 2026*
