# SOC Investigations

Hands-on security investigations documented the way a SOC actually expects findings written up — objective, evidence, timeline, indicators, MITRE ATT&CK mapping, and a verdict. Not lab answers, incident reports.

I'm a cybersecurity graduate (WGU, Cybersecurity and Information Assurance) with CompTIA CySA+, PenTest+, Security+, and Network+, targeting a Tier 1 SOC Analyst / Information Security Analyst role. This repo is where I keep full investigative write-ups — real evidence, real reasoning, not just bullet points on a resume.

📄 [Resume](#) &nbsp;|&nbsp; 💼 [LinkedIn](https://www.linkedin.com/in/hai-le-cybersecurity/)

---

## Investigations

| # | Investigation | Tools Used | Frameworks |
|---|---|---|---|
| 01 | [Phishing Campaign Investigation](./01-phishing-campaign-investigation) | Thunderbird, CyberChef, VirusTotal, sha256sum | NIST SP 800-61, MITRE ATT&CK |
| 02 | [Full Attack Chain Investigation](./02-full-attack-chain-investigation) | EvtxECmd, Timeline Explorer, SysmonView, Wireshark, CyberChef, VirusTotal, AbuseIPDB | NIST SP 800-61, MITRE ATT&CK |
| 03 | [APT Intrusion Analysis — Volt Typhoon](./03-volt-typhoon-apt-investigation) | Splunk Enterprise (SPL), CyberChef | NIST SP 800-61, MITRE ATT&CK |

More investigations in progress — this table grows as each one is completed and pushed.

Each folder contains a full write-up with screenshots, IOC tables, and a timeline reconstruction — click in to see the actual work, not just the summary.

## Skills Demonstrated Across This Repo

- **Email/phishing forensics** — header analysis, SPF/DKIM/DMARC validation, display-spoofing detection
- **Log correlation & timeline reconstruction** — Windows Event Logs, Sysmon telemetry, EvtxECmd/Timeline Explorer/SysmonView
- **SIEM investigation** — SPL query development across heterogeneous log sources (identity/account management, WMI execution, PowerShell pipeline logs), cross-source actor attribution
- **Threat intel enrichment** — VirusTotal, AbuseIPDB, URLScan
- **Malware/phishing kit analysis** — source code review, behavioral indicators
- **Full attack chain analysis** — exploit-to-persistence process lineage, C2 traffic decoding, privilege escalation and lateral movement tracing
- **Living-off-the-land (LOTL) technique identification** — abuse of native tools (`wmic`, `certutil`, `netsh`) for discovery, execution, and defense evasion
- **Command-line deobfuscation** — Base64/CyberChef decoding of obfuscated payloads
- **Analytical self-correction** — identifying and correcting flawed investigative methodology using baseline/statistical analysis, not just following the first lead
- **Incident documentation** — NIST SP 800-61 process, MITRE ATT&CK technique mapping

---
*Last updated: July 2026*
