# SOC Alert Triage: Practitioner Pain Points (2024–2026)

Compiled 2026-10-14 for the Probewise redesign. Every bullet cites a source. Labels: **[vendor]** means a vendor sponsored or published it. **[secondary]** means I saw only a summary, not the primary report. **[UNVERIFIED]** means I could not confirm it against the primary source. Reddit was not reachable with my tools (the domain is blocked), so I did not read Reddit threads directly. Practitioner forum sentiment comes from Nath et al. (SOUPS 2026), a peer-reviewed study that coded 892 r/cybersecurity, r/Information_Security and r/ciso posts.

---

## 1. Quantitative data

**Alert volume**
- **4,484 alerts/day** on average, and **67% are ignored**. 83% of analysts say alerts are mostly false positives. 97% worry about missing a real event. 67% are considering leaving or actively leaving the job. Source: Vectra, *2023 State of Threat Detection*, 2023 [vendor]. https://content.vectra.ai/hubfs/downloadable-assets/V_2023-State-of-Threat-Detection.pdf (the 83% figure is from secondary coverage: https://www.intelligentcio.com/north-america/2023/08/04/research-reveals-significant-disconnect-between-security-operations-teams-and-the-effectiveness-of-threat-detection/)
- **Median ~100 alerts/day.** The mean approaches 1,000/day in the largest environments. 74% get 50+ alerts/day and 27% get 500+. Source: Prophet Security / ViB, *State of AI in the SOC 2026*, N=250, 2026-08-03 [vendor]. https://www.prophetsecurity.ai/blog/state-of-ai-in-the-soc-2026
- The 2025 edition reported ~960 alerts/day, ~40% never investigated and 70 min per investigation [vendor][secondary]. The 2026 median is much lower, so the two editions are not directly comparable. https://thehackernews.com/2025/09/the-state-of-ai-in-soc-2025-insights.html

**False positives and uninvestigated alerts**
- **46% of alerts are false positives** and **42% go uninvestigated**. Analysts pivot across an **average of 10.9 consoles**. **66% of SOCs lose 20% of their week** to aggregation and correlation. Only ~59% of tools push data to the SIEM. Source: Microsoft and Omdia, *State of the SOC*, N=300, fieldwork Jun–Jul 2025, blog published 2026-02-17 [vendor-commissioned]. https://microsoft.com/en-us/security/blog/2026/02/17/unify-now-or-pay-later-new-research-exposes-the-operational-cost-of-a-fragmented-soc
- **Average 28% of alerts uninvestigated** (median 22%). **60% say an ignored alert later proved material.** **40% have turned off, or may turn off, detection rules** because they lack the resources to investigate them. Source: Prophet 2026 (above) [vendor].
- **73% of organizations name false positives as their #1 detection challenge.** The share seeing "very frequent" FPs rose from 13% to 20% year over year. Source: SANS *2025 Detection & Response Survey*, as reported by sponsor Stamus Networks, 2025-12-16 [vendor][secondary]. https://go.stamus-networks.com/blog/what-the-2025-sans-detection-response-survey-reveals-false-positives-alert-fatigue-are-worsening
- In a think-aloud field study, **only 44 of 400 real T1 investigations (11%) were escalation-worthy** ("Att"). Source: Kersten et al., TU Eindhoven, NDSS USEC 2025 workshop paper. https://ndss-symposium.org/wp-content/uploads/usec25-34.pdf

**Time to triage and investigate**
- Average investigation takes ~**75 min** (median ~45). **64%** report a mean time to investigate of 30+ min. Alert dwell time before pickup averages **55 min** (median 23). Source: Prophet 2026 (above) [vendor].
- "Nearly three hours a day" of manual triage. Source: Vectra 2023 [vendor][secondary][UNVERIFIED in primary].

**Burnout, staffing and tools**
- **71% of analysts report burnout.** 69% say their team is understaffed. Source: Tines, *Voice of the SOC Analyst*, N=468, 2022 [vendor]. https://tines.com/reports/voice-of-the-soc-analyst/
- **52% say their team is overworked** and **52% have considered leaving cybersecurity** because of stress. **59% spend too much time maintaining tools.** **51% say their tools don't integrate.** 59% report too many alerts and 55% too many FPs. Only **11% fully trust AI** for mission-critical tasks. Source: Splunk (Cisco), *State of Security 2025*, N=2,058, May 2025 [vendor][alert/FP figures secondary]. https://newsroom.cisco.com/c/r/newsroom/en/us/a/y2025/m05/global-state-of-security-report-reveals-critical-need-for-connected-security-operations.html
- **62% say their organization isn't doing enough to retain staff.** **69% report metrics manually.** **GenAI tools scored lowest in satisfaction** of all technologies measured. 42% use AI/ML "out of the box" with no customization. EDR is the primary response trigger for 85%. Source: SANS *2025 SOC Survey* (sponsor Elastic), July 2025, as summarized by Tines on 2025-07-17 [secondary]. https://www.tines.com/blog/sans-soc-survey-2025/ and primary: https://www.elastic.co/resources/security/report/2025-state-of-the-soc-survey

---

## 2. What L1/L2 analysts actually do

**Generic flow (practitioner-written)**
1. Work the severity-ranked queue, including carry-over from the previous shift.
2. Triage by asking what fired, how critical the asset is, whether this user or IP has done it before, and whether there is a threat-intel match.
3. Pivot in the SIEM on user, host and IP within the surrounding time window.
4. Enrich IOCs in VirusTotal and internal threat intel.
5. Map the activity to MITRE ATT&CK.
6. Scope: check other hosts, lateral movement and accounts.
7. Close as FP (with a tuning note) or escalate, recording what was ruled out.
8. Document every case.

Source: O'Grady, TryHackMe blog, 2026-03-14. https://tryhackme.com/resources/blog/how-soc-analysts-actually-investigate-alerts-real-blue-team-workflow

**Observed behavior (field data, 400 investigations)**
- Contextual information was gathered in **97%** of investigations. Rule information was gathered in only 53%, related/historical alerts in 48%, and attack evidence in 58%. The SIEM is the dominant source. Attack evidence (IP/domain reputation) came from **external tools (URLscan, VirusTotal) in 160 of 223** cases. Source: Kersten et al. 2025 (above).
- Alert history came mostly from **analysts' memory (tacit knowledge)** rather than search. Only one analyst ever queried how often an alert had fired before. Source: Kersten et al. 2025.
- The process **varies widely across analysts and alert types**. Some analysts "chaotically switch context." Escalation-worthy alerts need more actions. A structured support panel cut actions on those alerts and made analysts collect more relevant information. Source: Kersten et al. 2025.

**Systems and pivots**
- Analysts move between SIEM, EDR, cloud posture, identity and ticketing tools, typically **5–10 consoles** [vendor]. Source: Wiz Academy, n.d. https://www.wiz.io/academy/cloud-careers/soc-analyst-burnout. Microsoft/Omdia's survey figure is 10.9 consoles (above).
- A typical time sink: copying a username from the SIEM into the EDR, losing timestamp context, and juggling five tabs. One 14-day Windows event-log query took 90 seconds. Source: ManageEngine blog, n.d. [vendor]. https://meblog.manageengine.com/siem/log360/a-day-in-the-life-of-a-soc-analystand-what-actually-slows-them-down.html

**Per-scenario sketches [UNVERIFIED synthesis]**
No primary practitioner source in this pass gave step-by-step runbooks per scenario. These sketches assemble the generic sources above:
- **Suspicious login:** IdP sign-in logs (geo, device, MFA result) → user's login history (SIEM) → HR or VPN context (is the user travelling?) → ask the user or their manager.
- **Endpoint malware:** EDR process tree and hash → VirusTotal → asset criticality (CMDB) → SIEM search for the same hash or C2 domain on other hosts.
- **Phishing report:** headers and URLs/attachments → URLscan/VT → search the mail gateway for other recipients → check clicks in the proxy logs.

Phishing-report base rates are uncertain:
- Vendor claims put manual triage at "up to 30 min/email." Source: Abnormal [vendor][UNVERIFIED]. https://abnormal.ai/blog/ai-phishing-triage
- A Microsoft RCT of its phishing-triage agent reported up to **6.5x true positives per analyst-minute** and **+77% verdict accuracy**. Source: Bono, arXiv 2511.13860, 2025-11-17 [vendor-authored]. https://arxiv.org/abs/2511.13860

---

## 3. Recurring pain points, ranked

**Method:** sources in this report mentioning each pain point. This count reflects my sample of sources, not prevalence across the industry.

| # | Pain point | Sources (count) |
|---|---|---|
| 1 | **Alert volume and false positives** | Vectra 2023, SANS D&R 2025, Splunk 2025, Microsoft/Omdia, Prophet 2026, CSA 2026 (6) |
| 2 | **Tool fragmentation, context switching, manual correlation** | Microsoft/Omdia (10.9 consoles), Splunk (51% non-integrated, 59% tool upkeep), Wiz, ManageEngine, Kersten (external tools) (5) |
| 3 | **Uninvestigated alerts and fear of missed attacks** | Vectra, Microsoft/Omdia, Prophet, Thurner et al. (4) |
| 4 | **Understaffing, burnout, turnover** | Tines 2022, Vectra, Splunk, SANS SOC 2025 (4) |
| 5 | **Missing context / tacit knowledge / inconsistent process** | Kersten, Thurner ("feed the LLM correct data"), TryHackMe (handoffs) (3) |
| 6 | **Manual reporting and documentation** | SANS 2025 (69% manual metrics), Tines 2023 ("too many reporting requirements"), Banstola et al. (3) |

CSA research note, 2026-09-14: AI-tool usage is a new source of noise. AI-related alerts grew 685% (Feb–Jun 2026), and 94.1% were legitimate-use noise. 81.7% were auto-suppressed without review. CSA flags this as AI-assisted, unreviewed research. https://labs.cloudsecurityalliance.org/wp-content/uploads/2026/09/CSA_research_note_ai_soc_alert_noise_20260914-csa-styled.pdf

Tines 2023 source for row 6: https://tines.com/blog/voice-of-the-soc-2023

---

## 4. Practitioners on AI/LLM tools

**Useful today**
- **Reporting/documentation, scripting and query writing, threat-intel summarization, enrichment of unfamiliar logs, and onboarding.** Incident analysis, malware de-obfuscation and autonomous response are rated *not feasible*. Triage is acceptable as *assistance, not automation*. Source: Thurner et al., 25 SOC practitioner interviews, arXiv 2608.00672, 2026-08 (v2 2026-10-12). https://arxiv.org/abs/2608.00672
- On Reddit, triage/IR was the most-discussed use case (42.8% of 325 use-case posts). Actual adoption is led by scripting/query support (28%) and reporting (26%). Source: Nath et al., SOUPS 2026. https://arxiv.org/abs/2604.09998
- In a SOC deployment, analysts reused the AI companion's output in **>90% of ticket closing reports**. The more analysts could shape the tool, the more they trusted it. Source: Banstola et al., arXiv 2609.06250, 2026-09-05. https://arxiv.org/abs/2609.06250

**Distrusted**
- Sentiment on Reddit by factor: reliability was **94.8% negative**, security & privacy **88.5% negative**, autonomy **87.2% negative** and cost **85.7% negative**. Efficiency was **84.4% positive**. By topic, data leakage came up in 31 posts and hallucinations in ~25. Expanded attack surface came up in 17 posts and verification overhead in 10. Source: Nath et al. 2026.
- Over-reliance and deskilling were rated the top risk in almost all interviews. **Missed attacks are the dominant fear** ("from chasing ghosts to missed attacks"). Hallucination is often blamed on missing context. Nearly all participants distrust cloud providers and prefer on-prem hosting. **Prompt injection and data poisoning were raised unprompted.** Plausible reasoning can make wrong answers *more* convincing. Source: Thurner et al. 2026.
- Barriers: **data privacy/LLM training 44%**, **lack of explainability 41%**, cost 36%, integration 35%, accuracy 32%. **57% require human review of every verdict.** **No respondent grants full autonomy.** 46% of in-house LLM SOC builds were abandoned or never reached production. Source: Prophet 2026 [vendor].
- Hallucinations were a blocker for 26% of security leaders. Source: IDC/Tines *Voice of Security 2025* [vendor][secondary]. https://www.csoonline.com/article/3847860/new-research-reveals-securitys-biggest-ai-challenges-and-two-potential-solutions.html

**What would drive adoption (synthesis of the above)**
- Grounding in **organization-specific context** (asset, user and alert history), since missing context causes hallucinations. Source: Thurner.
- A **human-in-the-loop design that recommends but does not act**, with least privilege. Source: Thurner, Prophet.
- **Verifiable evidence for each claim and measurable verdict-agreement metrics.** Only 30% of Prophet respondents see ≥90% agreement with senior analysts. Source: Prophet, Nath.
- **On-prem or private deployment and data separation.** Source: Thurner.
- The ability to **try before buying** and **tune the tool to the team**. Source: Nath, Banstola.
- Measured speed-ups exist. CSA's benchmark reports AI-assisted analysts finished investigations **45–61% faster** (cited via the CSA note above). 72% of AI users in Prophet's survey report at least a 25% cut in investigation time [vendor].
