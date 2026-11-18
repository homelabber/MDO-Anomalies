# Phish & Chats

*MDO email and Teams anomaly detections, because attackers stopped waiting for you to open your inbox.*

This repo has a **Microsoft Sentinel workbook** and a set of **Microsoft Defender XDR custom detections** for the email and Teams attack patterns that Microsoft Threat Intelligence tracks and Microsoft Defender for Office 365 (MDO) surfaces. It covers mail bombing and twelve other patterns, a view of mail flagged by MDO's LLM-based content analysis, multi-step **attack sequences** (for example a risky sign-in followed by a new inbox rule), **Microsoft Teams threats** (malicious chats, external calls, deepfakes) and threats delivered because of **allow-list overrides**.

> Formerly **MDO-Anomalies**. Old GitHub links redirect here. Custom detection ids keep their `MDO-` prefix, so redeploying updates your existing rules instead of creating duplicates.

Need to share findings with someone who doesn't have Sentinel open? An [HTML report export](#export-an-html-report) runs the same workbook queries and writes one self-contained file.

Detections are built as **custom detections** rather than Sentinel scheduled analytics rules, in line with Microsoft's move to unified detections in the Defender portal. They can run every hour, use the Advanced Hunting tables directly (including columns not streamed to Sentinel, such as `LatestDeliveryLocation`), and support response actions.

## Coverage

| # | Anomaly | Threat actors / campaigns | Workbook | Custom detection | MITRE ATT&CK |
|---|---------|---------------------------|:--------:|------------------|--------------|
| 01 | Email bombing (mail bombing) | Storm-1811, Black Basta affiliates | ✅ | `MDO-01` (Medium) | T1667 |
| 02 | Email bombing, then external Teams chat or call, or remote-tool launch | Storm-1811, Storm-2410, Black Basta, 2026 help-desk impersonation | ✅ | `MDO-02a` Teams (High), `MDO-02b` RMM tool (High) | T1566.004, T1219, T1667 |
| 03 | QR code phishing (quishing) | Tycoon2FA, Rockstar 2FA kits | ✅ | `MDO-03` (Medium) | T1566.002 |
| 04 | Direct Send / internal-domain spoofing | Voicemail and HR-lure campaigns | ✅ | `MDO-04` (Medium) | T1656, T1566 |
| 05 | HTML / SVG smuggling attachments | SVG phishing, HTML-smuggled loaders | ✅ | `MDO-05` (Medium) | T1027.006, T1566.001 |
| 06 | AiTM phishing click, then sign-in from a new IP | Storm-1167, Tycoon2FA, EvilProxy | ✅ | `MDO-06` (High) | T1557, T1539, T1566.002 |
| 07 | Device code phishing | Storm-2372 | ✅ | `MDO-07` (High) | T1528, T1566.002 |
| 08 | BEC / user, domain, and brand impersonation | BEC groups (for example Storm-1152 infrastructure) | ✅ | `MDO-08` (Medium) | T1656, T1566 |
| 09 | Callback phishing (TOAD) | Luna Moth / Silent Ransom, BazarCall | ✅ | Workbook only | T1566.003 |
| 10 | Compromised account sending outbound spam/phish | Post-ATO internal phishing | ✅ | `MDO-10` (High) | T1534, T1078.004 |
| 11 | Malicious mail still in inbox (ZAP missed or failed) | Any | ✅ | `MDO-11` (High) | T1566 |
| 12 | Inbox or forwarding rule created after phish exposure | BEC / AiTM follow-on | ✅ | `MDO-12` (High) | T1114.003, T1564.008 |
| 13 | Look-alike and newly seen sender domains | BEC, typosquatting | ✅ | Workbook only | T1583.001 |
| 14 | Mail flagged by MDO's **LLM content analysis** (intent-based detection) | Novel, well-written lures (often AI-assisted) | ✅ | `MDO-14` (Medium) | T1566 |
| 15 | **Attack sequences** (S1-S11): risky sign-in, then inbox rule / MFA registration / OAuth consent / mail burst / mass download; rule, then finance mail out; attachment, then execution; phish click, then risky sign-in, then rule; help-desk reset, then new country; external Teams contact, then remote tool, then payload; deepfake call, then account or payment change | Storm-1167 (AiTM/BEC), Octo Tempest, Storm-0501, consent phishing, cross-tenant help-desk impersonation | ✅ | `MDO-S1`, `MDO-S2`, `MDO-S3`, `MDO-S6`, `MDO-S8`, `MDO-S10` (High) | T1564.008, T1114.003, T1556.006, T1528, T1534, T1557, T1219, T1547.001 |
| 16 | **Teams threats**: malicious external chats not remediated, post-delivery (ZAP) results, Teams URL clicks, external callers by tenant and account type, screen-share activity on external calls, same party chatting and calling, deepfake (synthetic media) detections | Storm-1811, Storm-2410, cross-tenant help-desk impersonation, AI voice/video fraud | ✅ | `MDO-16a` message not remediated (Medium), `MDO-16b` external call then RMM tool (High), `MDO-16c` deepfake in call (High) | T1566.003, T1566.004, T1219, T1656 |
| 17 | **Allow-list overrides**: phish or malware delivered because an org or user allow overrode the verdict, business-service brand spoofs, overridden threats still in the inbox, Tenant Allow/Block List allow changes | Brand-spoof phishing (DocuSign, Adobe and similar) | ✅ | `MDO-17` (Medium) | T1566, T1562 |

Anomalies 09 and 13 are workbook-only. Without message-body content or domain-age data, they produce too many false positives to alert on. Tab 14 shows mail that Microsoft's large language models flagged, and highlights **LLM-only** catches, where no reputation, detonation, or impersonation signal also fired. Those are the best available stand-in for novel or AI-assisted lures. It does *not* prove that an attacker used AI; nothing in the email data can show that. Its detection, `MDO-14`, alerts only when LLM-flagged mail is still in the inbox, and reports whether it was LLM-only and whether the recipient clicked. When the verdict is Phish or Malware it can fire together with `MDO-11`; Defender groups both alerts into one incident.

### Attack sequences (tab 15)

Single events such as a new inbox rule are noisy. The same event shortly after a risky sign-in, for the same user, is not. Tab 15 joins steps per user:

| Seq | Chain | Window | Detection |
|---|---|---|---|
| S1 | Risky sign-in (Entra ID Protection, medium/high) -> inbox or forwarding rule that hides or forwards mail. Scored for forwarding, finance keywords, an obfuscated rule name (`.`, `..`) and same IP as the risky sign-in | 24h | `MDO-S1` |
| S2 | Risky sign-in -> new MFA / security info registered (workbook also shows device registration) | 24h | `MDO-S2` |
| S3 | Risky sign-in -> OAuth app consent | 24h | `MDO-S3` |
| S4 | Risky sign-in -> outbound/internal mail burst (internal phishing) | 24h | Workbook only |
| S5 | Risky sign-in -> mass SharePoint/OneDrive download or sharing | 24h | Workbook only |
| S6 | Suspicious inbox rule -> outbound mail with finance/payment language (BEC thread hijack) | 72h | `MDO-S6` |
| S7 | Risky attachment delivered -> file written to a device -> script host / LOLBin launched | 24h + 1h | Workbook only |
| S8 | Phish click -> risky sign-in (2h) -> inbox rule (24h): the full AiTM chain | 26h | `MDO-S8` |
| S9 | Help-desk style password reset or MFA change -> sign-in from a country not seen in the prior 30 days | 24h | Workbook only |
| S10 | External Teams chat or call -> remote-access tool -> silent MSI install, Node.js loader from AppData, or EdgeUpdate-named Run key / Startup persistence on the same device | 4h + 4h | `MDO-S10` |
| S11 | Deepfake detected in a Teams call -> a participant has a risky sign-in, MFA or password change, new inbox rule, or sends finance mail externally | 24h | Workbook only |

A "Users hit by more than one sequence" table ranks users who show several chains.

### Teams threats and allow-list overrides (tabs 16 and 17)

Defender for Office 365 now records Teams activity in Advanced Hunting: messages (`MessageEvents`), post-delivery ZAP and admin actions (`MessagePostDeliveryEvents`), URLs (`MessageUrlInfo`), clicks (`UrlClickEvents` with workload Teams), calls (`CallActivityEvents`) and deepfake detections (`SyntheticMediaDetectionEvents`). Tab 16 and `MDO-16a`-`MDO-16c` use them. External callers are identified by account type (consumer, PSTN, Azure Communication Services, unauthenticated) or a tenant different from the recipient's, never by display name: Microsoft reported in Q3 2026 that actors moved from "Help Desk" names to ordinary personal names. Tab 02 now includes external calls too.

Tab 17 follows Microsoft's Q3 2026 email threat report, which found that a large share of delivered phishing got through because of tenant or user allow rules. It uses the `OrgLevelAction`/`UserLevelAction` override columns and excludes phishing simulation and SecOps mailbox policies. In the workbook, earlier steps look back 3 days before the selected time range. `MDO-S1` overlaps `MDO-12` and `MDO-S8` overlaps `MDO-06`/`MDO-12`; Defender correlates them into the same incident.

## Repository layout

```
version.json                    # Current release; read by the update checks
Workbook/
  Phish-and-Chats.json       # Workbook gallery template (paste into Advanced Editor)
  azuredeploy.json              # ARM template that deploys the workbook
Report/
  Export-PhishAndChatsReport.ps1 # Runs the workbook queries and writes an HTML findings report
CustomDetections/
  detections.json               # Rule metadata: severity, frequency, entities, MITRE
  Queries/*.kql                 # One KQL query per custom detection
  Deploy-CustomDetections.ps1   # Creates or updates the rules through Microsoft Graph
```

## Prerequisites

| Requirement | Used by |
|---|---|
| Microsoft Defender for Office 365 Plan 2 | Everything (Email* and UrlClickEvents tables) |
| Microsoft Sentinel **Microsoft Defender XDR** connector streaming `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, `UrlClickEvents`, `CloudAppEvents` | Workbook |
| `DeviceProcessEvents`, `DeviceFileEvents`, `DeviceRegistryEvents` (Defender for Endpoint) | Workbook tabs 02 and 15 (S7, S10), `MDO-02b`, `MDO-16b`, `MDO-S10` |
| Teams tables (optional): `MessageEvents`, `MessagePostDeliveryEvents`, `MessageUrlInfo`, `CallActivityEvents` | Workbook tabs 02, 15 (S10, S11) and 16, `MDO-02a`, `MDO-16a`, `MDO-16b`, `MDO-S10` |
| `SyntheticMediaDetectionEvents` (optional, needs an approved deepfake detection engine: Microsoft, GetReal, Pindrop, Reality Defender or Resemble AI) | Workbook tabs 15 (S11) and 16, `MDO-16c` |
| Microsoft Entra ID connector (`SigninLogs`, `AuditLogs`, `AADUserRiskEvents`) | Workbook tabs 06, 07 and 15 |
| Entra ID P2 (`EntraIdSignInEvents` in Advanced Hunting, ID Protection risk levels) | `MDO-06`, `MDO-07`, `MDO-S1`, `MDO-S2`, `MDO-S3`, `MDO-S8`, tab 15 |
| UEBA (`IdentityInfo`) | Workbook tab 08 display-name match (optional) |
| Defender for Cloud Apps Microsoft 365 connector (`CloudAppEvents`, including Entra ID audit events) | Tabs 12 and 15, `MDO-12`, `MDO-S1`-`MDO-S8` |

Workbook queries that depend on optional tables use `union isfuzzy=true`, so a missing table shows "no data" instead of an error.

## Deploy the workbook

**Option 1: Deploy to Azure**

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhomelabber%2FPhish-and-Chats%2Fmain%2FWorkbook%2Fazuredeploy.json)

Pick the resource group that contains your Sentinel workspace and provide the workspace's full resource ID.

**Option 2: Paste the template**

1. In Microsoft Sentinel, go to **Workbooks**, select **+ Add workbook**, then **Edit**, then **Advanced Editor** (`</>`).
2. Replace the contents with [`Workbook/Phish-and-Chats.json`](Workbook/Phish-and-Chats.json), then select **Apply** and **Save**.

**Option 3: Azure CLI**

```bash
az deployment group create -g <resource-group> \
  --template-uri https://raw.githubusercontent.com/homelabber/Phish-and-Chats/main/Workbook/azuredeploy.json \
  --parameters workspaceResourceId=<workspace-resource-id>
```

## Export an HTML report

[`Report/Export-PhishAndChatsReport.ps1`](Report/Export-PhishAndChatsReport.ps1) runs every workbook query against your workspace for a time range and writes **one self-contained HTML file**: no external scripts, fonts, or images. You can attach it to an incident, email it, or open it offline. The workbook doesn't need to be deployed. The script reads the queries from `Workbook/Phish-and-Chats.json` at run time, so the report always matches your copy of the workbook.

The report contains:

- A header with the workspace, time range, and query counts.
- A tab index with **hits/queries** badges, plus an *only show queries that returned results* filter.
- Each tab's description, followed by its results:
  - tiles as cards, with non-zero counts highlighted
  - bar and pie charts as bars
  - time charts as inline SVG
  - tables as sortable tables
- Failed queries shown inline with the API error, so one missing table doesn't sink the whole report.

It prints cleanly, with one tab per page.

**Requirements**

- PowerShell 7 (recommended) or Windows PowerShell 5.1.
- An identity with read access to the workspace, such as **Log Analytics Reader** or **Microsoft Sentinel Reader**.
- One way to get a token. The script tries `-AccessToken` first, then the current Az PowerShell context (`Connect-AzAccount`, Az.Accounts module), then the Azure CLI (`az login`).

```powershell
Connect-AzAccount

# Last 7 days, all tabs
.\Report\Export-PhishAndChatsReport.ps1 -WorkspaceId <workspace-guid> -TimeRange 7d

# Incident window, only the sequence and inbox-rule tabs, with the KQL behind each result
.\Report\Export-PhishAndChatsReport.ps1 -WorkspaceId <workspace-guid> `
  -StartTime '2026-10-01 08:00' -EndTime '2026-10-02 08:00' `
  -Tab sequences, inboxrules -IncludeQueries -OutputPath .\INC-1234-mail.html
```

| Parameter | Default | Description |
|---|---|---|
| `-WorkspaceId` | (required) | The workspace ID (GUID) from the Log Analytics workspace overview, not the resource ID |
| `-TimeRange` | `1d` | `1h`, `4h`, `12h`, `1d`, `3d`, `7d`, `14d` or `30d`, ending now |
| `-StartTime` / `-EndTime` | none / now | Absolute range, used instead of `-TimeRange` |
| `-Tab` | all | Tab ids or labels, wildcards allowed: `overview`, `bombing`, `bombteams`, `qr`, `directsend`, `smuggling`, `aitm`, `devicecode`, `bec`, `callback`, `outbound`, `zap`, `inboxrules`, `lookalike`, `llm`, `sequences`, `teams`, `overrides` |
| `-OutputPath` | `.\Phish-and-Chats-Report-<yyyyMMdd-HHmm>.html` | Where to write the report |
| `-MaxRows` | `250` | Rows shown per table. The full row count is always shown |
| `-IncludeQueries` | off | Adds the executed KQL under each result |
| `-Endpoint` | `https://api.loganalytics.io` | Use `https://api.loganalytics.us` for Azure Government |
| `-AccessToken` | none | A Log Analytics API bearer token, as a `SecureString` |
| `-SkipUpdateCheck` | off | Skips the check for a newer release (see [Staying up to date](#staying-up-to-date)) |

Notes:

- Queries the workbook pins to a longer window, such as the 90-day look-alike baseline and the attack sequences, keep that window in the report as well.
- The time grain for charts is picked from the range, the same way the workbook does it.
- **The report contains real mailbox addresses, IP addresses, and subjects.** Treat it as confidential, and store and share it like any other incident evidence.
- If you downloaded the script and your execution policy blocks it, review the script and then unblock it with `Unblock-File` or your organization's code-signing process. Don't lower the execution policy to run it.

## Deploy the custom detections

The script uses the Microsoft Graph `security/rules/detectionRules` API. It creates each rule, or updates it if the id already exists. By default, rules are created **disabled** so you can review and tune them first.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # once

# Create or update all rules, disabled
.\CustomDetections\Deploy-CustomDetections.ps1

# Deploy only some rules, enabled
.\CustomDetections\Deploy-CustomDetections.ps1 -Include 'mdo-01*','mdo-02*' -Status enabled

# Write the Graph request bodies to disk without calling Graph (review or CI)
.\CustomDetections\Deploy-CustomDetections.ps1 -ExportOnly .\out
```

You need the `CustomDetection.ReadWrite.All` delegated permission and a Defender role that can manage custom detections, such as Security Administrator.

If you prefer to do it by hand, open **Defender portal > Hunting > Advanced hunting**, paste a query from `CustomDetections/Queries`, select **Create detection rule**, and copy the settings from `detections.json`.

### Custom detection summary

| Id | Severity | Frequency | Key entities |
|---|---|---|---|
| mdo-01-email-bombing | Medium | 1h | Mailbox, account |
| mdo-02a-email-bomb-external-teams | High | 1h | Mailbox, account |
| mdo-02b-email-bomb-remote-tool | High | 1h | Device, account, file |
| mdo-03-qr-code-phishing | Medium | 1h | Mailbox, email message |
| mdo-04-direct-send-spoofing | Medium | 1h | Mailbox, email message, IP |
| mdo-05-html-svg-smuggling | Medium | 1h | Mailbox, email message, file |
| mdo-06-aitm-click-signin | High | 1h | Account, IP |
| mdo-07-device-code-phishing | High | 1h | Account, IP |
| mdo-08-bec-impersonation | Medium | 1h | Mailbox, email message |
| mdo-10-compromised-outbound-spam | High | 1h | Mailbox, account |
| mdo-11-malicious-mail-in-inbox | High | 3h | Mailbox, email message |
| mdo-12-inbox-rule-after-phish | High | 3h | Account, IP |
| mdo-14-llm-flagged-in-inbox | Medium | 3h | Mailbox, account, email message |
| mdo-s1-risky-signin-then-inbox-rule | High | 1h | Account, IP |
| mdo-s2-risky-signin-then-mfa-registration | High | 1h | Account, IP |
| mdo-s3-risky-signin-then-oauth-consent | High | 1h | Account, IP |
| mdo-s6-inbox-rule-then-finance-mail | High | 1h | Account, mailbox, email message |
| mdo-s8-aitm-full-chain | High | 1h | Account, IP |
| mdo-16a-teams-threat-not-remediated | Medium | 3h | Account, mailbox |
| mdo-16b-external-teams-call-remote-tool | High | 1h | Device, account, file |
| mdo-16c-deepfake-in-teams-call | High | 1h | Account |
| mdo-17-threat-delivered-by-allow-override | Medium | 1h | Mailbox, account, email message |
| mdo-s10-teams-remote-tool-payload | High | 1h | Device, account |

Each query's lookback matches the documented custom-detection window for its frequency: 1h runs look back 4h and 3h runs look back 12h. This allows for ingestion delay. The sequence detections (`MDO-S*`) use the same 4h lookback for the final step and extend it by the chain window for earlier steps.

## Staying up to date

Phish & Chats checks for updates and tells you when one is out, but it never installs anything by itself. You decide when new detection logic reaches your SOC.

- **Workbook:** the version banner at the top of the **Overview** tab reads [`version.json`](version.json) from this repo with `externaldata()`. It shows ✅ when you're current, or 🆕 with a link to the release notes when a newer version is out. If your workspace can't reach `raw.githubusercontent.com`, the banner shows an error and everything else keeps working. The installed version is also shown under the workbook title.
- **Scripts:** `Deploy-CustomDetections.ps1` and `Export-PhishAndChatsReport.ps1` compare your local `version.json` with the one on GitHub. If a newer release is out, they print a one-line warning. The check times out after 5 seconds, fails silently, and only reads a version number. Use `-SkipUpdateCheck` to turn it off, for example in offline or locked-down environments.

**To update:**

1. Pull or download the new release, then review the changes and the [release notes](https://github.com/homelabber/Phish-and-Chats/releases).
2. **Custom detections:** run `Deploy-CustomDetections.ps1` again. It updates existing rules by id, and new rules are created disabled unless you pass `-Status enabled`. Tuned thresholds are overwritten, so merge your changes into the `.kql` files first.
3. **Workbook:** update the workbook you already have, instead of adding a second copy:
   - **Paste:** open the workbook, select **Edit**, then **Advanced Editor**, replace the contents with the new `Workbook/Phish-and-Chats.json`, then **Apply** and **Save**.
   - **ARM/CLI:** pass your existing workbook's GUID, which is the last segment of its resource ID: `--parameters workspaceResourceId=<id> workbookId=<existing-guid>`. Without it, the template creates a new workbook.

For hands-off updates, fork the repo and connect your fork to [Microsoft Sentinel Repositories](https://learn.microsoft.com/azure/sentinel/ci-cd) for the workbook. Use a scheduled GitHub Action that runs the deploy script for the detections. Sync your fork on your own schedule, so a person reviews the changes before production does.

## Tuning

- **Thresholds** are `let` statements at the top of each `.kql` file (for example `taggedThreshold`, `volumeThreshold`, and `domainThreshold` for email bombing). Change them and re-run the deploy script.
- **Remote tools (02b, 16b, S10):** remove any RMM tool your help desk uses legitimately, or exclude your managed instances.
- **External Teams callers (16b, S10):** exclude partner tenants you call regularly. `CallActivityEvents` activity types aren't fully documented yet; use the workbook's *Call activity types* table to see what your tenant records.
- **Allow overrides (17):** every hit is a reason to narrow the allow that let it through, not to tune the query.
- **Direct Send (04):** if you have scanners or line-of-business apps that use Direct Send, exclude their IPs. Better still, move them to an authenticated connector and set `Set-OrganizationConfig -RejectDirectSend $true`.
- **HTML/SVG (05):** consider blocking these types outright with the anti-malware common attachments filter.
- **Sequences (S1-S10):** exclude break-glass or service accounts, and raise the risk level to high only if medium-risk sign-ins are too noisy. Tune `chainWindow` at the top of each `15-S*.kql` file.
- **Device code (07):** a Conditional Access *authentication flows* policy that blocks device code flow is the best mitigation.

## Disclaimer

This is community content provided as-is, without warranty. Test the queries in your own environment before enabling alerting.

## References

- [Email bombing detection in Defender for Office 365](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/protecting-your-organization-against-email-bombing/4399227)
- [Threat actors misusing Quick Assist in social engineering attacks](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/)
- [Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [From cookie theft to BEC: AiTM phishing (Storm-1167)](https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/)
- [Octo Tempest crosses boundaries](https://www.microsoft.com/en-us/security/blog/2023/10/25/octo-tempest-crosses-boundaries-to-facilitate-extortion-encryption-and-destruction/)
- [Impersonating IT support: threat actors turn a remote session into enterprise-wide access](https://www.microsoft.com/en-us/security/blog/2026/09/02/impersonating-it-support-threat-actors-turn-remote-session-into-enterprise-wide-access/)
- [Cross-tenant help-desk impersonation to data exfiltration](https://www.microsoft.com/en-us/security/blog/2026/04/18/crosstenant-helpdesk-impersonation-data-exfiltration-human-operated-intrusion-playbook/)
- [Help-desk impersonation and AD CS abuse](https://www.microsoft.com/en-us/security/blog/2026/10/30/help-desk-impersonation-ad-cs-abuse-investigating-esc1-esc8-intrusion-paths/)
- [Email threat landscape: Q3 2026 trends and insights](https://www.microsoft.com/en-us/security/blog/2026/11/05/email-threat-landscape-q3-2026-trends-and-insights/)
- [What's new in Defender for Office 365](https://learn.microsoft.com/en-us/defender-office-365/defender-for-office-365-whats-new)
- [CallActivityEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-callactivityevents-table)
- [SyntheticMediaDetectionEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-synthetic-media-detection-events)
- [Custom detection rules (Defender XDR)](https://learn.microsoft.com/defender-xdr/custom-detection-rules)
- [detectionRule resource type (Microsoft Graph)](https://learn.microsoft.com/graph/api/resources/security-detectionrule)
- [Advanced hunting email tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table)
