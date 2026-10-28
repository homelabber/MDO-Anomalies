# MDO Mail Anomalies

This repo has a **Microsoft Sentinel workbook** and a set of **Microsoft Defender XDR custom detections** for the mail-borne attack patterns that Microsoft Threat Intelligence tracks and Microsoft Defender for Office 365 (MDO) surfaces. It covers mail bombing and twelve other patterns, plus a view of mail flagged by MDO's LLM-based content analysis.

Detections are built as **custom detections** rather than Sentinel scheduled analytics rules, in line with Microsoft's move to unified detections in the Defender portal. They can run every hour, use the Advanced Hunting tables directly (including columns not streamed to Sentinel, such as `LatestDeliveryLocation`), and support response actions.

## Coverage

| # | Anomaly | Threat actors / campaigns | Workbook | Custom detection | MITRE ATT&CK |
|---|---------|---------------------------|:--------:|------------------|--------------|
| 01 | Email bombing (mail bombing) | Storm-1811, Black Basta affiliates | ✅ | `MDO-01` (Medium) | T1667 |
| 02 | Email bombing, then external Teams contact or remote-tool launch | Storm-1811, Storm-2410, Black Basta | ✅ | `MDO-02a` Teams (High), `MDO-02b` RMM tool (High) | T1566.004, T1219, T1667 |
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
| 14 | Mail flagged by MDO's **LLM content analysis** (intent-based detection) | Novel, well-written lures (often AI-assisted) | ✅ | Workbook only | T1566 |

Anomalies 09 and 13 are workbook-only. Without message-body content or domain-age data, they produce too many false positives to alert on. Tab 14 is a visibility view, not an alert. It shows mail that Microsoft's large language models flagged, and highlights **LLM-only** catches, where no reputation, detonation, or impersonation signal also fired. Those are the best available stand-in for novel or AI-assisted lures. It does *not* prove that an attacker used AI; nothing in the email data can show that.

## Repository layout

```
Workbook/
  MDO-Mail-Anomalies.json       # Workbook gallery template (paste into Advanced Editor)
  azuredeploy.json              # ARM template that deploys the workbook
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
| `DeviceProcessEvents` (Defender for Endpoint) | Workbook tab 02, `MDO-02b` |
| `MessageEvents` (Teams, optional) | Workbook tab 02, `MDO-02a` |
| Microsoft Entra ID connector (`SigninLogs`) | Workbook tabs 06 and 07 |
| Entra ID P2 (`EntraIdSignInEvents` in Advanced Hunting) | `MDO-06`, `MDO-07` |
| UEBA (`IdentityInfo`) | Workbook tab 08 display-name match (optional) |
| Defender for Cloud Apps Microsoft 365 connector (`CloudAppEvents`) | Tab 12, `MDO-12` |

Workbook queries that depend on optional tables use `union isfuzzy=true`, so a missing table shows "no data" instead of an error.

## Deploy the workbook

**Option 1: Deploy to Azure**

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fhomelabber%2FMDO-Anomalies%2Fmain%2FWorkbook%2Fazuredeploy.json)

Pick the resource group that contains your Sentinel workspace and provide the workspace's full resource ID.

**Option 2: Paste the template**

1. In Microsoft Sentinel, go to **Workbooks**, select **+ Add workbook**, then **Edit**, then **Advanced Editor** (`</>`).
2. Replace the contents with [`Workbook/MDO-Mail-Anomalies.json`](Workbook/MDO-Mail-Anomalies.json), then select **Apply** and **Save**.

**Option 3: Azure CLI**

```bash
az deployment group create -g <resource-group> \
  --template-uri https://raw.githubusercontent.com/homelabber/MDO-Anomalies/main/Workbook/azuredeploy.json \
  --parameters workspaceResourceId=<workspace-resource-id>
```

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

Each query's lookback matches the documented custom-detection window for its frequency: 1h runs look back 4h and 3h runs look back 12h. This allows for ingestion delay.

## Tuning

- **Thresholds** are `let` statements at the top of each `.kql` file (for example `taggedThreshold`, `volumeThreshold`, and `domainThreshold` for email bombing). Change them and re-run the deploy script.
- **Remote tools (02b):** remove any RMM tool your help desk uses legitimately, or exclude your managed instances.
- **Direct Send (04):** if you have scanners or line-of-business apps that use Direct Send, exclude their IPs. Better still, move them to an authenticated connector and set `Set-OrganizationConfig -RejectDirectSend $true`.
- **HTML/SVG (05):** consider blocking these types outright with the anti-malware common attachments filter.
- **Device code (07):** a Conditional Access *authentication flows* policy that blocks device code flow is the best mitigation.

## Disclaimer

This is community content provided as-is, without warranty. Test the queries in your own environment before enabling alerting.

## References

- [Email bombing detection in Defender for Office 365](https://techcommunity.microsoft.com/blog/microsoftdefenderforoffice365blog/protecting-your-organization-against-email-bombing/4399227)
- [Threat actors misusing Quick Assist in social engineering attacks](https://www.microsoft.com/en-us/security/blog/2024/05/15/threat-actors-misusing-quick-assist-in-social-engineering-attacks-leading-to-ransomware/)
- [Storm-2372 conducts device code phishing campaign](https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/)
- [Custom detection rules (Defender XDR)](https://learn.microsoft.com/defender-xdr/custom-detection-rules)
- [detectionRule resource type (Microsoft Graph)](https://learn.microsoft.com/graph/api/resources/security-detectionrule)
- [Advanced hunting email tables](https://learn.microsoft.com/defender-xdr/advanced-hunting-emailevents-table)
