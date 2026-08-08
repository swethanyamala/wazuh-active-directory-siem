# Hunt: Suspicious PowerShell / LOLBins Usage

**Tactic:** Execution (T1059.001 — PowerShell), Defense Evasion (T1027 — Obfuscated Files or Information)

## Hypothesis

Attackers frequently rely on PowerShell rather than dropping custom binaries, since it's a trusted, signed, already-installed tool ("living off the land") — the same reasoning documented for the LDAP recon technique in the companion Splunk repo. Common offensive PowerShell usage tends to cluster around a few recognizable patterns: base64-encoded commands (to evade simple string-matching in logs), in-memory execution via `IEX`/`Invoke-Expression`, remote payload download via `DownloadString`/`DownloadFile`, and known offensive tooling names.

## Hunt query (Wazuh Discover)

```
data.win.system.eventID:4104 AND data.win.eventdata.scriptBlockText:(*-enc* OR *-EncodedCommand* OR *IEX* OR *Invoke-Expression* OR *DownloadString* OR *DownloadFile* OR *Invoke-Mimikatz* OR *Invoke-WebRequest*)
```

## What to look for

- **Base64-encoded blocks** — Script Block Logging generally decodes these automatically before writing the log, so a hit here means the original command actively tried to obscure itself. That's a stronger signal than the keyword match alone.
- **Source host and account** — is this a workstation with no business reason to run this, or a legitimate admin/automation host?
- **Sequence with other hunts/rules** — PowerShell recon or download activity immediately preceding a Kerberoasting or DCSync alert in this repo turns a "worth a look" hit into a near-certain confirmed incident.

## Why this is a hunt, not a rule

Keyword matching on script content is inherently noisy — attackers rename functions, split strings, and obfuscate to dodge exactly this kind of static match, and legitimate admin scripts frequently contain some of these same keywords (`Invoke-WebRequest` is extremely common in normal automation). This is best run as a periodic analyst review with judgment applied per hit, not wired to auto-fire as a high-severity alert, or it will drown itself in false positives.
