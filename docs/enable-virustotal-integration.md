# VirusTotal Integration (extends FIM)

This builds directly on the File Integrity Monitoring setup in [`enable-fim.md`](./enable-fim.md) rather than standing alone: when FIM detects a new or changed file in a monitored path (e.g., a new file dropped in `C:\Windows\System32\Tasks`), Wazuh's VirusTotal integration automatically submits that file's hash to VirusTotal and reports back whether it's recognized as malicious — turning "a file changed" into "a file changed, and it's a known-bad hash" without any manual lookup.

## Why this matters for this specific lab

The persistence hunt and FIM rules in this repo can tell you *that* something changed in a sensitive location. They can't tell you on their own whether the dropped file is actually malicious or a legitimate admin action. VirusTotal enrichment closes that gap for the subset of cases where the file matches a hash VirusTotal already knows about — genuinely custom/novel attacker tooling won't match, but commodity malware and known offensive tools often will.

## Setup

1. Get a free VirusTotal API key from [virustotal.com](https://www.virustotal.com) (free tier: 4 requests/minute, sufficient for a lab).
2. On the Wazuh manager, add to `ossec.conf`:

```xml
<integration>
  <name>virustotal</name>
  <api_key>YOUR_VIRUSTOTAL_API_KEY_HERE</api_key>
  <group>syscheck</group>
  <alert_format>json</alert_format>
</integration>
```

3. `<group>syscheck</group>` scopes this to only fire VirusTotal lookups on FIM events — not every alert in the system, which would burn through the free-tier rate limit immediately.
4. Restart the manager: `systemctl restart wazuh-manager`

## Validating

1. Trigger a FIM event on a monitored path (see the test steps in `enable-fim.md`).
2. Check `/var/ossec/logs/integrations.log` for a VirusTotal lookup entry.
3. If the file hash is known to VirusTotal, a new alert appears with the scan results (detection ratio, e.g. "3/70 engines flagged this file"); unknown/clean files simply won't generate a follow-up alert.

## Known limitation

Free-tier VirusTotal rate limits (4 requests/minute) mean this doesn't scale past a lab environment — a production deployment would need a paid API tier or a queuing mechanism to avoid dropping lookups during a burst of FIM events. Worth stating this limitation directly rather than presenting the lab setup as production-ready as-is.
