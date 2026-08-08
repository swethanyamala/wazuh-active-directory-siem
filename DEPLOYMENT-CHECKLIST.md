# Deployment Checklist

One ordered run-through to deploy everything in this repo against your existing lab (DC + Windows 10 endpoint + Kali + Wazuh already built) and collect the evidence needed to call this repo complete. Check items off as you go — kick off step 6 (vulnerability feed download) early since it runs in the background while you do everything else.

## 1. Deploy the rules (~15 min)

- [ ] Append [`rules/local_rules.xml`](rules/local_rules.xml) to `/var/ossec/etc/rules/local_rules.xml` on the Wazuh manager
- [ ] Append [`rules/fim_rules.xml`](rules/fim_rules.xml) to the same file
- [ ] `systemctl restart wazuh-manager`
- [ ] Validate: `/var/ossec/bin/wazuh-logtest` — confirm no syntax errors

## 2. Enable auditing prerequisites on the DC (~20 min)

Follow [`docs/enable-auditing.md`](docs/enable-auditing.md) in full:
- [ ] Confirm Wazuh agent is reading the Security eventchannel
- [ ] Enable "Kerberos Service Ticket Operations" audit success (for 4769/Kerberoasting)
- [ ] Enable "Directory Service Access" audit success (for 4662/DCSync)
- [ ] Add the SACL on the domain root object (Everyone/Success, Replicating Directory Changes + Replicating Directory Changes All)
- [ ] Verify events reaching Wazuh: `tail -f /var/ossec/logs/alerts/alerts.log | grep -E "4769|4662"`

## 3. Enable FIM on the DC agent (~15 min)

Follow [`docs/enable-fim.md`](docs/enable-fim.md):
- [ ] Add the `<syscheck>` block (SYSVOL Policies, System32\Tasks, Run/RunOnce registry keys) to the DC agent's `ossec.conf`
- [ ] Restart the agent

## 4. Run the attacks from Kali (~40 min)

Follow [`docs/attack-simulation-and-testing.md`](docs/attack-simulation-and-testing.md):
- [ ] Create test SPN account if you don't already have one
- [ ] Simulate Kerberoasting — confirm rule `110010` fires (and `110012` if you hit 3+ SPNs)
- [ ] Simulate DCSync via Mimikatz — confirm rule `110001` fires
- [ ] **Screenshot:** alert list + one expanded alert per attack, showing decoded fields and MITRE tag

## 5. False-positive check (~15 min)

- [ ] Generate legitimate traffic (normal logons, file access) — confirm it does NOT fire
- [ ] Confirm real DC-to-DC replication is suppressed by rule `110002`
- [ ] **Screenshot:** this confirmed-true-negative result — more convincing than the attack screenshots alone

## 6. Trigger FIM (~10 min, can overlap with step 4-5)

- [ ] Run the test scheduled task command from `docs/enable-fim.md`
- [ ] Confirm rule `110021` fires
- [ ] **Screenshot:** the FIM alert
- [ ] Clean up the test task afterward

## 7. Enable Vulnerability Detection (~5 min config + up to 60 min feed download — start this early)

Follow [`docs/enable-vulnerability-detection.md`](docs/enable-vulnerability-detection.md):
- [ ] Add the `<vulnerability-detector>` block to the manager's `ossec.conf`, restart
- [ ] Wait for the CVE feed to download (check `ossec.log`)
- [ ] **Screenshot:** CVE findings against the DC agent, and write one sentence interpreting a real finding

## 8. Enable VirusTotal integration (~15 min)

Follow [`docs/enable-virustotal-integration.md`](docs/enable-virustotal-integration.md):
- [ ] Get a free VirusTotal API key
- [ ] Add the `<integration>` block, restart the manager
- [ ] Re-trigger a FIM event and confirm a VirusTotal lookup appears in `integrations.log`

## 9. MITRE ATT&CK dashboard (~5 min)

- [ ] Once alerts exist from steps 4/6, open the MITRE ATT&CK module in the Wazuh dashboard
- [ ] **Screenshot:** the matrix view showing your techniques highlighted

## 10. Wrap up (~15 min)

- [ ] Drop all screenshots into `screenshots/`
- [ ] Commit and push (or send them over and I'll push)

**Total: roughly 3-3.5 hours of active work**, plus the vulnerability feed download running in the background.
