# Hunt: Golden Ticket Indicators

**Tactic:** Credential Access — T1558.001 (Steal or Forge Kerberos Tickets: Golden Ticket)

## Hypothesis

A Golden Ticket is a forged TGT built with a stolen `krbtgt` hash — exactly the credential a successful DCSync (detected by rule `110001` in this repo) would expose. A forged TGT lets an attacker skip the normal initial authentication step entirely. Normal Kerberos usage always starts with an AS-REQ/AS-REP exchange (Event 4768) before a client can request any service ticket (Event 4769). A Golden Ticket holder can present a forged TGT and request service tickets (4769) **without ever generating a corresponding 4768** for that logon session, because they never actually authenticated.

This isn't a single-event pattern, so it's a poor fit for a static rule — it requires comparing two event types for the same account across a time window, which is exactly what a hunt is for.

## Hunt query (Wazuh Discover)

**Step 1 — list accounts with TGS requests in your window:**
```
data.win.system.eventID:4769
```
Note the distinct `data.win.eventdata.TargetUserName` values and timestamps.

**Step 2 — for each account, check for a preceding AS-REQ:**
```
data.win.system.eventID:4768 AND data.win.eventdata.TargetUserName:"<account_from_step_1>"
```

## What to look for

- A 4769 for an account with **no 4768 anywhere in a reasonably wide preceding window** (several hours, since a legitimate TGT is valid for the domain's configured lifetime — commonly 10 hours by default) is the core anomaly.
- Cross-reference the account against your known DCSync/replication-rights audit (see the Splunk repo's Stage 3 detection gap writeup) — if this account was ever exposed to a DCSync-capable position, treat any hit here as high-confidence.
- This is inherently a **coarse, manual heuristic** in a home lab; production environments typically automate this correlation with a proper UEBA tool or a scripted query against the Wazuh indexer rather than eyeballing Discover results. Worth stating that limitation plainly rather than overselling this as a polished automated capability.

## Known false-positive source

Ticket renewal (as opposed to fresh requests) can also produce 4769 without a fresh 4768 in some configurations — validate against your environment's actual renewal behavior before treating every unmatched pair as malicious.
