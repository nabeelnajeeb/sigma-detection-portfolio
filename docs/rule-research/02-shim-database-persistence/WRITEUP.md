# Technique 2: Shim Database Persistence (T1546.011)

**Tactic:** Persistence / Privilege Escalation
**Dataset evidence:** 30 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process

I ran Chainsaw with SigmaHQ's existing `registry_set_persistence_shim_database.yml` rule to locate the 30 raw registry events it flags, then reviewed the raw `Image`, `TargetObject`, `EventType`, and `Details` fields directly before reading the official rule's own logic.

## Reasoning

Grouping the 30 events by the GUID embedded in each registry path reduced them to 6 distinct shim installations — the other 24 events are metadata writes (description, path, install timestamp, database type) that `sdbinst.exe` writes alongside every install, legitimate or not, and don't by themselves indicate anything suspicious.

Of the 6 installs, 5 targeted `osk.exe` and 1 targeted `Utilman.exe` — both accessibility tools launchable pre-authentication from the Windows logon screen with SYSTEM privileges, a well-documented persistence/privilege-escalation abuse pattern (the same target-binary family relevant to Sticky-Keys-style logon screen backdoors, and notably the same `osk.exe` seen as an abused *parent process* in Technique 1 — worth flagging as a recurring theme in this dataset). One install (targeting `Utilman.exe`) also had an anomalous `DatabaseDescription` of `titi`, versus `New Database(1)` for every other install — a weak secondary signal, deliberately not used in the final rule (see below).

## My rule

`rules/persistence/shim_database_accessibility_targeting.yml`

Logic: flag any `sdbinst.exe`-created shim database whose target path names a known accessibility-tool binary. I chose not to include the anomalous-description signal in the final detection logic — a legitimate shim could plausibly carry any description text, and relying on it would be trivially bypassed by an attacker simply using the tool's default description. The accessibility-binary targeting is a more durable signal.

I extended the target list beyond what's directly present in this dataset (`osk.exe`, `Utilman.exe`) to include the full known accessibility-abuse family (`sethc.exe`, `Narrator.exe`, `Magnify.exe`, `DisplaySwitch.exe`) — a deliberate extrapolation from known technique research, not something validated against this sample data. See limitations below.

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt`). Run via Chainsaw against the full sample dataset: **6 detections out of 30 candidate events**, matching exactly the 6 `\Custom\...` shim-installation events (the `InstalledSDB` metadata writes correctly excluded), verified against `my_rule_results.json`.

## Comparison to the official SigmaHQ rule

[paste the comparison section above here]

## Known limitations

- 4 of the 6 target binaries (`sethc.exe`, `Narrator.exe`, `Magnify.exe`, `DisplaySwitch.exe`) are extrapolated from known technique research, not empirically validated against this dataset — only `osk.exe` and `Utilman.exe` are directly confirmed here.
- The rule would miss a shim targeting any binary outside this specific list, including entirely novel targets the official, broader rule would still catch.
- False-positive reasoning is based on manual review of sample data, not live production telemetry.
