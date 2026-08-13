# Technique 4: CrackMapExec Process Patterns (T1003.001)

**Tactic:** Credential Access
**Dataset evidence:** 360 hits in the initial smoke test using SigmaHQ's community rule — by far the highest count of any technique investigated.

## Investigation process — an anomaly, not a clean pattern

Reviewing the 360 raw events revealed something unexpected: the vast majority were core Windows system processes (`smss.exe`, `csrss.exe`, `winlogon.exe`, `services.exe`, dozens of `svchost.exe` instances) with entirely normal, minimal command lines and no relation to credential access whatsoever.

This did not match the official rule's actual detection logic, which specifically targets three LSASS credential-dumping command patterns: `tasklist` output piped to search for `lsass.exe`, a `comsvcs.dll`-based memory dump technique, and `procdump`-style process enumeration. None of these strings appeared in the 360 matched events I reviewed.

**Diagnosis:** the official rule's first selection block (`selection_lsass_dump1`) combines a `CommandLine|contains|all` condition with a separate `User|contains` condition listing `'AUTHORI'`/`'AUTORI'` (intended to match `NT AUTHORITY\...` across language locales). Every one of the 360 matched events runs as `NT AUTHORITY\SYSTEM`. This strongly suggests Chainsaw's evaluation of this rule is not correctly enforcing the `CommandLine` and `User` clauses as a combined AND condition within the same selection block — effectively matching on the `User` clause in isolation. I want to state this precisely: this is a strong, evidence-backed diagnosis based on correlating all sampled hits against the rule's structure, not a confirmed root-cause trace through Chainsaw's internal matching engine.

## Reasoning — pivoting to a genuine signal

Given the official rule's output wasn't usable as a locator for real credential-access indicators in this dataset, I searched the same 360 events manually for known lateral-movement/credential-access tooling artifacts instead. `PSEXESVC.exe` — the temporary service binary dropped only when a PsExec-style remote execution tool is used against a machine via SMB (notably including CrackMapExec's own `smbexec` execution module) — appeared 4 times. This binary does not exist on an unmodified Windows install; its presence is inherently a strong signal, requiring no secondary filtering condition (similar reasoning to Technique 3's UACMe rule).

## My rule

`rules/lateral-movement/nonnative_remote_exec_service.yml`

Logic: flag execution of `PSEXESVC.exe`, or either of two well-documented tools in the same family — `PAExec.exe` (an open-source PsExec clone) and `RemComSvc.exe` (another open-source remote-execution tool, also used directly by CrackMapExec's `smbexec` module).

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt`). Run via Chainsaw against the full sample dataset: **4 detections**, all confirmed genuine `PSEXESVC.exe` executions (verified via `my_rule_results.json`) — an initial manual count of 2 undercounted due to deduplicating on exact string match, which missed quoting/casing variants of the same binary across separate real events. `PAExec.exe` and `RemComSvc.exe` did not appear in this dataset; their inclusion is extrapolated from known technique research, not empirically validated here.

## Comparison to the official SigmaHQ rule

Not a direct like-for-like comparison, given the diagnosed anomaly above — the official rule's *intended* logic (LSASS dump command detection) targets a genuinely different, narrower behaviour than my rule (remote-execution service artifact detection), and as observed in this environment, its actual matching behaviour did not reflect that intended logic at all. My rule was developed independently of the official rule's approach, using a different signal entirely (a non-native binary artifact rather than a command-line pattern).

## Known limitations

- The rule-parsing anomaly is diagnosed from strong correlation across all matched events, not a confirmed internal trace of Chainsaw's rule engine — worth re-testing with a different Sigma-to-engine toolchain (e.g. direct pySigma evaluation) if pursued further.
- `PAExec.exe`/`RemComSvc.exe` coverage is extrapolated, not validated against this dataset.
- With only 4 confirming events for the empirically-validated binary, this is a thin sample; false-positive reasoning is theoretical (no legitimate use case for this binary), not measured.
