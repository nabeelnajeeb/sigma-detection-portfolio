# Sigma Detection Engineering Portfolio

Hand-built Sigma detection rules developed from raw log analysis, tested against real attack sample data, and benchmarked against SigmaHQ's community rules, including four independently diagnosed and evidence-backed discrepancies between community rules' stated logic and their actual matching behaviour in this toolchain.

## What this is

Eight Windows attack techniques were selected from a broad smoke test (SigmaHQ's ~1300 community rules run against the [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) dataset via [Chainsaw](https://github.com/WithSecureLabs/chainsaw)), chosen to span distinct MITRE ATT&CK tactics rather than clustering in one area. For each technique, the process was the same:

1. Use the existing SigmaHQ community rule only as a *locator*, to find the relevant raw log events in the sample dataset.
2. Review the raw event fields directly and reason out an original detection pattern, before reading the official rule's own logic.
3. Write an original Sigma rule, convert it to Splunk SPL and Elastic/Lucene syntax via `sigma-cli`, and test it against the full sample dataset.
4. Compare the result against the official community rule's actual behaviour, and document where they agree, differ, or where the official rule itself is subtly incorrect.

## Notable finding: four confirmed community-rule discrepancies

While validating official SigmaHQ rules as locators, four of the eight rules examined showed a meaningful, evidence-backed gap between their stated detection logic and their actual matching behaviour in this toolchain (Chainsaw's Sigma evaluation, cross-checked against pySigma's independent parsing and Splunk-conversion output). These weren't assumed or guessed at. Each was isolated through direct testing against real data, and where possible, confirmed against a second independent Sigma implementation before being written up.

| Technique | Official rule hits | Root cause |
|---|---|---|
| [CobaltStrike Load by Rundll32](docs/rule-research/05-cobaltstrike-rundll32/WRITEUP.md) | 46 | Ungrouped OR/AND at a selection-block boundary, confirmed via Splunk conversion |
| [Samtheadmin Computer Name](docs/rule-research/06-samtheadmin-computername/WRITEUP.md) | 45 | AND condition not enforced in Chainsaw despite pySigma confirming correct logic |
| [Cobalt Strike Operator Bloopers](docs/rule-research/07-cobaltstrike-bloopers/WRITEUP.md) | 97 | Same ungrouped OR/AND category as above, isolated to a different structural point |
| [EDR-Freeze Execution](docs/rule-research/08-edrfreeze-tightening/WRITEUP.md) | 1489 | `1 of selection_*` wildcard syntax combined with an AND-structured block, isolated through systematic elimination testing |

## Techniques covered

| # | Technique | Tactic | Rule | Write-up |
|---|---|---|---|---|
| 1 | Local Accounts Discovery (T1033/T1087.001) | Discovery | [rule](rules/discovery/local_account_discovery_atypical_context.yml) | [write-up](docs/rule-research/01-local-accounts-discovery/WRITEUP.md) |
| 2 | Shim Database Persistence (T1546.011) | Persistence | [rule](rules/persistence/shim_database_accessibility_targeting.yml) | [write-up](docs/rule-research/02-shim-database-persistence/WRITEUP.md) |
| 3 | UACMe Akagi Execution (T1548.002) | Privilege Escalation | [rule](rules/privilege-escalation/uacme_product_metadata.yml) | [write-up](docs/rule-research/03-uacme-akagi/WRITEUP.md) |
| 4 | Non-Native Remote Execution Service (T1003.001) | Credential Access / Lateral Movement | [rule](rules/lateral-movement/nonnative_remote_exec_service.yml) | [write-up](docs/rule-research/04-crackmapexec/WRITEUP.md) |
| 5 | CobaltStrike Load by Rundll32 (T1218.011) | Defense Evasion | [rule](rules/defense-evasion/cobaltstrike_rundll32_startw_corrected.yml) | [write-up](docs/rule-research/05-cobaltstrike-rundll32/WRITEUP.md) |
| 6 | Samtheadmin Computer Name (T1078) | Initial Access / Persistence | [rule](rules/persistence/samtheadmin_computername_corrected.yml) | [write-up](docs/rule-research/06-samtheadmin-computername/WRITEUP.md) |
| 7 | Cobalt Strike Operator Bloopers (T1059.003) | Execution | [rule](rules/execution/cobaltstrike_bloopers_corrected.yml) | [write-up](docs/rule-research/07-cobaltstrike-bloopers/WRITEUP.md) |
| 8 (bonus) | EDR-Freeze Execution (T1685) | Defense Evasion | [rule](rules/defense-evasion/edrfreeze_corrected_condition.yml) | [write-up](docs/rule-research/08-edrfreeze-tightening/WRITEUP.md) |

## Repository structure
```

rules/ Original Sigma detection rules, organized by tactic
docs/rule-research/ Per-technique research: raw event JSON, SIEM-converted
queries, and a full write-up (investigation, reasoning,
test results, comparison to the official rule, limitations)
scripts/ Reusable helper scripts (e.g. show_cards.py, a condensed
viewer for Chainsaw's JSON output)

```
Raw log data (`data/EVTX-ATTACK-SAMPLES`, `data/sigma-official`) and the Chainsaw binary itself are excluded via `.gitignore`, as third-party tooling and datasets rather than original work.

## Methodology notes and honesty standards

A few deliberate practices were applied consistently across all eight write-ups, worth stating explicitly:

- **Reasoned false positives, not measured ones.** All false-positive analysis is based on manual review of the sample dataset, not live production telemetry. Every write-up states this distinction rather than implying a measured false-positive rate.
- **Extrapolated coverage is labeled as such.** Where a rule's scope was extended beyond what's directly present in the sample dataset (e.g. the full accessibility-tool binary family in Technique 2, or additional PsExec-family tools in Technique 4), this is explicitly separated from empirically validated coverage.
- **Confirmed-negative results are not overstated as confirmed-positive.** Where a corrected rule produces 0 detections because the sample dataset lacks a genuine positive example (Techniques 5, 7, 8), this is stated directly rather than presented as full validation.
- **Tooling claims are scoped to what was actually demonstrated.** For example, Splunk and Elastic were used only via `sigma-cli`'s query conversion, to validate rule portability and, in several cases, to diagnose grouping bugs. Neither product was actually installed or run against live data in this project.

## Tools used

- [Sigma](https://github.com/SigmaHQ/sigma) / [pySigma](https://github.com/SigmaHQ/pySigma) / [sigma-cli](https://github.com/SigmaHQ/sigma-cli), rule format, reference parsing, and SIEM query conversion
- [Chainsaw](https://github.com/WithSecureLabs/chainsaw), Sigma rule execution against raw EVTX log data
- [EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES), public, pre-labeled Windows event log dataset
- Python (standard library only) for JSON parsing, aggregation, and rule-behaviour verification scripts
