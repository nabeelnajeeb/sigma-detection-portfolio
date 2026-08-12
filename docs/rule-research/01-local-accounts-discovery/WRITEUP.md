# Technique 1: Local Accounts Discovery (T1033 / T1087.001)

**Tactic:** Discovery
**Dataset evidence:** 25 hits in the initial smoke test using SigmaHQ's community rule, confirming this technique is well-represented in the EVTX-ATTACK-SAMPLES dataset.

## Investigation process

I ran Chainsaw with SigmaHQ's existing `proc_creation_win_susp_local_system_owner_account_discovery.yml` rule against the full sample dataset to locate the 25 raw log events it flags. Rather than reading that rule's own logic first, I reviewed the raw event data directly — `Image`, `CommandLine`, `ParentImage`, and `User` — across all 25 matches, to independently form a view on what makes these events suspicious.

## Reasoning

`whoami`, `net user`, and `net1 user` are common, largely benign administrative commands on their own — 20 of the 25 matches were launched from a normal interactive shell (`cmd.exe` or `powershell.exe`) by an ordinary interactive user, which is unremarkable behaviour. A rule that flags the command alone would be far too noisy for real use.

The 5 events that stood out shared one of two properties instead:
- **An atypical parent process** with no legitimate reason to launch a discovery command — `osk.exe` (Windows' On-Screen Keyboard, a known accessibility-tool abuse vector for SYSTEM-level shells) and `EfsPotato.exe` (a known privilege-escalation exploit tool, not a native Windows binary).
- **An atypical account context** — `net`/`net1 user` executed under `IIS APPPOOL\DefaultAppPool`, a web server service account with no legitimate reason to be enumerating local accounts interactively.

## My rule

`rules/discovery/local_account_discovery_atypical_context.yml`

Logic: flag `whoami`/`net`/`net1` execution **when** the parent process is one of a small set of known-abuse binaries **or** the executing account is a non-interactive service account — rather than trying to define "every abnormal parent," which is an unbounded problem. This is a blocklist-of-known-offenders approach, not an attempted allowlist of "everything normal" — narrower in theoretical coverage, but concrete and testable.

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt` in this folder). Run against the full sample dataset via Chainsaw: **5 detections out of the original 25 candidate events**, matching exactly the 5 events identified through manual review (verified via `scripts/show_cards.py` against `my_rule_results.json`).

## Comparison to the official SigmaHQ rule

The official rule (`proc_creation_win_susp_local_system_owner_account_discovery.yml`) and my rule take genuinely different approaches, not just different levels of detail:

**Coverage:** The official rule is far broader — it also covers `quser`, `qwinsta`, `wmic useraccount get`, `cmdkey /l`, and `cmd /c dir \Users\`, in addition to `whoami`/`net`/`net1`. My rule only covers the three commands actually present in this sample dataset.

**Filtering philosophy — this is the real difference.** The official rule does not look at `ParentImage` or `User` at all. Instead, it uses *exclusion filters* on the command line itself — e.g. for `net user`, it explicitly excludes administrative flag usage (`/domain`, `/add`, `/delete`, etc.) to avoid flagging legitimate account management, but otherwise flags `net user` unconditionally. For `whoami`, `quser`, and `qwinsta`, there's no filtering at all — every occurrence is flagged, regardless of parent process or account context. This is reflected in its `level: low` rating: it's designed as a broad, high-recall triage feed that expects a human analyst to review and dismiss the (likely many) benign hits.

My rule instead adds a second, independent signal — parent process and account context — to filter *at the rule level* rather than relying on downstream triage. This trades recall for precision: it would miss a genuinely malicious `whoami` launched from an ordinary `cmd.exe` shell (which the official rule would still catch), but it surfaces a much smaller, higher-confidence set of hits (5 vs. 25 on this dataset) without needing a human to manually rule out the ~80% that were benign.

**Neither is simply "better"** — they represent two legitimate, common detection-engineering philosophies: broad-and-low-severity (cast a wide net, let a SOC analyst triage) versus narrow-and-elevated-severity (do more filtering work up front, escalate fewer but higher-confidence events). In a real SOC, both tiers are useful together: the official rule's broad version as a low-priority background feed, and a rule like mine as a higher-priority escalation on top of it.

## Known limitations

- The "atypical parent" list (`osk.exe`, `EfsPotato.exe`) is a known-offender blocklist, not exhaustive — it would miss a novel or unlisted abuse tool used the same way. This is a deliberate, named trade-off, not an oversight.
- False-positive reasoning here is based on manual review of this sample dataset, not measured against live, noisy production telemetry — a live environment could surface false positives (e.g. legitimate service accounts with broader permissions) not represented in this data.
EOF
