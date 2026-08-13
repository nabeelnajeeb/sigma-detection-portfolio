# Technique 3: UACMe Akagi Execution (T1548.002)

**Tactic:** Privilege Escalation
**Dataset evidence:** 23 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process

I ran Chainsaw with SigmaHQ's existing `proc_creation_win_hktl_uacme.yml` rule to locate the 23 raw process-creation events it flags, then reviewed `Image`, `CommandLine`, `Product`, `Company`, and `Hashes` directly before reading the official rule's own logic.

## Reasoning

`Image` (filename and path) varied constantly across the 23 events — `UACME.exe`, `Fubuki.exe`, `Akagi.exe`, `Akagi64.exe`, `Clipup.exe`, `[1]consent.exe`, run from Desktop, AppData\Temp, and arbitrary custom folders — making filename or path an unreliable signal on its own. `Hashes` (full file SHA1/MD5/SHA256) also varied even between files sharing identical `Product`/`Company` metadata, consistent with UACMe being open-source and independently recompiled by different people; a full-file hash is not stable across rebuilds of identical source code.

`Product` was the one field that held steady: 22 of 23 events carried `Product: UACMe`, regardless of filename, path, or hash. The 23rd event (`Furutaka.exe`, `Product: TurlaDriverLoader`) is a different tool entirely and was treated as out of scope for this rule. Since UACMe has no legitimate production use, a single condition on `Product` alone is sufficient — unlike techniques 1 and 2, this rule doesn't need a second, narrowing condition, because there's no benign baseline usage to filter out.

## My rule

`rules/privilege-escalation/uacme_product_metadata.yml`

Logic: flag any process whose embedded `Product` metadata equals `UACMe`, regardless of filename, path, or hash.

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt`). Run via Chainsaw against the full sample dataset: **22 detections out of 23 candidate events**, correctly excluding the one `TurlaDriverLoader` event, verified against `my_rule_results.json`.

## Comparison to the official SigmaHQ rule

[paste the comparison section above here]

## Known limitations

- Single point of failure: if `Product` metadata is stripped or edited, this rule catches nothing. The official rule's layered approach (PE metadata + filename + IMPHASH) is more resilient to this.
- Does not use IMPHASH, a more rebuild-resistant hash type than the full file hash I initially (correctly) ruled out.
- False-positive reasoning is based on manual review of sample data, not live production telemetry.
