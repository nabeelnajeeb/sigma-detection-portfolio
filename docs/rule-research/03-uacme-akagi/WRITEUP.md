# Technique 3: UACMe Akagi Execution (T1548.002)

**Tactic:** Privilege Escalation
**Dataset evidence:** 23 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process

I ran Chainsaw with SigmaHQ's existing `proc_creation_win_hktl_uacme.yml` rule to locate the 23 raw process-creation events it flags, then reviewed `Image`, `CommandLine`, `Product`, `Company`, and `Hashes` directly before reading the official rule's own logic.

## Reasoning

`Image` (filename and path) varied constantly across the 23 events: `UACME.exe`, `Fubuki.exe`, `Akagi.exe`, `Akagi64.exe`, `Clipup.exe`, `[1]consent.exe`, run from Desktop, AppData\Temp, and arbitrary custom folders, making filename or path an unreliable signal on its own. `Hashes` (full file SHA1/MD5/SHA256) also varied even between files sharing identical `Product`/`Company` metadata, consistent with UACMe being open-source and independently recompiled by different people; a full-file hash is not stable across rebuilds of identical source code.

`Product` was the one field that held steady: 22 of 23 events carried `Product: UACMe`, regardless of filename, path, or hash. The 23rd event (`Furutaka.exe`, `Product: TurlaDriverLoader`) is a different tool entirely and was treated as out of scope for this rule. Since UACMe has no legitimate production use, a single condition on `Product` alone is sufficient and unlike techniques 1 and 2, this rule doesn't need a second, narrowing condition, because there's no benign baseline usage to filter out.

## My rule

`rules/privilege-escalation/uacme_product_metadata.yml`

Logic: flag any process whose embedded `Product` metadata equals `UACMe`, regardless of filename, path, or hash.

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt`). Run via Chainsaw against the full sample dataset: **22 detections out of 23 candidate events**, correctly excluding the one `TurlaDriverLoader` event, verified against `my_rule_results.json`.

## Comparison to the official SigmaHQ rule

The official rule (`proc_creation_win_hktl_uacme.yml`) is more sophisticated than my single-field rule, using four independent signal groups (`condition: 1 of selection_*`, i.e. any one triggers a match): PE metadata (`Product`, `Company`, `Description`, `OriginalFileName`), filename (`Akagi.exe`/`Akagi64.exe` specifically), and **Import Hash (IMPHASH)**, not the full file hash.

I intially dismissed file hashing as an unreliable signal because independent recompilation changes the full file hash (confirmed directly in this dataset (events sharing identical `Product`/`Company` had different `SHA1`/`MD5`/`SHA256` values). IMPHASH is a different kind of hash: it fingerprints only the table of external Windows API functions a binary imports, which tends to stay stable across recompiles of the same source, even when the full file hash changes. The official rule can therefore safely use hashing as a signal, in a way the full-hash approach I thought we could not.

The official rule's `Company` list (`REvol Corp`, `APT 92`, `UG North`, `Hazardous Environments`, `CD Project Rekt`) also reveals something my rule doesn't capture: `Company` appears to vary because different versions/forks of UACMe (or different threat actors' rebuilds) ship different Company strings, my dataset only surfaced 3 of these 5 known values, and I initially treated `Company` as too unreliable to key on because of that variance. The official rule instead treats the *enumerated set* of known Company values as a usable signal, alongside and not instead of the `Product` field.

My rule is narrower by design: a single condition (`Product: UACMe`) that would have caught 22 of this dataset's 23 UACMe-related events (missing only event 19, a different tool entirely ( `TurlaDriverLoader` ) that the official rule also doesn't cover, since it's out of scope for this specific rule). The official rule's four-signal OR structure is more resilient against an attacker who successfully strips or edits the PE metadata, my rule would go completely blind if `Product` were altered, whereas the official rule would likely still catch the same binary via IMPHASH or filename.

## Known limitations

- Single point of failure: if `Product` metadata is stripped or edited, this rule catches nothing. The official rule's layered approach (PE metadata + filename + IMPHASH) is more resilient to this.
- Does not use IMPHASH, a more rebuild-resistant hash type than the full file hash I initially (correctly) ruled out.
- False-positive reasoning is based on manual review of sample data, not live production telemetry.
