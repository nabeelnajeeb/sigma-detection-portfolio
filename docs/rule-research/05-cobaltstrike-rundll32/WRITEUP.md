# Technique 5: CobaltStrike Load by Rundll32 (T1218.011)

**Tactic:** Defense Evasion
**Dataset evidence:** 46 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process: a second diagnosed rule bug

Reviewing the 46 raw events revealed every one was a standard, Microsoft-signed system DLL being loaded via entirely ordinary, legitimate exported functions (`shell32.dll,SHCreateLocalServerRunDll`, `ieframe.dll,OpenURL`, `url.dll,FileProtocolHandler`, and similar). None referenced Cobalt Strike or any attacker-controlled DLL.

Reading the official rule's own logic explained why. Its `selection_rundll` block is written as a three-item list under Sigma's implicit list-OR syntax (`Image` ends with rundll32.exe, **OR** `OriginalFileName` is RUNDLL32.EXE, **OR** `CommandLine` contains 'rundll32.exe'/'rundll32 '). The rule's `condition: all of selection*` requires this block AND `selection_params` (the actual Cobalt Strike signal: `.dll` present, command line ending in `StartW`, Cobalt Strike's documented rundll32-based loader function) to both be true. Because `selection_rundll` alone is satisfied by simply being a rundll32.exe execution, true of all 46 events, the `.dll`/`StartW` narrowing condition is bypassable by any of the three unconditional sub-clauses in `selection_rundll`.

**This was confirmed via two independent Sigma implementations:**
1. Manual search across all 46 events for the actual `.dll` + `StartW` pattern returned zero matches.
2. Converting the official rule to Splunk syntax via `sigma-cli`/pySigma (`sigma convert -t splunk -p splunk_windows`) produced an ungrouped query `Image="*\rundll32.exe" OR OriginalFileName="RUNDLL32.EXE" OR CommandLine IN (...) CommandLine="*.dll*" CommandLine IN ("* StartW", "*,StartW")` with no parentheses grouping the OR clause, meaning by standard operator precedence (AND binds tighter than OR), only the third OR-branch is actually joined to the `.dll`/`StartW` condition; the first two branches fire completely unconditionally.

Both Chainsaw's native evaluation and pySigma's independent conversion are consistent with the same conclusion.

## My rule: a corrected version of the official rule

`rules/defense-evasion/cobaltstrike_rundll32_startw_corrected.yml`

Rather than building an entirely new detection, I corrected the existing rule's grouping: a single flat `Image|endswith: '\rundll32.exe'` condition, explicitly AND-combined via `condition: selection_rundll and selection_startw` with the `.dll`/`StartW` narrowing clause removing the ambiguity that let the original rule's real signal go unenforced.

## Test results

Converted to Splunk SPL and Elastic/Lucene syntax (see `splunk_query.txt` / `elastic_query.txt`), the corrected Splunk output now shows proper parenthetical grouping around the AND-combined conditions, direct visual confirmation the fix took effect.

Run via Chainsaw against the full sample dataset: **0 detections**, correctly excluding all 46 benign rundll32 executions that fooled the original rule. This dataset does not contain a genuine `StartW`-based Cobalt Strike execution, so this result cannot demonstrate a true positive empirically, only that the false positives are correctly rejected. As a partial substitute, I validated the rule's underlying logic against a synthetic (hand-constructed, not dataset-derived) command line matching the intended pattern (`rundll32.exe evil.dll,StartW`), confirming the `.dll`/`StartW` condition correctly evaluates to true when the real pattern is present.

## Comparison to the official SigmaHQ rule

The detection intent is identical, the official rule's own description and `selection_params` block make clear the `StartW` pattern was always meant to be the deciding signal. The fix is structural: enforcing the AND-relationship the rule's description already implies, rather than leaving it exposed to an unintended OR-bypass.

## Known limitations

- No true-positive validation against real attack data exists in this dataset; the rule's logic is confirmed correct via a synthetic test, not an observed genuine event.
- The diagnosed grouping issue is confirmed across two independent Sigma evaluation paths (Chainsaw, pySigma/Splunk conversion), but not exhaustively tested against every possible Sigma backend or engine.
- False-positive reasoning ("no known legitimate use of StartW outside Cobalt Strike") is based on the rule's own documented intent and public references, not independently verified against a broad legitimate-software corpus.
