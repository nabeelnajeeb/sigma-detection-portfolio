# Technique 8: EDR-Freeze Execution, Tightening Exercise (T1685)

**Tactic:** Defense Evasion / Impairment
**Dataset evidence:** 1489 hits in the initial smoke test using SigmaHQ's community rule, the highest volume of any rule examined in this project.

## Investigation process, the most rigorously isolated finding in this project

Reviewing raw matched events showed no relationship whatsoever to EDR-Freeze: `csrss.exe`, `winlogon.exe`, `cmd.exe`, `plink.exe` (a legitimate SSH client), none matching the rule's own two conditions (a filename pattern, or one of eight known IMPHASH values). Direct testing confirmed 0 of 1489 matched events satisfied either condition as written, a categorically larger discrepancy than any other rule examined.

Diagnosis required isolating multiple candidate mechanisms individually, each tested in a minimal standalone rule file, before reproducing the failure:

1. `selection_img`'s internal structure (a list-valued `Image|contains` line combined with a single-valued `Image|endswith` line, no leading dashes) was tested alone and confirmed to correctly enforce AND logic.
2. The `condition: 1 of selection_*` wildcard syntax was tested alone, against two separate impossible single-value conditions, and confirmed to correctly resolve to 0 matches.
3. Neither mechanism alone reproduced the bug. Combining them, an internally-AND block referenced through `1 of selection_*` (rather than by direct name), using the exact real EDR-Freeze filename and IMPHASH values, reproduced the full 1489-hit false-positive rate exactly.
4. A follow-up test confirmed this doesn't require two selection blocks: `selection_img` alone, referenced via `1 of selection_*`, independently reproduces all 1489 hits.

**Precise conclusion:** the bug is specific to referencing an internally-AND-structured selection block through the `1 of selection_*` wildcard condition syntax, in this Chainsaw/mapping toolchain. Both ingredients tested individually behave correctly; only their combination fails. This is a more precisely isolated finding than Techniques 5 and 7 (which identified a general operator-precedence/grouping category of issue), narrowed here to a specific condition-syntax construct.

## My rule

`rules/defense-evasion/edrfreeze_corrected_condition.yml`

Logic is identical to the official rule's detection intent (filename pattern OR known IMPHASH). The only change is avoiding the `1 of selection_*` wildcard syntax entirely, using an explicit `condition: selection_img or selection_imphash` referencing each block by name instead.

## Test results

Run via Chainsaw against the full sample dataset: **0 detections**, correctly excluding all 1489 false-positive events the original rule matched. This dataset does not contain genuine EDR-Freeze samples (a technique first documented in September 2025, likely postdating this sample dataset's assembly), so this result validates the false-positive fix but does not empirically confirm a true positive.

## Comparison to the official SigmaHQ rule

This is the fourth of four rules in this project (alongside Techniques 4, 5, and 6) found to have a meaningful gap between authored intent and actual matching behaviour in this toolchain, and the most severe by volume (1489 false positives, versus 45, 46, and 97 in the other three). Taken together, these four findings suggest genuine value in independently validating community detection rules against real sample data before trusting them in production, rather than assuming a rule's name and stated logic reflect its actual behaviour in a given toolchain.

## Known limitations

- No true-positive validation exists in this dataset; the fix is confirmed against false-positive rejection only.
- The root cause is isolated to the specific combination of an AND-block referenced via wildcard condition syntax, but the underlying reason Chainsaw's engine handles this combination differently from either piece in isolation was not traced further, this is a precisely isolated behavioural finding, not a source-code-level root cause.
- Not tested against a second independent hunting engine (only Chainsaw); pySigma's own condition-resolution behaviour for this specific construct was not separately verified, unlike Techniques 5-7.
