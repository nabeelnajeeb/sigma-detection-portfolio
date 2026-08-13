# Technique 7: Operator Bloopers Cobalt Strike Commands (T1059.003)

**Tactic:** Execution
**Dataset evidence:** 97 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process, a fourth diagnosed operator-precedence issue

Cobalt Strike's "Operator Bloopers" refers to a small set of distinctive, documented command-syntax mistakes (e.g. `psinject`, `getsystem`, `execute-assembly` typed directly into a CMD shell rather than the Cobalt Strike console). These strings are specific enough that their presence is meaningful signal regardless of whether the resulting command succeeded, since no legitimate administrative activity would coincidentally produce them.

Reviewing the 97 matched events showed ordinary `cmd.exe` activity (`ipconfig`, `whoami /groups`, various legitimate-looking scripted commands, along with clearly malicious but topically unrelated activity like reverse shells and lateral movement commands), none containing any of the nine documented blooper strings. A full check across all 97 confirmed 0 contain any of them.

The official rule has two blocks: `selection_img` (an OR: `OriginalFileName` is `Cmd.Exe`, or `Image` ends with `\cmd.exe`) and `selection_cli` (an AND: command line starts with a shell-invocation pattern, AND contains one of the nine blooper strings). `condition: all of selection_*` should require both blocks true. Converting the rule via `sigma convert -t splunk` produced an ungrouped query with no parentheses separating `selection_img`'s OR from `selection_cli`'s conditions, meaning by standard operator precedence only the second OR-branch of `selection_img` was actually joined to `selection_cli`, an operator-precedence pattern consistent with Technique 5's finding, but manifesting at a different structural point in the rule.

Loading the rule via pySigma's own parser confirmed `selection_cli: item_linking=ConditionAND` (correctly AND, as authored) and `selection_img: item_linking=ConditionOR` (correctly OR, as authored, since it's meant to represent two alternative ways to identify cmd.exe). Both internal groupings are individually correct; the issue is the missing grouping between the two named blocks once assembled into the full query.

Direct verification against the 97 matched events confirmed the practical effect precisely: 26 events matched via the `OriginalFileName="Cmd.Exe"` branch alone, and 71 matched via the `Image|endswith: '\cmd.exe'` branch alone, both branches independently bypassing `selection_cli` entirely, meaning essentially any cmd.exe execution in the dataset satisfied the rule regardless of its command-line content.

## My rule

No new detection logic was required, same as Technique 6. The rule's authored logic (once correctly grouped) is sound; the issue is a structural/evaluation discrepancy, not a design flaw. A corrected version with explicit grouping is included to document the fix:

`rules/execution/cobaltstrike_bloopers_corrected.yml`

```yaml
detection:
    selection_img:
        - OriginalFileName: 'Cmd.Exe'
        - Image|endswith: '\cmd.exe'
    selection_cli:
        CommandLine|startswith:
            - 'cmd '
            - 'cmd.exe'
            - 'c:\windows\system32\cmd.exe'
        CommandLine|contains:
            - 'psinject'
            - 'spawnas'
            - 'make_token'
            - 'remote-exec'
            - 'rev2self'
            - 'dcsync'
            - 'logonpasswords'
            - 'execute-assembly'
            - 'getsystem'
    condition: selection_img and selection_cli
```

The only substantive change from the official rule is the explicit `and` between named blocks in `condition:`, removing any ambiguity in how the two blocks combine once converted to a flat query.

## Test results

Splunk conversion and pySigma internal parsing both confirm `selection_cli`'s AND logic and `selection_img`'s OR logic are individually correct, and that the two blocks lack explicit grouping once assembled. Direct testing against real data confirmed the practical consequence precisely: 26 events via one OR-branch, 71 via the other, 0 containing any genuine blooper string, for a combined 97, exactly matching the original hit count. No real Cobalt Strike blooper events exist in this dataset to empirically confirm a true positive with the corrected rule; as with Technique 5, this is a confirmed-negative validation, not a confirmed-positive one.

## Comparison to the official SigmaHQ rule

This is the second confirmed instance (alongside Technique 5) of the same underlying class of issue, an ungrouped OR/AND boundary at the top level of a multi-block Sigma rule causing a narrowing condition to become unintentionally optional. Technique 5's instance affected a single-branch OR; this instance affects both branches of a two-branch OR independently. 

## Known limitations

- No true-positive validation exists in this dataset for the corrected rule; validated only against confirmed-negative real data plus the rule's documented blooper-string list.
- The grouping fix addresses the specific issue found; a more robust long-term fix would involve testing the rule across multiple independent Sigma-consuming engines beyond Chainsaw and pySigma's Splunk backend.
