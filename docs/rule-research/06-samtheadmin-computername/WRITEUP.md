# Technique 6: Suspicious Computer Name (SAMTHEADMIN Pattern) (T1078, CVE-2021-42278/42287)

**Tactic:** Initial Access / Persistence / Privilege Escalation
**Dataset evidence:** 45 hits in the initial smoke test using SigmaHQ's community rule.

## Investigation process, a third diagnosed engine discrepancy

Reviewing the 45 matched events showed `TargetUserName`/`SamAccountName` values such as `ICORP-DC$`, `EXCHANGE$`, and `WIN-77LTAPHIQ1R$`, none containing "SAMTHEADMIN" anywhere. A full search across all 45 events confirmed 0 contained that string in any field.

The official rule's two selection blocks each require two conditions on the same field: `startswith: 'SAMTHEADMIN-'` AND `endswith: '$'`. Testing each condition separately against the real data showed 45 of 45 events satisfy the `endswith: '$'` condition (expected, since Windows machine account names always end in `$` by convention) but 0 of 45 satisfy `startswith: 'SAMTHEADMIN-'`. This means Chainsaw matched every event in the rule against a two-condition AND block where only one condition was actually true, effectively flagging any machine authentication event in the environment.

**Unlike Technique 5, where the rule's own YAML structure was ambiguous, this rule's logic was independently confirmed correct through three separate checks:**
1. Converting the rule via `sigma convert -t splunk` produced `(SamAccountName="SAMTHEADMIN-*" SamAccountName="*$") OR (TargetUserName="SAMTHEADMIN-*" TargetUserName="*$")`, correctly showing both conditions ANDed within each parenthesized group (Splunk SPL implicitly ANDs adjacent terms).
2. Loading the rule directly via pySigma's Python library and inspecting its internal parsed representation showed `item_linking=<class 'sigma.conditions.ConditionAND'>` for both selection blocks, pySigma's own reference parser explicitly confirming AND-combination.
3. Manual field-by-field testing against all 45 real events confirmed the practical effect: 45/45 satisfy one condition, 0/45 satisfy the other, yet all 45 were matched.

This points to the disagreement being localized specifically to how Chainsaw evaluated this rule against this data, not to any ambiguity in the rule's authored logic or in how an independent, purpose-built Sigma parser interprets it. I want to be precise about the limit of this claim: I have not traced the specific internal cause within Chainsaw's own matching code, only confirmed a reproducible disagreement between Chainsaw's output and two independent reference implementations of the same rule.

## My rule

`rules/persistence/samtheadmin_computername_corrected.yml` (logic identical to the official rule, included to document re-validation, not as a new detection)

Since the rule's authored logic is correct and its intent is sound, no new detection logic was needed. The corrective action here was re-validation through an independent tool rather than a rewrite.

## Test results

Splunk and pySigma-parser validation both confirm the rule's logic is structurally sound (both selections correctly AND-combined). No corrected Chainsaw re-run was performed since the discrepancy appears specific to Chainsaw's evaluation rather than the rule file; re-testing the identical YAML through the same engine would be expected to reproduce the same result.

## Comparison to the official SigmaHQ rule

Not applicable in the usual sense. This entry documents an engine-level evaluation discrepancy rather than a rule design comparison. The official rule's logic is sound as written and as confirmed by two independent implementations.

## Known limitations

- Root cause within Chainsaw's matching engine was not traced to source; only a reproducible discrepancy between Chainsaw's output and two independent Sigma implementations was confirmed.
- No alternative Sigma-hunting engine (e.g. a pySigma-based hunter) was available in this project's toolchain to directly confirm correct behaviour against the same EVTX data; validation relied on rule-structure inspection rather than a second full end-to-end hunt.
