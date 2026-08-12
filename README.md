
## Technique 1: Local Accounts Discovery (T1033 / T1087.001)
[Full write-up](docs/rule-research/01-local-accounts-discovery/WRITEUP.md) | [Rule](rules/discovery/local_account_discovery_atypical_context.yml)

Detects whoami/net/net1 execution from an atypical parent process or non-interactive service account context, rather than plain command usage. Validated: 5/25 candidate events matched hand-reasoned analysis exactly.
