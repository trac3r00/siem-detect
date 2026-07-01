# Why I built siem-detect

## The gap

Sigma is the lingua franca of detection engineering — a portable YAML format
for describing "what bad looks like" in logs. But the tooling around it splits
into two camps:

1. **Converters** — [pySigma](https://github.com/SigmaHQ/pySigma) and
   [`sigma-cli`](https://github.com/SigmaHQ/sigma-cli) translate a Sigma rule
   into a Splunk / Elastic / Sentinel query. They never match a log line
   themselves; they hand you a query string and assume you own a SIEM.
2. **Platform-locked hunters** — [Hayabusa](https://github.com/Yamato-Security/hayabusa)
   and [Chainsaw](https://github.com/WithSecureLabs/chainsaw) *execute* Sigma
   beautifully, but only over **Windows EVTX**, as compiled Rust binaries.

If you just have a text log — an nginx access log, a Linux `auth.log`, a blob of
CloudTrail JSON — and you want to run Sigma against it *right now*, on any OS,
inside a script or a CI job, there isn't an obvious small tool. That's the gap
`siem-detect` fills.

## Design decisions

**Execute, don't convert.** The core of this project is a from-scratch
implementation of Sigma's matching semantics: the difference between a YAML list
(OR) and a YAML dict (AND), the ~15 field modifiers, and a real recursive-descent
evaluator for the `condition` mini-language (`(selection or other) and not
filter`, `1 of selection*`). Getting `contains|all`, `cidr`, and operator
precedence right is the actual engineering here.

**Logsource targeting is a feature, not decoration.** A naive engine runs every
rule against every event, so a Windows LSASS rule "fires" on an nginx log by
coincidence. `siem-detect` reads each parser's logsource descriptor and only
runs rules whose `logsource` is compatible — the same scoping Sigma itself
defines. This kills a whole class of false positives.

**Dependency-light on purpose.** One runtime dependency (PyYAML, which every
Sigma tool already needs). No compiled extensions, no SIEM, no cloud. It runs
in a lambda, a container, a triage notebook, or a pre-commit hook.

**Analyst-first output.** Every detection is mapped back to MITRE ATT&CK
(technique + tactic) parsed from the rule's `attack.*` tags, rolled up into a
verdict and a technique histogram. The markdown report is meant to be pasted
straight into a ticket; the JSON is meant to be piped into the next tool; the
`--fail-on` exit code is meant to gate CI.

## What it is not

It's not a SIEM, not a log shipper, and not a correlation engine — a single rule
matches a single event; multi-event correlation (Sigma's newer `correlation`
docs) is deliberately out of scope. For backend query generation, pySigma is the
right tool. `siem-detect` is the small, sharp thing for the "I have logs and
Sigma rules, match them" moment.
