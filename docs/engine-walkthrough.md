# The engine: how a Sigma rule becomes a match

This walkthrough traces one rule through the engine so the matching semantics
are concrete. Source: [`src/siem_detect/sigma.py`](../src/siem_detect/sigma.py).

## The rule

```yaml
title: SSH Brute Force - Repeated Failed Password From External IP
logsource:
  product: linux
  service: auth
detection:
  selection:
    program: sshd
    outcome: failure
  filter_internal:
    src_ip|cidr:
      - 10.0.0.0/8
      - 172.16.0.0/12
      - 192.168.0.0/16
      - 127.0.0.0/8
  condition: selection and not filter_internal
tags:
  - attack.credential_access
  - attack.t1110.001
level: medium
```

## Step 1 — logsource targeting

`auth.log` parses to `{"product": "linux", "service": "auth"}`. Before scanning,
`Engine.scan()` drops every rule whose `logsource` is incompatible, so this rule
is active but the Windows/AWS rules are not. Empty rule constraints match
anything.

## Step 2 — selections compile to matchers

Each selection becomes a `Selection` object:

- `selection` is a **dict** → implicit **AND**: `program == "sshd"` **and**
  `outcome == "failure"`.
- `filter_internal` has one field with a **list** value and the `|cidr`
  modifier → `src_ip` is in **any** (OR) of the four networks.

The `program: sshd` pair compiles to a `FieldMatcher`. Because the value has no
`|modifier` and no `*`, it's an exact (case-insensitive) compare. `src_ip|cidr`
compiles the four strings into `ipaddress.ip_network` objects; matching parses
the event's `src_ip` and tests membership.

## Step 3 — the condition evaluator

`selection and not filter_internal` is tokenized and evaluated by a
recursive-descent parser (`ConditionEvaluator`) with the precedence
`or < and < not < atom`. For each event it resolves the named selections to
booleans and combines them. Parentheses and `1 of x*` / `all of x*` are handled
in `_parse_atom` / `_quantifier`.

Given the event:

```
{"program": "sshd", "outcome": "failure", "src_ip": "203.0.113.9", ...}
```

- `selection` → True (sshd + failure)
- `filter_internal` → False (203.0.113.9 is not RFC1918)
- `selection and not filter_internal` → **True** → detection fires.

An internal source (`10.1.2.3`) makes `filter_internal` True, so the rule
correctly stays silent.

## Step 4 — MITRE roll-up

`rule.mitre_techniques` regexes the `attack.tNNNN[.NNN]` tags into
`["T1110.001"]`; `mitre_tactics` maps the tactic tags. The `Report` aggregates
these across all detections into the histogram shown in the summary.

## Field modifiers reference

| Modifier          | Meaning                                             |
|-------------------|-----------------------------------------------------|
| `contains`        | substring match                                     |
| `contains|all`    | **every** listed value must be a substring          |
| `startswith` / `endswith` | prefix / suffix match                       |
| `re`              | Python regex (`re|i` adds ignore-case)              |
| `cidr`            | IP-in-network membership                            |
| `base64` / `base64offset` | encode the expected value before matching   |
| `windash`         | dash-variant permutations (`-`, `/`, en/em dashes)  |
| `lt/lte/gt/gte`   | numeric comparison                                  |
| `cased`           | force case-sensitive matching                       |
| `exists`          | field presence test (`true`/`false`)                |

Wildcards `*` and `?` inside a plain value are treated as globs.
