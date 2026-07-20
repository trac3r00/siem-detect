# Engine walkthrough

This document traces a bundled rule through parsing, logsource filtering, matching, and reporting. The relevant implementation is in [`logsource.py`](../src/siem_detect/logsource.py), [`sigma.py`](../src/siem_detect/sigma.py), and [`engine.py`](../src/siem_detect/engine.py).

## Example rule

The shortened rule below detects an individual failed SSH password event from an address outside the listed networks:

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

The engine evaluates each event independently. It does not count repeated failures or apply a time window.

## 1. Parse and identify the source

For an authentication log, `parse_log()` returns normalized events and the descriptor `{"product": "linux", "service": "auth"}`. The authentication parser extracts fields such as `program`, `user`, `src_ip`, and `outcome` from recognized `sshd` messages.

When the input format is `auto`, the parser examines up to the first 50 lines. An explicit `--format auth` selection bypasses format detection.

## 2. Filter rules by logsource

Before scanning events, `Engine.scan()` compares each rule's `category`, `product`, and `service` constraints with the parser descriptor. The example rule remains active for authentication logs, while incompatible Windows and web server rules are excluded.

No compatibility filter is applied when the parsed source has no descriptor, as is the case for generic `json` and `jsonl` inputs. The `--no-logsource-filter` option also disables this step.

## 3. Compile selections

Each named detection block becomes a `Selection`:

- `selection` is a mapping, so its fields use implicit AND: `program` must equal `sshd` and `outcome` must equal `failure`.
- `filter_internal` contains a list for `src_ip|cidr`, so the address may match any listed network.

Plain string comparisons are case-insensitive unless the `cased` modifier is present. Plain values containing `*` or `?` use wildcard matching.

## 4. Evaluate the condition

`ConditionEvaluator` parses `selection and not filter_internal` with the precedence `or < and < not < atom`. For this event:

```json
{"program": "sshd", "outcome": "failure", "src_ip": "203.0.113.9"}
```

- `selection` is true.
- `filter_internal` is false because `203.0.113.9` is outside the listed networks.
- `selection and not filter_internal` is true, so the rule produces a detection.

An event with `src_ip` set to `10.1.2.3` matches `filter_internal`, making the complete condition false.

The condition evaluator also supports parentheses, `1 of pattern*`, `all of pattern*`, `1 of them`, and `all of them`.

## 5. Build the report

Each detection contains the rule identity, severity, matching event, source rule path, tags, and MITRE ATT&CK metadata. `Report` calculates severity and technique counts and serializes the result as Markdown or JSON. JSON Lines output serializes each detection individually.

## Supported field modifiers

| Modifier | Behavior |
| --- | --- |
| `contains` | Substring match |
| `contains|all` | Every listed value must be present as a substring |
| `startswith`, `endswith` | Prefix or suffix match |
| `re` | Python regular expression search; add `i` for case-insensitive matching |
| `cidr` | IP address membership in one or more networks |
| `base64` | Match the Base64 encoding of the expected value |
| `base64offset` | Match generated Base64 offset variants of the expected value |
| `windash` | Match supported dash and slash variants |
| `lt`, `lte`, `gt`, `gte` | Numeric comparison |
| `cased` | Use case-sensitive string matching |
| `exists` | Test whether a field is present |

Dotted field names such as `userIdentity.type` traverse nested mappings. List-valued event fields match when any element satisfies the field matcher.
