"""Sigma rule model, field-matching, and condition evaluation.

This module implements a practical subset of the Sigma specification
(https://sigmahq.io/docs) sufficient to evaluate real detection rules against
structured log events:

* logsource targeting (category / product / service)
* selections as YAML dicts (implicit AND across keys) and lists (OR)
* field-list values (OR) and keyword lists (OR)
* field modifiers: contains, startswith, endswith, all, re, cidr,
  base64, base64offset, windash, lt/lte/gt/gte, cased
* condition mini-language: and / or / not / parentheses,
  ``1 of pattern*`` / ``all of pattern*`` / ``1 of them`` / ``all of them``

It intentionally does NOT convert rules to backend queries (that is what
pySigma/sigma-cli do). Instead it *executes* the rule directly against events,
which is what a lightweight host-side detection engine needs.
"""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError as exc:  # pragma: no cover - guidance path
    raise ImportError(
        "siem-detect requires PyYAML. Install with: pip install pyyaml"
    ) from exc


class SigmaParseError(ValueError):
    """Raised when a Sigma rule is malformed or uses unsupported syntax."""


# --------------------------------------------------------------------------- #
# Value matching (a single field-value comparison, honoring modifiers)
# --------------------------------------------------------------------------- #

_NUMERIC_MODS = {"lt", "lte", "gt", "gte"}


def _as_str(value: Any) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _windash_variants(pattern: str) -> list[str]:
    """Return dash-variant permutations used by the ``windash`` modifier."""
    dashes = ["-", "/", "\u2013", "\u2014", "\u2015"]
    out = {pattern}
    for d in dashes:
        if d in pattern:
            for repl in dashes:
                out.add(pattern.replace(d, repl))
    return list(out)


def _base64_variants(value: str) -> list[str]:
    raw = value.encode("utf-8")
    return [base64.b64encode(raw).decode("ascii")]


def _base64offset_variants(value: str) -> list[str]:
    """Emulate Sigma's base64offset: substring survives at 3 byte offsets."""
    raw = value.encode("utf-8")
    variants = []
    for off in range(3):
        encoded = base64.b64encode(b"\x00" * off + raw).decode("ascii")
        # trim partial leading/trailing chars introduced by the offset padding
        start = 0 if off == 0 else (off * 4) // 3
        variants.append(encoded[start:].rstrip("="))
    return variants


class FieldMatcher:
    """Compiled matcher for one ``field|modifiers`` -> value(s) entry."""

    __slots__ = ("field", "modifiers", "values", "_regexes", "_networks")

    def __init__(self, spec: str, raw_value: Any):
        parts = spec.split("|")
        self.field = parts[0]
        self.modifiers = parts[1:]
        # Values are always normalised to a list; a list means OR.
        if isinstance(raw_value, list):
            self.values = raw_value
        else:
            self.values = [raw_value]
        self._regexes: list[re.Pattern] | None = None
        self._networks: list[Any] | None = None

        if "re" in self.modifiers:
            flags = 0
            if "i" in self.modifiers or "cased" not in self.modifiers:
                # Sigma 're' is case-sensitive by default; 're|i' adds ignorecase.
                pass
            if "i" in self.modifiers:
                flags |= re.IGNORECASE
            self._regexes = [re.compile(_as_str(v), flags) for v in self.values]
        if "cidr" in self.modifiers:
            self._networks = [
                ipaddress.ip_network(_as_str(v), strict=False) for v in self.values
            ]

    # -- individual comparison helpers -- #
    def _expand_string_variants(self, target: str) -> list[str]:
        variants = [target]
        if "base64offset" in self.modifiers:
            variants = _base64offset_variants(target)
        elif "base64" in self.modifiers:
            variants = _base64_variants(target)
        if "windash" in self.modifiers:
            expanded: list[str] = []
            for v in variants:
                expanded.extend(_windash_variants(v))
            variants = expanded
        return variants

    def _string_match(self, expected: str, actual: str) -> bool:
        cased = "cased" in self.modifiers
        exp = expected if cased else expected.lower()
        act = actual if cased else actual.lower()
        if "contains" in self.modifiers:
            if "all" in self.modifiers:
                return exp in act  # 'all' handled at value-list level
            return exp in act
        if "startswith" in self.modifiers:
            return act.startswith(exp)
        if "endswith" in self.modifiers:
            return act.endswith(exp)
        # Default Sigma semantics: exact match, but '*' and '?' are wildcards.
        if "*" in expected or "?" in expected:
            flags = 0 if cased else re.IGNORECASE
            regex = fnmatch.translate(expected)
            return re.match(regex, actual, flags) is not None
        return exp == act

    def _numeric_match(self, expected: Any, actual: Any) -> bool:
        try:
            a = float(actual)
            e = float(expected)
        except (TypeError, ValueError):
            return False
        if "lt" in self.modifiers:
            return a < e
        if "lte" in self.modifiers:
            return a <= e
        if "gt" in self.modifiers:
            return a > e
        if "gte" in self.modifiers:
            return a >= e
        return a == e

    def matches(self, event: dict) -> bool:
        # Regex modifier
        if self._regexes is not None:
            actual = event.get(self.field)
            if actual is None:
                return False
            return any(rx.search(_as_str(actual)) for rx in self._regexes)

        # CIDR modifier
        if self._networks is not None:
            actual = event.get(self.field)
            if actual is None:
                return False
            try:
                ip = ipaddress.ip_address(_as_str(actual))
            except ValueError:
                return False
            return any(ip in net for net in self._networks)

        actual = _resolve_field(event, self.field)

        # 'field|exists: true/false'
        if "exists" in self.modifiers:
            want = self.values[0]
            present = actual is not None
            return present == bool(want)

        if actual is None:
            # A null-valued expectation matches a missing field.
            return any(v is None for v in self.values)

        # Numeric comparison modifiers
        if self.modifiers and any(m in _NUMERIC_MODS for m in self.modifiers):
            return any(self._numeric_match(v, actual) for v in self.values)

        # '|contains|all' => every listed value must be a substring.
        if "contains" in self.modifiers and "all" in self.modifiers:
            act = _as_str(actual)
            return all(self._string_match(_as_str(v), act) for v in self.values)

        # Field can itself be a list (e.g. multiple URLs) -> any element matches.
        actual_items = actual if isinstance(actual, list) else [actual]
        for exp in self.values:
            for variant in self._expand_string_variants(_as_str(exp)):
                for act_item in actual_items:
                    if isinstance(exp, bool):
                        if isinstance(act_item, bool) and act_item == exp:
                            return True
                        continue
                    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
                        if self._numeric_match(exp, act_item):
                            return True
                    if self._string_match(variant, _as_str(act_item)):
                        return True
        return False


def _resolve_field(event: dict, field_name: str) -> Any:
    """Resolve a field, supporting dotted paths (a.b.c) into nested dicts."""
    if field_name in event:
        return event[field_name]
    if "." in field_name:
        cur: Any = event
        for part in field_name.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return None
        return cur
    return None


# --------------------------------------------------------------------------- #
# Selection (one named block inside `detection`)
# --------------------------------------------------------------------------- #

class Selection:
    """A named selection: a dict of field matchers, a list of them, or keywords."""

    __slots__ = ("name", "_matchers", "_keyword_values", "_or_blocks")

    def __init__(self, name: str, spec: Any):
        self.name = name
        self._matchers: list[FieldMatcher] = []
        self._keyword_values: list[str] | None = None
        self._or_blocks: list[Selection] | None = None

        if isinstance(spec, dict):
            for key, val in spec.items():
                self._matchers.append(FieldMatcher(key, val))
        elif isinstance(spec, list):
            # A list under a selection name = OR of the sub-blocks (or keywords).
            if all(isinstance(item, dict) for item in spec):
                self._or_blocks = [
                    Selection(f"{name}[{i}]", item) for i, item in enumerate(spec)
                ]
            else:
                # Keyword list: OR of plain-string substring searches.
                self._keyword_values = [_as_str(item) for item in spec]
        else:
            raise SigmaParseError(
                f"selection '{name}' must be a mapping or list, got {type(spec).__name__}"
            )

    def matches(self, event: dict) -> bool:
        if self._keyword_values is not None:
            blob = _event_blob(event)
            return any(kw.lower() in blob for kw in self._keyword_values)
        if self._or_blocks is not None:
            return any(block.matches(event) for block in self._or_blocks)
        # dict form: implicit AND across all field matchers
        return all(m.matches(event) for m in self._matchers)


def _event_blob(event: dict) -> str:
    """Flatten an event to a lowercase string for keyword searches."""
    parts: list[str] = []

    def walk(v: Any) -> None:
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        else:
            parts.append(_as_str(v))

    walk(event)
    return " ".join(parts).lower()


# --------------------------------------------------------------------------- #
# Condition mini-language
# --------------------------------------------------------------------------- #

_TOKEN_RE = re.compile(r"\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|\bthem\b|[\w*?.]+")


def _tokenize_condition(cond: str) -> list[str]:
    # Normalise the multiword operators before tokenizing.
    tokens = _TOKEN_RE.findall(cond)
    return [t.strip() for t in tokens if t.strip()]


class ConditionEvaluator:
    """Recursive-descent evaluator for the Sigma ``condition`` expression."""

    def __init__(self, condition: str, selections: dict[str, Selection]):
        self.tokens = _tokenize_condition(condition)
        self.pos = 0
        self.selections = selections
        self.raw = condition

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _next(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def evaluate(self, event: dict) -> bool:
        self.pos = 0
        result = self._parse_or(event)
        if self.pos != len(self.tokens):
            raise SigmaParseError(f"unparsed tokens in condition: {self.raw!r}")
        return result

    def _parse_or(self, event: dict) -> bool:
        val = self._parse_and(event)
        while self._peek() == "or":
            self._next()
            rhs = self._parse_and(event)
            val = val or rhs
        return val

    def _parse_and(self, event: dict) -> bool:
        val = self._parse_not(event)
        while self._peek() == "and":
            self._next()
            rhs = self._parse_not(event)
            val = val and rhs
        return val

    def _parse_not(self, event: dict) -> bool:
        if self._peek() == "not":
            self._next()
            return not self._parse_not(event)
        return self._parse_atom(event)

    def _parse_atom(self, event: dict) -> bool:
        tok = self._peek()
        if tok == "(":
            self._next()
            val = self._parse_or(event)
            if self._peek() != ")":
                raise SigmaParseError(f"missing ) in condition: {self.raw!r}")
            self._next()
            return val
        if tok in ("1 of", "all of"):
            self._next()
            quant = tok
            pattern = self._next()
            return self._quantifier(event, quant, pattern)
        # Bare selection name
        name = self._next()
        return self._match_named(event, name)

    def _quantifier(self, event: dict, quant: str, pattern: str) -> bool:
        if pattern == "them":
            names = list(self.selections.keys())
        else:
            regex = re.compile(fnmatch.translate(pattern))
            names = [n for n in self.selections if regex.match(n)]
        if not names:
            return False
        results = (self.selections[n].matches(event) for n in names)
        if quant == "1 of":
            return any(results)
        return all(results)

    def _match_named(self, event: dict, name: str) -> bool:
        sel = self.selections.get(name)
        if sel is None:
            raise SigmaParseError(
                f"condition references unknown selection {name!r} in rule "
                f"(available: {', '.join(self.selections) or 'none'})"
            )
        return sel.matches(event)


# --------------------------------------------------------------------------- #
# Sigma rule
# --------------------------------------------------------------------------- #

@dataclass
class SigmaRule:
    id: str
    title: str
    level: str
    description: str
    logsource: dict
    tags: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    author: str = ""
    status: str = ""
    source_path: str = ""
    _selections: dict[str, Selection] = field(default_factory=dict, repr=False)
    _condition: ConditionEvaluator | None = field(default=None, repr=False)

    @property
    def mitre_techniques(self) -> list[str]:
        out = []
        for t in self.tags:
            m = re.match(r"attack\.(t\d{4}(?:\.\d{3})?)", t, re.IGNORECASE)
            if m:
                out.append(m.group(1).upper())
        return out

    @property
    def mitre_tactics(self) -> list[str]:
        tactics = {
            "reconnaissance", "resource_development", "initial_access", "execution",
            "persistence", "privilege_escalation", "defense_evasion",
            "credential_access", "discovery", "lateral_movement", "collection",
            "command_and_control", "exfiltration", "impact",
        }
        out = []
        for t in self.tags:
            name = t.split("attack.")[-1].lower()
            if name in tactics:
                out.append(name)
        return out

    def matches(self, event: dict) -> bool:
        if self._condition is None:
            return False
        return self._condition.evaluate(event)

    def targets_logsource(self, source: dict | None) -> bool:
        """Return True if this rule's logsource is compatible with ``source``.

        ``source`` describes the parsed log (e.g. {"product": "linux",
        "service": "auth"}). Empty rule constraints match anything.
        """
        if not source:
            return True
        for key in ("category", "product", "service"):
            want = self.logsource.get(key)
            if want and source.get(key) and want != source.get(key):
                return False
        return True


def _require(d: dict, key: str, ctx: str) -> Any:
    if key not in d:
        raise SigmaParseError(f"{ctx}: missing required '{key}'")
    return d[key]


def _build_rule(doc: dict, path: str) -> SigmaRule:
    if not isinstance(doc, dict):
        raise SigmaParseError(f"{path}: rule must be a YAML mapping")
    detection = _require(doc, "detection", path)
    if not isinstance(detection, dict):
        raise SigmaParseError(f"{path}: 'detection' must be a mapping")
    condition = detection.get("condition")
    if not condition:
        raise SigmaParseError(f"{path}: 'detection' missing 'condition'")

    selections: dict[str, Selection] = {}
    for name, spec in detection.items():
        if name == "condition":
            continue
        selections[name] = Selection(name, spec)

    rule = SigmaRule(
        id=str(doc.get("id", Path(path).stem)),
        title=str(doc.get("title", "(untitled)")),
        level=str(doc.get("level", "medium")).lower(),
        description=str(doc.get("description", "")),
        logsource=doc.get("logsource", {}) or {},
        tags=[str(t) for t in doc.get("tags", []) or []],
        references=[str(r) for r in doc.get("references", []) or []],
        falsepositives=[str(f) for f in doc.get("falsepositives", []) or []],
        author=str(doc.get("author", "")),
        status=str(doc.get("status", "")),
        source_path=path,
        _selections=selections,
    )
    rule._condition = ConditionEvaluator(str(condition), selections)
    # Fail fast on obviously broken conditions by evaluating against an empty event.
    try:
        rule._condition.evaluate({})
    except SigmaParseError:
        raise
    except Exception:  # noqa: BLE001 - runtime match errors are fine on {}
        pass
    return rule


def load_rule_file(path: str | Path) -> list[SigmaRule]:
    """Load one or more Sigma rules from a single YAML file."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    rules = []
    for doc in yaml.safe_load_all(text):
        if doc is None:
            continue
        # Skip Sigma "global" / correlation-only docs we don't execute.
        if isinstance(doc, dict) and "detection" not in doc:
            continue
        rules.append(_build_rule(doc, str(p)))
    return rules


def load_rules(path: str | Path) -> list[SigmaRule]:
    """Recursively load all ``*.yml`` / ``*.yaml`` Sigma rules under ``path``."""
    p = Path(path)
    if p.is_file():
        return load_rule_file(p)
    rules: list[SigmaRule] = []
    for f in sorted(p.rglob("*.yml")) + sorted(p.rglob("*.yaml")):
        try:
            rules.extend(load_rule_file(f))
        except SigmaParseError as exc:
            raise SigmaParseError(f"failed loading {f}: {exc}") from exc
    return rules
