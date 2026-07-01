"""Detection engine — run Sigma rules over parsed events and report hits."""
from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Iterable, Sequence

from .sigma import SigmaRule

# Sigma severity -> numeric weight (for summary/sorting).
_LEVEL_WEIGHT = {
    "informational": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "critical": 5,
}
_LEVEL_ICON = {
    "informational": "ℹ️",
    "low": "🟢",
    "medium": "🟡",
    "high": "🟠",
    "critical": "🔴",
}


@dataclass
class Detection:
    rule_id: str
    rule_title: str
    level: str
    event_index: int
    event: dict
    mitre_techniques: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)
    description: str = ""
    tags: list[str] = field(default_factory=list)
    source_path: str = ""

    @property
    def weight(self) -> int:
        return _LEVEL_WEIGHT.get(self.level, 3)


@dataclass
class Report:
    detections: list[Detection]
    events_scanned: int
    rules_loaded: int
    rules_matched: int
    logsource: dict
    generated_at: str

    # -- summaries -- #
    def level_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.detections:
            counts[d.level] = counts.get(d.level, 0) + 1
        return counts

    def technique_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.detections:
            for t in d.mitre_techniques:
                counts[t] = counts.get(t, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    @property
    def verdict(self) -> str:
        if not self.detections:
            return "clean"
        top = max(d.weight for d in self.detections)
        if top >= 5:
            return "critical"
        if top >= 4:
            return "high"
        if top >= 3:
            return "suspicious"
        return "low"

    # -- serialisation -- #
    def to_dict(self, include_events: bool = True) -> dict:
        dets = []
        for d in self.detections:
            row = asdict(d)
            if not include_events:
                row.pop("event", None)
            dets.append(row)
        return {
            "generated_at": self.generated_at,
            "verdict": self.verdict,
            "events_scanned": self.events_scanned,
            "rules_loaded": self.rules_loaded,
            "rules_matched": self.rules_matched,
            "logsource": self.logsource,
            "level_counts": self.level_counts(),
            "mitre_techniques": self.technique_counts(),
            "detections": dets,
        }

    def to_json(self, indent: int = 2, include_events: bool = True) -> str:
        return json.dumps(self.to_dict(include_events), indent=indent, default=str)

    def to_markdown(self, max_rows: int = 200) -> str:
        icon = _LEVEL_ICON.get(self.verdict, "")
        lines = [
            f"# siem-detect report — verdict: {icon} **{self.verdict.upper()}**",
            "",
            f"- generated: `{self.generated_at}`",
            f"- events scanned: **{self.events_scanned}**",
            f"- rules loaded: **{self.rules_loaded}** · matched: **{self.rules_matched}**",
            f"- total detections: **{len(self.detections)}**",
        ]
        lc = self.level_counts()
        if lc:
            badge = "  ".join(
                f"{_LEVEL_ICON.get(k,'')} {k}: {v}"
                for k, v in sorted(lc.items(), key=lambda kv: -_LEVEL_WEIGHT.get(kv[0], 0))
            )
            lines.append(f"- by level: {badge}")
        tc = self.technique_counts()
        if tc:
            lines.append(
                "- MITRE ATT&CK: "
                + ", ".join(f"`{t}`×{n}" for t, n in list(tc.items())[:12])
            )
        lines += ["", "## Detections", ""]
        if not self.detections:
            lines.append("_No rules fired. Log is clean against the loaded ruleset._")
            return "\n".join(lines)

        lines.append("| # | level | rule | ATT&CK | event # | key fields |")
        lines.append("|---|-------|------|--------|---------|------------|")
        ordered = sorted(
            self.detections, key=lambda d: (-d.weight, d.event_index)
        )
        for i, d in enumerate(ordered[:max_rows], 1):
            att = ",".join(d.mitre_techniques) or "-"
            keys = _summarise_event(d.event)
            title = d.rule_title.replace("|", "\\|")
            lines.append(
                f"| {i} | {_LEVEL_ICON.get(d.level,'')} {d.level} | {title} "
                f"| {att} | {d.event_index} | {keys} |"
            )
        if len(self.detections) > max_rows:
            lines.append(f"\n_…{len(self.detections) - max_rows} more detections truncated._")
        return "\n".join(lines)


def _summarise_event(event: dict, limit: int = 4) -> str:
    prefer = ("src_ip", "user", "program", "EventID", "Image",
              "CommandLine", "uri", "status", "message", "outcome")
    parts: list[str] = []
    for k in prefer:
        if k in event and event[k] not in (None, ""):
            val = str(event[k])
            if len(val) > 60:
                val = val[:57] + "…"
            parts.append(f"{k}={val}")
        if len(parts) >= limit:
            break
    if not parts:
        for k, v in list(event.items())[:limit]:
            if k.startswith("_"):
                continue
            parts.append(f"{k}={str(v)[:40]}")
    return "; ".join(parts).replace("|", "\\|")


class Engine:
    """Match a set of Sigma rules against a stream of events."""

    def __init__(self, rules: Sequence[SigmaRule], match_logsource: bool = True):
        self.rules = list(rules)
        self.match_logsource = match_logsource

    def scan(
        self,
        events: Iterable[dict],
        logsource: dict | None = None,
    ) -> Report:
        # Pre-filter rules by logsource so we don't run windows rules on nginx.
        if self.match_logsource and logsource:
            active = [r for r in self.rules if r.targets_logsource(logsource)]
        else:
            active = list(self.rules)

        detections: list[Detection] = []
        matched_rule_ids: set[str] = set()
        count = 0
        for idx, event in enumerate(events):
            count += 1
            for rule in active:
                try:
                    hit = rule.matches(event)
                except Exception:  # noqa: BLE001 - a broken rule shouldn't kill the scan
                    hit = False
                if hit:
                    matched_rule_ids.add(rule.id)
                    detections.append(
                        Detection(
                            rule_id=rule.id,
                            rule_title=rule.title,
                            level=rule.level,
                            event_index=idx,
                            event={k: v for k, v in event.items() if not k.startswith("_")}
                            or dict(event),
                            mitre_techniques=rule.mitre_techniques,
                            mitre_tactics=rule.mitre_tactics,
                            description=rule.description,
                            tags=rule.tags,
                            source_path=rule.source_path,
                        )
                    )
        return Report(
            detections=detections,
            events_scanned=count,
            rules_loaded=len(self.rules),
            rules_matched=len(matched_rule_ids),
            logsource=logsource or {},
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )
