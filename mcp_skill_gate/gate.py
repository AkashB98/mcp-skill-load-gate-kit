"""The load-time vetting gate: decide ALLOW / ALLOW_STRIPPED / QUARANTINE.

Version drift: if a previously-allowed skill arrives with a new version or
a changed command set, it is treated as NEW and fully re-vetted — a skill
that was clean at v1 earns no trust at v2.
"""
from __future__ import annotations

import hashlib
import json

from .classifier import classify
from .extract import extract_commands

QUARANTINE_CLASSES = {"destructive", "network", "obfuscated"}


def fingerprint(commands: list[str]) -> str:
    payload = "\n".join(sorted(commands)).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def load_bundle(path) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def load_registry(path) -> dict:
    """Registry format: {"skills": {name: {"version", "commands", "decision"}}}"""
    if path is None:
        return {}
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return data.get("skills", data)


def vet(bundle: dict, registry: dict | None = None) -> dict:
    """Vet one bundle and return its audit record (a plain dict)."""
    manifest = bundle.get("manifest") or {}
    name = manifest.get("name") or bundle.get("name") or "unnamed-skill"
    version = str(manifest.get("version") or bundle.get("version") or "0.0.0")
    server = manifest.get("source_server") or bundle.get("source_server") or "unknown-server"

    commands = extract_commands(bundle)
    results = [classify(c) for c in commands]
    classes = {r["classification"] for r in results}

    stripped = [r["command"] for r in results if r["classification"] == "workspace-write"]
    if classes & QUARANTINE_CLASSES:
        decision = "QUARANTINE"
        stripped = []
    elif stripped:
        decision = "ALLOW_STRIPPED"
    else:
        decision = "ALLOW"

    # --- version-drift check -------------------------------------------------
    drift_detected = False
    re_vetted = False
    previous_version = None
    cached = False
    prior = (registry or {}).get(name)
    if prior:
        previous_version = str(prior.get("version", ""))
        prior_fp = prior.get("fingerprint") or fingerprint(list(prior.get("commands") or []))
        drift_detected = previous_version != version or prior_fp != fingerprint(commands)
        if drift_detected:
            # Treated as NEW: the classification above *is* the re-vet.
            re_vetted = True
        elif prior.get("decision") in {"ALLOW", "ALLOW_STRIPPED"}:
            cached = True  # same version, same commands, previously allowed

    return {
        "skill": name,
        "version": version,
        "source_server": server,
        "decision": decision,
        "commands": results,
        "command_count": len(results),
        "stripped_commands": stripped if decision == "ALLOW_STRIPPED" else [],
        "quarantine_classes": sorted(classes & QUARANTINE_CLASSES),
        "fingerprint": fingerprint(commands),
        "drift_detected": drift_detected,
        "re_vetted_as_new": re_vetted,
        "previous_version": previous_version,
        "cached_previous_allow": cached,
    }


# --- plain regex denylist baseline (for the honest eval contrast) -----------
import re as _re

_BASELINE_PATTERNS = [
    r"rm\s+-rf", r"\bcurl\s", r"\bwget\s", r"\bsudo\b", r"chmod\s+777",
    r"dd\s+if=", r"\bmkfs\b", r":\(\)\s*\{", r"\bnc\s+-",
]


def baseline_decision(bundle: dict) -> str:
    """A plain regex denylist over the raw commands: QUARANTINE or ALLOW."""
    text = "\n".join(extract_commands(bundle))
    for pattern in _BASELINE_PATTERNS:
        if _re.search(pattern, text):
            return "QUARANTINE"
    return "ALLOW"
