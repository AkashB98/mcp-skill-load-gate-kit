"""Adapter for a PreSkillShellCommand-style hook payload.

ASSUMED PAYLOAD FORMAT — this is NOT a verified integration with any real
hook. Anthropic shipped Skills over MCP (2026-11-24) and a
PreSkillShellCommand hook in Claude Code 2.1.332 (2026-11-25); the exact
payload schema was not available to this project, so the shape below is an
explicit assumption, labelled as such everywhere it appears:

    {
      "skill": {"name": ..., "version": ..., "source_server": ...},
      "instructions": "...",
      "shell_commands": ["...", ...]
    }

If the real payload differs, only this module should need to change.
"""
from __future__ import annotations


def bundle_from_hook_payload(payload: dict) -> dict:
    """Convert an assumed-format hook payload into a gate bundle."""
    skill = payload.get("skill") or {}
    return {
        "manifest": {
            "name": skill.get("name", "unnamed-skill"),
            "version": str(skill.get("version", "0.0.0")),
            "source_server": skill.get("source_server", "unknown-server"),
        },
        "instructions": payload.get("instructions", ""),
        "shell_commands": payload.get("shell_commands", []),
    }


def hook_response(audit_record: dict) -> dict:
    """Map an audit record to an assumed-format hook response."""
    decision = audit_record["decision"]
    return {
        "allow": decision in {"ALLOW", "ALLOW_STRIPPED"},
        "decision": decision,
        "stripped_commands": audit_record.get("stripped_commands", []),
        "reason": (
            "quarantined classes: " + ", ".join(audit_record.get("quarantine_classes", []))
            if decision == "QUARANTINE" else "no quarantined classes"
        ),
        "assumed_payload_format": True,
    }
