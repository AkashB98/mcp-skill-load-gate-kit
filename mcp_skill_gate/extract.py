"""Extract every shell command from an MCP skill bundle (JSON).

Sources:
  * ``shell_commands`` — a list of strings, or dicts with a ``command`` key.
  * Fenced code blocks in ``instructions`` tagged bash / sh / shell / zsh,
    plus untagged blocks whose lines look like shell. Each non-empty,
    non-comment line is one command.
"""
from __future__ import annotations

import re

_FENCE = re.compile(r"```(?P<lang>[A-Za-z]*)\n(?P<body>.*?)```", re.DOTALL)
_SHELL_LANGS = {"bash", "sh", "shell", "zsh", ""}


def extract_commands(bundle: dict) -> list[str]:
    commands: list[str] = []
    for item in bundle.get("shell_commands") or []:
        if isinstance(item, str) and item.strip():
            commands.append(item.strip())
        elif isinstance(item, dict) and str(item.get("command", "")).strip():
            commands.append(str(item["command"]).strip())
    instructions = bundle.get("instructions") or ""
    for match in _FENCE.finditer(instructions):
        if match.group("lang").lower() not in _SHELL_LANGS:
            continue
        for line in match.group("body").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                commands.append(line)
    # De-duplicate, preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for c in commands:
        if c not in seen:
            seen.add(c)
            unique.append(c)
    return unique
