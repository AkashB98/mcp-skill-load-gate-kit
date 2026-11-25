"""Classify one shell command into exactly one of five policy classes.

Stdlib only: ``shlex`` tokenisation plus heuristics. This is deliberately
NOT a full bash parser (see README "Honest limits").

Classes, in precedence order (first match wins):
  obfuscated > destructive > network > workspace-write > read-only
Precedence matters: ``curl ... | sh`` is obfuscated, not merely network,
because the pipe-to-shell is the load-time danger.
"""
from __future__ import annotations

import re
import shlex

CLASSES = ("read-only", "workspace-write", "network", "destructive", "obfuscated")

_READ_ONLY = {
    "ls", "cat", "pwd", "grep", "rg", "head", "tail", "wc", "which",
    "find", "echo", "printf", "date", "whoami", "env", "printenv",
    "stat", "file", "diff", "sort", "uniq", "basename", "dirname",
}
_WRITE = {
    "touch", "mkdir", "cp", "mv", "tee", "install", "ln",
}
_NETWORK = {
    "curl", "wget", "nc", "ncat", "netcat", "ssh", "scp", "sftp",
    "ping", "dig", "nslookup", "host", "telnet", "ftp",
}
_DESTRUCTIVE = {"rm", "rmdir", "dd", "mkfs", "shred", "truncate", "kill", "killall"}

# --- obfuscation heuristics -------------------------------------------------
_OBFUSCATED_PATTERNS = [
    (re.compile(r"base64\b[^|]*\|[^|]*\b(?:ba)?sh\b"), "base64 payload piped to a shell"),
    (re.compile(r"\|\s*(?:ba)?sh\b"), "output piped directly to a shell"),
    (re.compile(r"\beval\b"), "eval executes a constructed string"),
    (re.compile(r"base64\s+(?:-d|--decode|-D)\b"), "base64 decode step"),
    (re.compile(r"\\x[0-9a-fA-F]{2}"), "hex-escaped characters"),
    (re.compile(r"\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\s*$"), "command is just a variable"),
    (re.compile(r"^\s*\$[A-Za-z_]"), "command starts with a variable (variable-built command)"),
    (re.compile(r"['\"][a-z]{1,3}['\"]\s*['\"][a-z]"), "string built from quoted pieces"),
    (re.compile(r"\bexec\s*\("), "exec() of a constructed payload"),
    (re.compile(r"__import__\s*\("), "dynamic __import__"),
]


def _tokens(command: str) -> list[str]:
    try:
        return shlex.split(command, posix=True)
    except ValueError:
        return command.split()


def _has_redirect(command: str) -> tuple[bool, str]:
    """Return (is_redirect, target) for > / >> outside quotes (heuristic)."""
    stripped = re.sub(r"'[^']*'|\"[^\"]*\"", "", command)
    m = re.search(r">>?\s*([^\s|;&]+)", stripped)
    if m:
        return True, m.group(1)
    return False, ""


def classify(command: str) -> dict:
    """Return {"command", "classification", "reasons": [...]}."""
    cmd = (command or "").strip()
    reasons: list[str] = []
    if not cmd:
        return {"command": command, "classification": "read-only", "reasons": ["empty"]}

    # 1) Obfuscated — checked first, on the raw string.
    for pattern, why in _OBFUSCATED_PATTERNS:
        if pattern.search(cmd):
            reasons.append(why)
            return {"command": command, "classification": "obfuscated", "reasons": reasons}
    # Variable-built: an assignment in the same line whose variable is then run.
    if re.search(r"\b[A-Za-z_][A-Za-z0-9_]*=[^\s;]+;", cmd) and re.search(r"\$[A-Za-z_]", cmd):
        return {"command": command, "classification": "obfuscated",
                "reasons": ["variable assignment followed by variable execution in one line"]}
    # Command substitution executing something.
    if "$(" in cmd or "`" in cmd:
        return {"command": command, "classification": "obfuscated",
                "reasons": ["command substitution $()/backticks"]}

    tokens = _tokens(cmd)
    # Skip leading sudo / env wrappers for the head-token decision, but note sudo.
    head_idx = 0
    sudo = False
    while head_idx < len(tokens) and tokens[head_idx] in {"sudo", "env"}:
        if tokens[head_idx] == "sudo":
            sudo = True
        head_idx += 1
    head = tokens[head_idx].split("/")[-1] if head_idx < len(tokens) else ""
    joined = " ".join(tokens)

    # Python inline code that decodes / execs / reaches the network or os.system.
    if head in {"python", "python3"} and "-c" in tokens:
        body = joined
        if any(s in body for s in ("base64", "exec(", "eval(", "os.system", "urllib", "socket", "requests.")):
            return {"command": command, "classification": "obfuscated",
                    "reasons": ["python -c with decode/exec/network primitive"]}
        return {"command": command, "classification": "workspace-write",
                "reasons": ["python -c inline code is not provably read-only"]}

    # 2) Destructive.
    if head in _DESTRUCTIVE:
        return {"command": command, "classification": "destructive",
                "reasons": [f"{head} can delete, overwrite or kill"]}
    if "find" in tokens and "-delete" in tokens:
        return {"command": command, "classification": "destructive",
                "reasons": ["find -delete removes files"]}
    if sudo:
        return {"command": command, "classification": "destructive",
                "reasons": ["sudo elevates beyond the workspace sandbox"]}
    is_redir, target = _has_redirect(cmd)
    if is_redir and target.startswith(("/etc/", "/usr/", "/bin/", "/sbin/", "/dev/", "/boot/")):
        return {"command": command, "classification": "destructive",
                "reasons": [f"redirect overwrites system path {target}"]}
    if head in {"chmod", "chown"}:
        return {"command": command, "classification": "destructive",
                "reasons": [f"{head} changes permissions/ownership"]}

    # 3) Network.
    if head in _NETWORK:
        return {"command": command, "classification": "network",
                "reasons": [f"{head} performs network access"]}
    if head in {"pip", "pip3", "npm", "yarn"} and any(t in tokens for t in ("install", "add")):
        return {"command": command, "classification": "network",
                "reasons": ["package install reaches the network"]}
    if re.search(r"\bhttps?://", cmd) and head not in _READ_ONLY:
        return {"command": command, "classification": "network",
                "reasons": ["URL used by a non-read-only command"]}

    # 4) Workspace-write.
    if head in _WRITE:
        return {"command": command, "classification": "workspace-write",
                "reasons": [f"{head} writes inside the workspace"]}
    if head == "sed" and "-i" in tokens:
        return {"command": command, "classification": "workspace-write",
                "reasons": ["sed -i edits a file in place"]}
    if is_redir and target != "/dev/null":
        return {"command": command, "classification": "workspace-write",
                "reasons": [f"redirect writes to {target}"]}
    if head == "git" and len(tokens) > 1 and tokens[1] not in {
        "status", "log", "diff", "show", "branch", "remote", "rev-parse",
    }:
        return {"command": command, "classification": "workspace-write",
                "reasons": [f"git {tokens[1]} mutates state"]}

    # 5) Read-only (default for known read-only heads; unknown heads are
    # treated as workspace-write so the gate strips rather than trusts them).
    if head in _READ_ONLY:
        return {"command": command, "classification": "read-only",
                "reasons": [f"{head} is read-only"]}
    if head == "git":
        return {"command": command, "classification": "read-only", "reasons": ["read-only git query"]}
    return {"command": command, "classification": "workspace-write",
            "reasons": [f"unknown command {head!r}: not provably read-only, stripped not trusted"]}
