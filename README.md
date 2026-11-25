# mcp-skill-load-gate-kit

**A load-time vetting gate for skills delivered by MCP servers — before a single shell command runs.**

When a skill arrives from an MCP server, it can carry shell commands in its manifest and in fenced code blocks inside its instructions. Loading it blindly means trusting a remote server with your shell. This kit vets every command *at load time*, decides **ALLOW / ALLOW_STRIPPED / QUARANTINE** per skill, checks for **version drift**, and emits a JSON audit record for every decision.

## Why now (November 2026)

- **2026-11-24** — Anthropic shipped **Skills over MCP**, so skills can now be delivered by remote MCP servers, not just installed locally by hand.
- **2026-11-25** — Claude Code **2.1.332** added a **PreSkillShellCommand** hook, a load-time interception point for skill shell commands.

That combination creates a new supply-chain surface: a skill that was clean at v1 can be re-published at v2 with new commands by the server that hosts it. A one-time review is not enough — vetting has to happen at load, every load, and a changed version has to be treated as a brand-new skill. That is exactly what this gate does.

## How it works

1. **Extract** — every shell command is pulled from the bundle's `shell_commands` field *and* from fenced `bash`/`sh`/`shell` code blocks in its instructions (`mcp_skill_gate/extract.py`).
2. **Classify** — each command gets exactly one of **5 policy classes** using `shlex` tokenisation plus heuristics (`mcp_skill_gate/classifier.py`). No full bash parser — deliberately.
3. **Decide** — per skill (`mcp_skill_gate/gate.py`):
   - any **destructive**, **network**, or **obfuscated** command → **QUARANTINE**
   - only borderline **workspace-write** commands on top of read-only ones → **ALLOW_STRIPPED** (the write commands are removed and named in the audit record)
   - otherwise → **ALLOW**
4. **Version-drift check** — the gate fingerprints a skill's command set (SHA-256). If a previously-allowed skill arrives with a new version *or* a changed command set, it is treated as **NEW and fully re-vetted** — v1's clean verdict earns v2 nothing.
5. **Audit** — every decision returns a JSON record: skill, version, source server, per-command classifications with reasons, stripped commands, quarantined classes, fingerprint, and drift flags.

### The 5 classes

| Class | Examples | Effect |
|---|---|---|
| `read-only` | `ls`, `cat`, `grep`, `git status`, `wc` | allowed |
| `workspace-write` | `touch`, `mkdir`, `cp`, `echo x > notes.txt`, `sed -i` | stripped |
| `network` | `curl`, `wget`, `ssh`, `nc`, package installs | **quarantine** |
| `destructive` | `rm`, `dd`, `find -delete`, `> /etc/passwd`, `sudo` | **quarantine** |
| `obfuscated` | base64 piped to a shell, `curl … \| sh`, `eval`, variable-built commands, `python -c` with `base64`/`exec(` | **quarantine** |

Precedence is `obfuscated > destructive > network > workspace-write > read-only`, so `curl … | sh` is reported as obfuscated — the pipe-to-shell is the danger, not just the download.

## Results (golden evals, measured — not asserted)

18 seeded synthetic bundles: 5 clean, 3 borderline, 4 malicious, 5 obfuscated, 1 version-drift v2. The eval harness (`run_evals.py`) also runs a **plain regex denylist baseline** (patterns like `rm -rf`, `curl `, `sudo`, `dd if=`) over the same bundles, so the contrast is measured:

| Metric | Gate | Regex denylist baseline |
|---|---|---|
| Decision accuracy vs. expected (18 bundles) | **1.0** | — |
| Planted malicious + obfuscated recall (9 bundles) | **1.0 (9/9)** | 0.5556 (5/9) |
| Planted bundles missed | none | `theme-installer` (base64 pipe), `quick-setup` (eval from pieces), `image-helper` (python base64 exec), `system-tidy` (variable-built) |
| Clean false-quarantine rate (8 clean/borderline) | **0.0** | — |
| Drift check (clean v1 → v2 adds a `curl` exfil command) | drift detected, re-vetted as new, **QUARANTINE** | — |

Reproduce with `python3 run_evals.py` — it writes `eval_report.json` with the full per-bundle rows.

## Run it

```bash
# Demo: vet all seeded bundles (exit code 0)
python3 demo.py

# Vet one bundle (exit 0 = allow / allow-stripped, 2 = quarantine)
python3 -m mcp_skill_gate check data/bundles/obfuscated_base64_pipe.json
python3 -m mcp_skill_gate check data/bundles/drift_skill_v2.json --registry data/registry.json

# Classify a single command
python3 -m mcp_skill_gate classify "echo aGk= | base64 -d | bash"

# Tests (stdlib unittest; the tests are also collectable by pytest)
python3 -m unittest discover -s tests -v     # 19 tests

# Golden evals -> eval_report.json
python3 run_evals.py
```

A bundle is a JSON file: `manifest` (`name`, `version`, `source_server`), `instructions` text, and a `shell_commands` list. See `data/bundles/` for 18 examples and `data/registry.json` for the previously-allowed registry used by the drift check.

## Hook adapter — assumed payload format

`mcp_skill_gate/adapter.py` converts a PreSkillShellCommand-*style* hook payload into a bundle and maps an audit record back to a hook response. **The payload format is assumed, not verified**: the exact real hook schema was not available to this project, so the adapter is labelled `assumed_payload_format` in code and in its output. If the real payload differs, only that module should need to change. There is **no real hook integration and no real MCP transport** in this kit — bundles are JSON files only.

## Honest limits

- **Heuristics, not a bash parser.** `shlex` + patterns will miss novel obfuscation (novel encodings, multi-step staging across commands, commands hidden outside fenced blocks). This is a load-time *gate*, not a proof of safety.
- **Per-command, not per-script.** Commands are classified individually; a sequence that is only dangerous in combination may pass.
- **Unknown commands are stripped, not trusted** — anything whose head token is not provably read-only is treated as workspace-write. That is a deliberate false-positive bias for borderline cases, and it is why the clean false-quarantine rate is measured on *quarantine*, not on stripping.
- **Synthetic data only.** All seeded bundles are invented; no real skills, servers, or personal data are included.
- **Stdlib only, no network.** Python 3, nothing to install.

## What this proves

Supply-chain thinking applied to the newest agent surface: threat-modelling a launch-week feature (Skills over MCP), building a small, testable policy engine with an honest baseline comparison, and treating version drift as a first-class attack — the same reliability mindset behind forward-deployed AI work.

## License

MIT — see `LICENSE`.
