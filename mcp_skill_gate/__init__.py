"""Load-time vetting gate for skills delivered by MCP servers."""

from .classifier import CLASSES, classify
from .extract import extract_commands
from .gate import baseline_decision, fingerprint, load_bundle, load_registry, vet

__all__ = [
    "CLASSES", "classify", "extract_commands",
    "baseline_decision", "fingerprint", "load_bundle", "load_registry", "vet",
]
__version__ = "0.1.0"
