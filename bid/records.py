"""
On-disk records of a run directory.

    receipts.jsonl   one EvidencePackage per line, in chain order
    cases.jsonl      one {"candidate": ..., "verdict": ...} per classified candidate

A receipt refers to its candidate and verdict by hash only. The case file keeps
the full objects, so a finding can be projected into a report, released or
re-verified later without re-running the pipeline. Asset bytes live in the same
directory, content-addressed (storage.ContentStore).

Appends are not locked: one writer per run directory at a time.
"""
from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel

from .models import Candidate, EvidencePackage, Verdict

RECEIPTS = "receipts.jsonl"
CASES = "cases.jsonl"


class Case(BaseModel):
    candidate: Candidate
    verdict: Verdict


def _lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_receipts(run_dir: Path) -> list[EvidencePackage]:
    return [EvidencePackage.model_validate_json(line) for line in _lines(Path(run_dir) / RECEIPTS)]


def write_receipts(run_dir: Path, packages: list[EvidencePackage]) -> None:
    """Replace the chain file with `packages` (a new chain)."""
    path = Path(run_dir) / RECEIPTS
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(p.model_dump_json() + "\n" for p in packages), encoding="utf-8")


def append_receipts(run_dir: Path, packages: list[EvidencePackage]) -> None:
    path = Path(run_dir) / RECEIPTS
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for p in packages:
            f.write(p.model_dump_json() + "\n")


def read_cases(run_dir: Path) -> dict[str, Case]:
    cases = [Case.model_validate_json(line) for line in _lines(Path(run_dir) / CASES)]
    return {c.candidate.id: c for c in cases}


def write_cases(run_dir: Path, cases: list[Case]) -> None:
    path = Path(run_dir) / CASES
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(c.model_dump_json() + "\n" for c in cases), encoding="utf-8")
