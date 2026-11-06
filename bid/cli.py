"""
Command-line entry point: `bid <command> [args]`.

Every command is a thin wrapper around one module's own main(argv), so
`python -m bid.<module>` keeps working and the two never drift apart.
`bid <command> --help` prints that command's options.
"""
from __future__ import annotations

import importlib
import sys

# command -> (module, one-line description)
COMMANDS: dict[str, tuple[str, str]] = {
    "run": ("bid.run_pipeline", "run the pipeline end to end and verify the evidence it signs"),
    "verify": ("bid.verify_receipt", "verify an evidence receipt with the public key only"),
    "replay": ("bid.replay", "re-run decisions and prove they are reproducible"),
    "console": ("bid.server", "start the operator console (needs the 'console' extra)"),
    "governance": ("bid.governance", "halt or resume the queue, release a confirm, escalate overdue holds"),
    "project": ("bid.projections", "project a confirmed finding into a report format"),
    "packs": ("bid.packs", "check a notice against a policy pack; best-effort report over receipts"),
    "conduct": ("bid.conduct", "signed conduct review of a classifier on the golden set"),
    "eval": ("bid.eval.run_eval", "measure detection quality on the labelled set"),
    "agreement": ("bid.eval.agreement", "compare same-family and cross-family model agreement"),
    "scale": ("bid.eval.scale_test", "stress-test the pipeline on a generated corpus"),
    "adversarial": ("bid.adversarial", "measure robustness to prompt injection"),
    "compare-models": ("bid.compare_models", "compare classifier models on the labelled set"),
    "brand-kb": ("bid.brand_kb", "build the brand knowledge base from public data"),
    "demo-sensors": ("bid.demo_sensors", "live look-alike domain and certificate-log sensors"),
    "demo-enrich": ("bid.demo_enrich", "live public-source pivot from one domain"),
    "demo-itunes": ("bid.demo_itunes", "live app-store sensor"),
}


def _usage() -> str:
    width = max(len(c) for c in COMMANDS)
    lines = ["usage: bid <command> [args]", "", "commands:"]
    lines += [f"  {name:<{width}}  {desc}" for name, (_, desc) in COMMANDS.items()]
    lines += ["", "bid <command> --help shows the options of one command.",
              "Runtime data goes to $BID_DATA_DIR (default ./.bid)."]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help", "help"):
        print(_usage())
        return 0
    if args[0] in ("-V", "--version"):
        from . import __version__
        print(f"bid {__version__}")
        return 0
    name, rest = args[0], args[1:]
    if name not in COMMANDS:
        print(f"bid: unknown command {name!r}\n\n{_usage()}", file=sys.stderr)
        return 2
    module = importlib.import_module(COMMANDS[name][0])
    saved = sys.argv[0]
    sys.argv[0] = f"bid {name}"  # argparse names the program after argv[0]
    try:
        return int(module.main(rest) or 0)
    finally:
        sys.argv[0] = saved


if __name__ == "__main__":
    raise SystemExit(main())
