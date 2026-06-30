"""``agsec`` CLI entrypoint.

Phase 0 ships a minimal, dependency-light stub so the console script resolves
and ``agsec doctor`` / ``agsec version`` work. Full command surface (lint-policy,
verify, agent, audit, ...) lands in Phase 6.
"""

from __future__ import annotations

import sys

from agent_security import __version__


def cli(argv: list[str] | None = None) -> int:
    """Tiny argument-free dispatcher (no click dependency at Phase 0)."""
    args = sys.argv[1:] if argv is None else argv
    command = args[0] if args else "help"

    if command == "version":
        print(f"agent-security-framework {__version__}")
        return 0
    if command == "doctor":
        print("agsec doctor")
        print(f"  version: {__version__}")
        print(f"  python : {sys.version.split()[0]}")
        print("  status : OK (Phase 0 scaffold)")
        return 0
    if command in {"help", "-h", "--help"}:
        print("usage: agsec <command>")
        print("commands (Phase 0): version, doctor, help")
        print("more commands arrive in Phase 6 (lint-policy, verify, agent, audit)")
        return 0

    print(f"agsec: unknown command {command!r}. Try 'agsec help'.", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(cli())
