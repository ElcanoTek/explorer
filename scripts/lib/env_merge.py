# SPDX-License-Identifier: BUSL-1.1
# Copyright (c) 2026 ElcanoTek, Inc.

"""Update bootstrap-managed keys in an existing .env, in place.

bootstrap.sh used to regenerate /opt/explorer/.env from its template, which
dropped every setting an operator added later (AWS keys from `explorer env
edit`, tuning knobs, custom keys). This rewrites only the keys the template
sets and keeps every other byte of the file, using the app's own dotenv parser
so "a binding" means exactly what it means to the app: `export`, quoted keys,
multi-line quoted values, ordering for ${VAR} interpolation.

Runs as root with the system interpreter in isolated mode (`python3 -I`) from
the root-owned source tree; it imports nothing but the vendored parser, by
path. The environment file is service-owned data and is never executed.

  env_merge.py values FILE KEY...       NUL-separated KEY, VALUE pairs (raw,
                                        last binding wins) for the given keys
  env_merge.py merge FILE TEMPLATE      the merged file on stdout
"""

from __future__ import annotations

import importlib.util
import io
import sys
from pathlib import Path

_PARSER = (
    Path(__file__).resolve().parents[2] / "app" / "_vendor" / "dotenv" / "parser.py"
)
_spec = importlib.util.spec_from_file_location("explorer_dotenv_parser", _PARSER)
assert _spec and _spec.loader
_parser = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = _parser
_spec.loader.exec_module(_parser)

# provision.sh owns the keys inside its block and replaces the block whole.
PROVISION_BEGIN = "# ── managed by explorer provision ("
PROVISION_END = "# ── end explorer provision ("


def _bindings(text: str) -> list:
    return list(_parser.parse_stream(io.StringIO(text)))


def _with_block_flags(bindings: list) -> list[tuple[object, bool]]:
    """Each binding paired with whether it sits inside a provision block."""
    out = []
    inside = False
    for b in bindings:
        text = b.original.string
        if b.key is None and PROVISION_BEGIN in text:
            inside = True
            out.append((b, True))
            continue
        out.append((b, inside))
        if b.key is None and PROVISION_END in text:
            inside = False
    return out


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def values(text: str, keys: list[str]) -> dict[str, str]:
    """The value the app actually uses for each key: the last binding, the
    provision block included (so prompts default to what is live)."""
    wanted = set(keys)
    found: dict[str, str] = {}
    for b in _bindings(text):
        if b.key in wanted and b.value is not None:
            found[b.key] = b.value
    return found


def merge(existing: str, template: str) -> str:
    desired: dict[str, str] = {}
    for b in _bindings(template):
        if b.key is not None and b.value is not None:
            desired[b.key] = b.value

    flagged = _with_block_flags(_bindings(existing))
    # provision.sh owns any key its block sets: that binding is the live one,
    # and the block is replaced whole on the next `explorer provision`. Leave
    # those keys alone everywhere rather than copy a provisioned value out.
    provisioned = {b.key for b, inside in flagged if inside and b.key}
    # Update only the effective (last) binding of each managed key, in place.
    # Earlier duplicates stay: a ${VAR} between them still sees the old value.
    last: dict[str, int] = {}
    for i, (b, inside) in enumerate(flagged):
        if not inside and b.key in desired and b.key not in provisioned:
            last[b.key] = i

    out: list[str] = []
    for i, (b, _inside) in enumerate(flagged):
        text = b.original.string
        if last.get(b.key) != i or b.value == desired[b.key]:
            out.append(text)  # not the live binding, or unchanged: keep as is
            continue
        lead = text[: len(text) - len(text.lstrip())]
        tail = "\n" if text.endswith(("\n", "\r")) else ""
        out.append(f"{lead}{b.key}={_quote(desired[b.key])}{tail}")

    missing = [k for k in desired if k not in last and k not in provisioned]
    if missing:
        merged = "".join(out)
        if merged and not merged.endswith("\n"):
            merged += "\n"
        merged += "\n# Added by bootstrap.sh\n"
        merged += "".join(f"{k}={_quote(desired[k])}\n" for k in missing)
        return merged
    return "".join(out)


def main(argv: list[str]) -> int:
    if len(argv) >= 2 and argv[0] == "values":
        text = Path(argv[1]).read_text(encoding="utf-8")
        for key, value in values(text, argv[2:]).items():
            sys.stdout.write(f"{key}\0{value}\0")
        return 0
    if len(argv) == 3 and argv[0] == "merge":
        existing = Path(argv[1]).read_text(encoding="utf-8")
        template = Path(argv[2]).read_text(encoding="utf-8")
        sys.stdout.write(merge(existing, template))
        return 0
    sys.stderr.write(__doc__ or "")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
