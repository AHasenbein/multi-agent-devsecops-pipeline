"""Is there a key in any log or record? (QA-PR-01)

    uv run python scripts/check_no_secrets.py <path> [<path> ...]

On the team host in Phase 8, run it over the state directory and the Control API's log:

    set -a; . ./.env; set +a
    journalctl -u <control-api unit> > /tmp/control-api.log
    uv run python scripts/check_no_secrets.py "$DEVSECOPS_STATE_DIR"/*.db /tmp/control-api.log

A SQLite file is read table by table: every text and blob value of every row (the
LangGraph checkpoints are blobs). Any other file is read as text, line by line. A
directory is searched file by file.

It looks for the shapes in devsecops/llm/redact.py (SECRET_PATTERNS), and for the exact
values of CONTROL_API_TOKEN, GITHUB_TOKEN and OPENROUTER_API_KEY when they are set. A hit
names the file, the table, row and column (or the line number) and the pattern, never the
text that matched.

Exit 1 on any hit, otherwise 2 when a path could not be read, otherwise 0 (clean).
"""

import argparse
import os
import re
import sqlite3
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from devsecops.llm.redact import SECRET_PATTERNS  # noqa: E402

SECRET_ENV_VARS = ("CONTROL_API_TOKEN", "GITHUB_TOKEN", "OPENROUTER_API_KEY")
MIN_SECRET_LEN = 8  # shorter "secrets" would match by accident
SQLITE_MAGIC = b"SQLite format 3\x00"


@dataclass
class Report:
    files: int = 0
    rows: int = 0
    lines: int = 0
    hits: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def search_patterns(env: dict[str, str] | None = None) -> list[tuple[str, re.Pattern[str]]]:
    """The named patterns to look for: the redaction shapes plus the exact env values."""
    env = os.environ if env is None else env
    patterns = [(p.name, p.pattern) for p in SECRET_PATTERNS]
    for name in SECRET_ENV_VARS:
        value = env.get(name, "").strip()
        if len(value) >= MIN_SECRET_LEN:
            patterns.append((f"value of {name}", re.compile(re.escape(value))))
    return patterns


def matches(text: str, patterns: list[tuple[str, re.Pattern[str]]]) -> list[str]:
    """The names of the patterns found in ``text``. An already redacted value such as
    ``token=[REDACTED]`` does not match: the patterns skip it."""
    return [name for name, pattern in patterns if pattern.search(text)]


def check_paths(paths: Iterable[Path], patterns: list[tuple[str, re.Pattern[str]]]) -> Report:
    report = Report()
    for path in _files(paths, report):
        report.files += 1
        try:
            if _is_sqlite(path):
                _check_sqlite(path, patterns, report)
            else:
                _check_text(path, patterns, report)
        except (OSError, sqlite3.Error) as exc:
            report.errors.append(f"{path}: cannot read ({type(exc).__name__})")
    return report


def _files(paths: Iterable[Path], report: Report) -> Iterator[Path]:
    for path in paths:
        if path.is_dir():
            yield from sorted(p for p in path.rglob("*") if p.is_file())
        elif path.is_file():
            yield path
        else:
            report.errors.append(f"{path}: no such file")


def _is_sqlite(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(len(SQLITE_MAGIC)) == SQLITE_MAGIC


def _check_sqlite(path: Path, patterns, report: Report) -> None:
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        tables = [
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name"
            )
        ]
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            cursor = conn.execute(f"SELECT * FROM {quoted}")  # noqa: S608 - names from the file
            columns = [d[0] for d in cursor.description]
            for number, row in enumerate(cursor, start=1):
                report.rows += 1
                for column, value in zip(columns, row, strict=True):
                    text = _as_text(value)
                    if text is None:
                        continue
                    for name in matches(text, patterns):
                        report.hits.append(
                            f"{path}: table {table}, row {number}, column {column}: {name}"
                        )
    finally:
        conn.close()


def _as_text(value: object) -> str | None:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value).decode("utf-8", errors="replace")
    return None


def _check_text(path: Path, patterns, report: Report) -> None:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for number, line in enumerate(f, start=1):
            report.lines += 1
            for name in matches(line, patterns):
                report.hits.append(f"{path}: line {number}: {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("paths", nargs="+", type=Path, help="SQLite files, logs or directories")
    args = parser.parse_args(argv)

    report = check_paths(args.paths, search_patterns())
    for hit in report.hits:
        print(f"HIT  {hit}")
    for error in report.errors:
        print(f"ERROR {error}", file=sys.stderr)
    print(
        f"checked {report.files} files, {report.rows} rows, {report.lines} lines: "
        f"{len(report.hits)} hits"
    )
    if report.hits:
        return 1
    return 2 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
