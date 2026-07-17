from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any


def _script_metadata(path: Path) -> dict[str, Any]:
    lines = path.read_text(encoding="utf-8").splitlines()
    start = lines.index("# /// script") + 1
    end = lines.index("# ///", start)
    content = "\n".join(line.removeprefix("# ") for line in lines[start:end])
    value = tomllib.loads(content)
    assert isinstance(value, dict)
    return value


def test_script_dependencies_match_declared_project_metadata() -> None:
    root = Path(__file__).resolve().parents[2]
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    runtime = _script_metadata(root / "shuttle-gate")
    development = _script_metadata(root / "test")

    runtime_dependencies = set(project["project"]["dependencies"])
    development_dependencies = set(project["dependency-groups"]["dev"])
    assert runtime["requires-python"] == project["project"]["requires-python"]
    assert set(runtime["dependencies"]) == runtime_dependencies
    assert set(development["dependencies"]) == runtime_dependencies | development_dependencies
