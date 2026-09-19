"""Install the bundled FalseAlarm agent skill into a supported skill directory."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from falsealarm.core.utils import get_data_path


SUPPORTED_SKILL_TARGETS = ("codex", "claude", "project")


def resolve_skill_destination(
    target: str = "codex",
    destination: str | Path | None = None,
) -> Path:
    """Resolve the final ``falsealarm`` skill directory."""
    if destination is not None:
        return Path(destination).expanduser().resolve()

    normalized = target.lower().strip()
    if normalized == "codex":
        configured_root = os.environ.get("CODEX_HOME")
        codex_root = Path(configured_root).expanduser() if configured_root else Path.home() / ".codex"
        return codex_root.resolve() / "skills" / "falsealarm"
    if normalized == "claude":
        return (Path.home() / ".claude" / "skills" / "falsealarm").resolve()
    if normalized == "project":
        return (Path.cwd() / ".agents" / "skills" / "falsealarm").resolve()

    choices = ", ".join(SUPPORTED_SKILL_TARGETS)
    raise ValueError(f"Unsupported skill target '{target}'. Choose one of: {choices}.")


def install_agent_skill(
    target: str = "codex",
    destination: str | Path | None = None,
    force: bool = False,
) -> Path:
    """Copy the bundled agent skill and return its installed directory."""
    source = get_data_path("skills/falsealarm")
    if not (source / "SKILL.md").is_file():
        raise FileNotFoundError("The packaged FalseAlarm agent skill is missing.")

    resolved = resolve_skill_destination(target=target, destination=destination)
    if resolved.exists() and not force:
        raise FileExistsError(
            f"Skill already exists at {resolved}. Re-run with --force to update it."
        )

    resolved.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, resolved, dirs_exist_ok=force)
    return resolved
