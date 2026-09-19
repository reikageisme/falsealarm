from pathlib import Path

import pytest
from typer.testing import CliRunner

from falsealarm import __version__
from falsealarm.cli import app
from falsealarm.core.skill_installer import (
    install_agent_skill,
    resolve_skill_destination,
)


def test_install_bundled_skill_to_custom_destination(tmp_path):
    destination = tmp_path / "falsealarm"

    installed = install_agent_skill(destination=destination)

    assert installed == destination.resolve()
    assert (installed / "SKILL.md").is_file()
    assert (installed / "agents" / "openai.yaml").is_file()
    assert (installed / "references" / "operations.md").is_file()
    assert (installed / "references" / "development.md").is_file()


def test_install_refuses_to_overwrite_without_force(tmp_path):
    destination = tmp_path / "falsealarm"
    install_agent_skill(destination=destination)

    with pytest.raises(FileExistsError, match="--force"):
        install_agent_skill(destination=destination)

    assert install_agent_skill(destination=destination, force=True) == destination.resolve()


def test_project_destination_uses_agents_directory(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    assert resolve_skill_destination("project") == (
        Path(tmp_path) / ".agents" / "skills" / "falsealarm"
    ).resolve()


def test_codex_destination_honors_codex_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path))

    assert resolve_skill_destination("codex") == (
        Path(tmp_path) / "skills" / "falsealarm"
    ).resolve()


def test_unknown_skill_target_is_rejected():
    with pytest.raises(ValueError, match="Unsupported skill target"):
        resolve_skill_destination("unknown-agent")


def test_global_version_option_reports_package_version():
    result = CliRunner().invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"FalseAlarm v{__version__}"
