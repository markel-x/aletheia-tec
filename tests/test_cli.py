"""CLI: la demostración recorre el flujo del núcleo y respeta el entorno."""

from __future__ import annotations

import json

import pytest

from aletheia.cli import main


def test_demo_runs_full_core_flow(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("ALETHEIA_ENV", "development")
    assert main(["demo"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["verification_before_revocation"]["result"] == "valid"
    assert out["verification_after_revocation"]["reason"] == "credential_revoked"
    assert out["verification_after_revocation"]["disclosed_claims"] is None


@pytest.mark.parametrize("env", [None, "production", "staging"])
def test_demo_refuses_outside_development(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], env: str | None
) -> None:
    if env is None:
        monkeypatch.delenv("ALETHEIA_ENV", raising=False)
    else:
        monkeypatch.setenv("ALETHEIA_ENV", env)
    assert main(["demo"]) == 2
    assert "no está permitido" in capsys.readouterr().err


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["version"]) == 0
    assert json.loads(capsys.readouterr().out)["profile"] == "ALT-P1"
