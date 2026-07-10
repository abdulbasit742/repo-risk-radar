import json

from repo_risk_radar.cli import main


def test_cli_exit_code_for_high_findings(tmp_path, capsys):
    (tmp_path / ".env").write_text(
        "APP_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )

    exit_code = main(["scan", str(tmp_path), "--format", "json", "--fail-on", "high"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["summary"]["high"] >= 1


def test_cli_exit_code_for_clean_repo(tmp_path, capsys):
    (tmp_path / "README.md").write_text("# clean repo\n", encoding="utf-8")

    exit_code = main(["scan", str(tmp_path), "--format", "markdown", "--fail-on", "critical"])
    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Repo Risk Radar Report" in captured.out
