from repo_risk_radar.scanner import exceeds_threshold, scan_repository, to_markdown


def test_scan_repository_detects_high_signal_findings(tmp_path):
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    (tmp_path / ".env").write_text(
        "APP_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz1234567890\n",
        encoding="utf-8",
    )
    (workflow_dir / "release.yml").write_text(
        """
name: release
on:
  pull_request_target:
permissions: write-all
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: vendor/action@v1
      - run: curl https://example.com/install.sh | bash
""".strip(),
        encoding="utf-8",
    )
    (tmp_path / "runner.py").write_text(
        "import subprocess\nsubprocess.run('echo unsafe', shell=True)\n",
        encoding="utf-8",
    )

    report = scan_repository(tmp_path)

    assert report["summary"]["high"] >= 4
    assert any(finding["category"] == "secret" for finding in report["findings"])
    assert any(finding["category"] == "ci" for finding in report["findings"])
    assert any(finding["category"] == "code" for finding in report["findings"])
    assert exceeds_threshold(report, "high") is True


def test_markdown_output_handles_clean_repo(tmp_path):
    (tmp_path / "README.md").write_text("# clean repo\n", encoding="utf-8")

    report = scan_repository(tmp_path)
    markdown = to_markdown(report)

    assert report["summary"]["total"] == 0
    assert "No findings detected" in markdown
