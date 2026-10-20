import runpy
import sys
from pathlib import Path
from subprocess import CompletedProcess

import pytest

import scripts.scan_staged_secrets as scanner

ROOT = Path(__file__).resolve().parents[1]
CREATE_ARTIFACT = ROOT / "scripts" / "create_artifact.py"


def test_create_artifact_writes_netid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(CREATE_ARTIFACT), "at7282"])

    runpy.run_path(str(CREATE_ARTIFACT), run_name="__main__")

    assert (tmp_path / "artifact.md").read_text(encoding="utf-8") == "at7282\n"


def test_create_artifact_requires_netid(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", [str(CREATE_ARTIFACT)])

    with pytest.raises(SystemExit):
        runpy.run_path(str(CREATE_ARTIFACT), run_name="__main__")

    assert not (tmp_path / "artifact.md").exists()


def test_staged_files_returns_non_empty_paths(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "_run_git",
        lambda *args, **kwargs: CompletedProcess(args, 0, "a.txt\0b.txt\0", ""),
    )

    assert scanner.staged_files() == ["a.txt", "b.txt"]


def test_staged_files_raises_when_git_fails(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "_run_git",
        lambda *args, **kwargs: CompletedProcess(args, 1, "", "git failed"),
    )

    with pytest.raises(RuntimeError, match="git failed"):
        scanner.staged_files()


def test_find_trufflehog_uses_environment_override(tmp_path, monkeypatch):
    executable = tmp_path / "trufflehog"
    executable.write_text("", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setenv("TRUFFLEHOG_BIN", str(executable))

    assert scanner.find_trufflehog() == str(executable)


def test_find_trufflehog_returns_none_when_missing(monkeypatch):
    monkeypatch.delenv("TRUFFLEHOG_BIN", raising=False)
    monkeypatch.setenv("HOME", "/nonexistent-home")
    monkeypatch.setattr(scanner.shutil, "which", lambda name: None)

    assert scanner.find_trufflehog() is None


def test_main_returns_zero_when_nothing_is_staged(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "staged_files", lambda: [])

    assert scanner.main() == 0
    assert "nothing to scan" in capsys.readouterr().out


def test_main_reports_git_failure(monkeypatch, capsys):
    def fail():
        raise RuntimeError("index unavailable")

    monkeypatch.setattr(scanner, "staged_files", fail)

    assert scanner.main() == 1
    assert "index unavailable" in capsys.readouterr().err


def test_main_reports_missing_trufflehog(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "staged_files", lambda: ["a.txt"])
    monkeypatch.setattr(scanner, "find_trufflehog", lambda: None)

    assert scanner.main() == 1
    assert "executable not found" in capsys.readouterr().err


def test_main_scans_staged_blobs_and_returns_scanner_status(monkeypatch):
    calls = []

    def fake_git(*args, text=True):
        if args[:2] == ("diff", "--cached"):
            return CompletedProcess(args, 0, "a.txt\0dir/b.txt\0", "")
        if args[0] == "show":
            return CompletedProcess(args, 0, b"staged-content", b"")
        return CompletedProcess(args, 0, "", "")

    def fake_run(command, check=False):
        scanned_root = Path(command[2])
        recorded = {
            path.relative_to(scanned_root).as_posix(): path.read_bytes()
            for path in scanned_root.rglob("*")
            if path.is_file()
        }
        calls.append((command, recorded))
        return CompletedProcess(command, 183)

    monkeypatch.setattr(scanner, "_run_git", fake_git)
    monkeypatch.setattr(scanner, "find_trufflehog", lambda: "trufflehog")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    assert scanner.main() == 183
    command, recorded = calls[0]
    assert recorded == {
        "a.txt": b"staged-content",
        "dir/b.txt": b"staged-content",
    }
    assert command[0] == "trufflehog"
    assert "--no-verification" in command
    assert "--fail" in command


def test_main_skips_staged_files_that_cannot_be_read(monkeypatch):
    def fake_git(*args, text=True):
        if args[:2] == ("diff", "--cached"):
            return CompletedProcess(args, 0, "deleted.txt\0", "")
        return CompletedProcess(args, 1, b"", b"missing")

    completed = []

    def fake_run(command, check=False):
        completed.append(command)
        return CompletedProcess(command, 0)

    monkeypatch.setattr(scanner, "_run_git", fake_git)
    monkeypatch.setattr(scanner, "find_trufflehog", lambda: "trufflehog")
    monkeypatch.setattr(scanner.subprocess, "run", fake_run)

    assert scanner.main() == 0
    assert completed[0][0] == "trufflehog"
