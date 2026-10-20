# Python Rekor Monitor

A command-line verifier for entries in the [Sigstore Rekor](https://rekor.sigstore.dev)
transparency log. It can fetch the latest signed checkpoint, verify that a log entry is
included in the log, verify the artifact signature attached to an entry, and check
consistency between a previous checkpoint and the current log.

## Features

- Fetch and print the latest Rekor signed checkpoint.
- Verify an entry's Merkle inclusion proof and artifact signature.
- Verify consistency between an older checkpoint and the latest checkpoint.

## Requirements

- Python 3.11 or newer
- [Poetry](https://python-poetry.org/) 2.x
- Network access to `https://rekor.sigstore.dev`
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) 3.x for the pre-commit
  secret scan

## Installation

```console
git clone git@github.com:at7282/at7282-assignment1.git
cd at7282-assignment1
poetry install
```

`poetry install` installs the runtime dependency (`cryptography`) and the development
tools (`ruff`, `mypy`, `bandit`, `pytest`, `pytest-cov`, and `pre-commit`).

## Usage

### Fetch the latest checkpoint

```console
poetry run python main.py --checkpoint
```

Add `--debug` to print the raw signed tree head and other diagnostic output.

### Verify an entry and its artifact signature

```console
poetry run python main.py --inclusion <log-index> --artifact examples/artifact.md
```

The command fetches the log entry, extracts the signing certificate and signature,
checks the signature against the artifact, and verifies the Merkle inclusion proof.

### Verify consistency between checkpoints

```console
poetry run python main.py --consistency \
    --tree-id <tree-id> \
    --tree-size <previous-tree-size> \
    --root-hash <previous-root-hash>
```

The previous values may come from an earlier `--checkpoint` run. A consistency proof is
only requested when the previous tree size is smaller than the current size.

## Development

### Linting, formatting, and static analysis

```console
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy
poetry run bandit -r .
```

### Tests and coverage

```console
poetry run pytest
```

The pytest configuration in `pyproject.toml` runs the suite with coverage, writes a
terminal report, an HTML report in `htmlcov/`, and `coverage.xml`, and fails the run if
total coverage drops below 75%.

Run a single test file or an individual test with the usual pytest arguments:

```console
poetry run pytest tests/test_merkle_proof.py
poetry run pytest tests/test_main.py::test_inclusion_verifies_signature_and_merkle_proof
```

To view the HTML coverage report, open `htmlcov/index.html` in a browser.

### Secret scanning with pre-commit

Install TruffleHog 3.x first (the scanner is not a Python package):

```console
# macOS
brew install trufflesecurity/trufflehog/trufflehog

# Linux: download a release binary from
# https://github.com/trufflesecurity/trufflehog/releases
trufflehog --version
```

Then install the hook once per clone:

```console
poetry run pre-commit install
```

The `trufflehog-staged` hook scans only the files staged for the pending commit. It
never scans the full repository history, which keeps commit time constant as the
repository grows. The scanner is implemented in
`scripts/scan_staged_secrets.py` and runs TruffleHog with `--no-verification` so it
works offline.

To confirm the hook blocks a secret, stage a file containing a fake credential and run
the hook directly:

```console
printf 'aws_access_key_id = AKIAZ7Q2XJ4W6M8P0R3T\n' > leak-test.txt  # trufflehog:ignore
git add leak-test.txt
poetry run pre-commit run trufflehog-staged
```

The command exits non-zero with a `Found unverified result` message. Remove the test
file afterwards:

```console
git restore --staged leak-test.txt
rm leak-test.txt
```

If TruffleHog is installed somewhere outside `PATH`, set `TRUFFLEHOG_BIN` to its
absolute path before committing.

### Branch protection

`main` requires pull requests and a linear commit history. The desired settings are
stored in [`.github/branch-protection.json`](.github/branch-protection.json) and can be
applied by a repository administrator:

```console
gh api --method PUT repos/at7282/at7282-assignment1/branches/main/protection \
    --input .github/branch-protection.json
```

Reviewers are not required by default because the repository currently has a single
maintainer; pull requests and linear history are still mandatory.

### Security and testing evidence

- [`docs/REPRODUCING-EVIDENCE.md`](docs/REPRODUCING-EVIDENCE.md) — exact commands and a
  screenshot checklist for the TruffleHog, coverage, and branch protection evidence.
- `docs/evidence/` — captured terminal output for each check.
- `docs/evidence/tool-outputs/` — initial and final Ruff, mypy, and Bandit reports.
- [`docs/evidence-report.pdf`](docs/evidence-report.pdf) — submission-ready PDF built
  from those captures.

Rebuild the PDF after refreshing the captures:

```console
python docs/build_evidence_pdf.py docs/evidence docs/evidence-report.pdf
```

## Repository layout

- `main.py` — command-line interface and Rekor API calls.
- `merkle_proof.py` — Merkle inclusion and consistency proof verification.
- `util.py` — certificate handling and artifact signature verification.
- `scripts/create_artifact.py` — creates a simple `examples/artifact.md` containing a NetID.
- `scripts/scan_staged_secrets.py` — staged-only TruffleHog pre-commit scanner.
- `tests/` — pytest suite (unit tests with no network access).
- `examples/` — sample artifact (`artifact.md`) and its signing material
  (`artifact.bundle`, `artifact.sigstore.json`).

## Security

Please do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md)
for the supported versions and the private reporting process.

## Contributing

Development workflow, coding style, and testing requirements are documented in
[CONTRIBUTING.md](CONTRIBUTING.md). Code ownership is defined in
[.github/CODEOWNERS](.github/CODEOWNERS).

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE).
