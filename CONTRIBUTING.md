# Contributing

Thanks for contributing to Python Rekor Monitor. This document describes how to report
issues, submit pull requests, and run the checks that CI and reviewers expect.

## Reporting issues

Before opening an issue:

1. Search existing issues to avoid duplicates.
2. Reproduce the problem on the latest `main`.
3. Remove credentials, tokens, and private keys from logs and screenshots.

Open a GitHub issue for bugs and feature requests. Include:

- What you expected to happen and what actually happened.
- Steps to reproduce, with the exact command and a sample log index if relevant.
- Python version, Poetry version, and operating system.
- The relevant error output.

**Security issues must not be reported in a public issue.** Follow
[SECURITY.md](SECURITY.md) instead.

## Pull requests

1. Create a topic branch from `main` (`fix/...`, `feat/...`, or `docs/...`).
2. Keep the change focused. Separate refactors from behavior changes.
3. Add or update tests for behavior changes.
4. Run the checks below before opening the pull request.
5. Open the pull request against `main` and describe the motivation and the approach.
6. Address review comments by pushing additional commits or amending as requested. The
   `main` branch requires a linear history, so keep the branch rebased on `main` and
   avoid merge commits.

Pull requests should not be merged with failing checks or unresolved review comments.

## Coding style

- Follow the existing style and keep changes minimal.
- Format and lint with Ruff; the configuration lives in `pyproject.toml`.
  - Line length is 100 characters.
  - Enabled lint rules: `E`, `F`, `I`, `B`, and `UP`.
  - Use double quotes and spaces for indentation.
- Add type hints to new functions where practical and pass `mypy`.
- Prefer the standard library and existing dependencies over new packages.
- Do not commit generated files, local virtual environments, coverage reports, or
  credentials.
- Keep comments for non-obvious intent, constraints, or security decisions. Do not add
  comments that restate the code.

## Testing requirements

- Every bug fix needs a regression test.
- New behavior needs unit tests in `tests/`.
- Tests must not depend on network access. Mock Rekor responses and use local fixtures.
- Keep total line coverage at or above **75%**. `poetry run pytest` enforces this
  through `--cov-fail-under=75`; CI and reviewers expect the command to pass.
- Add tests for error paths and validation, not only the happy path.

Run the full suite:

```console
poetry run pytest
```

The HTML report is written to `htmlcov/index.html`; the terminal report is printed by
the same command.

## Pre-submit checks

```console
poetry run ruff check .
poetry run ruff format --check .
poetry run mypy
poetry run bandit -r .
poetry run pytest
```

Install the secret-scanning hook once per clone:

```console
poetry run pre-commit install
```

The hook scans only the files staged for the next commit. To run it manually:

```console
poetry run pre-commit run trufflehog-staged
```

Never bypass the hook with `git commit --no-verify`. If a secret was already committed,
revoke it immediately and follow the incident steps in [SECURITY.md](SECURITY.md).

## Commit messages

- Use the imperative mood in the subject line.
- Keep the subject line under about 50 characters.
- Explain the reason for the change in the body when the subject is not enough.
- Do not include secrets, tokens, or customer data in commit messages.

## Review and ownership

- Code ownership is defined in `.github/CODEOWNERS`.
- `main` is protected: changes require a pull request and a linear history.
- Reviewers check correctness, tests, security impact, and documentation updates.

## License

By contributing, you agree that your contribution is licensed under the project's
[MIT License](LICENSE).
