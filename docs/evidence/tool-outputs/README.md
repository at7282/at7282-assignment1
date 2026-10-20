# Automated Tool Output

Initial outputs were generated against the Assignment 1 submission, commit
`e897ce2` ("Verified consistency of the transparency log"). The tool
configuration added in this assignment was applied to that code state.

Final outputs were generated against the current working tree after all
formatting, lint, type-checking, and Bandit issues were resolved.

## Tools and versions

- Ruff 0.17.1 (formatter and linter)
- mypy 2.4.0 (type checker)
- Bandit 1.9.4 (SAST)

## Files

| File | Contents |
| --- | --- |
| `ruff.initial.txt` | Ruff lint output for Assignment 1 |
| `ruff.final.txt` | Ruff lint output for the fixed tree |
| `ruff-format.initial.txt` | Ruff formatter check for Assignment 1 |
| `ruff-format.final.txt` | Ruff formatter check for the fixed tree |
| `mypy.initial.txt` | mypy output for Assignment 1 |
| `mypy.final.txt` | mypy output for the fixed tree |
| `bandit.initial.txt` | Bandit report for Assignment 1 |
| `bandit.final.txt` | Bandit report for the fixed tree |
| `rekor-link.txt` | Rekor API URL for the sample log entry |

## Commands

```console
poetry run ruff check -o <output>
poetry run ruff format --check <target>
poetry run mypy main.py merkle_proof.py util.py
poetry run bandit -r . -o <output> -f txt
```
