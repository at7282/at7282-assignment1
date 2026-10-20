# Reproducing the evidence PDF

The submission PDF in `docs/evidence-report.pdf` is generated from the terminal
captures in `docs/evidence/`. Every command below is safe to run: the credential used in
the TruffleHog test is synthetic, and the secret is never committed.

## Prerequisites

```console
poetry install
trufflehog --version      # 3.x
poetry run pre-commit install
```

If `trufflehog` is not on `PATH`, set `TRUFFLEHOG_BIN` to its absolute path.

## 1. TruffleHog detects a leaked secret

Stage a file containing a fake AWS key and attempt a commit:

```console
printf 'aws_access_key_id = AKIAZ7Q2XJ4W6M8P0R3T\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n' > leak-test.txt  # trufflehog:ignore
git add leak-test.txt
git commit -m "Add fake credential"
```

The commit is blocked and the hook prints `Found unverified result` with
`Detector Type: AWS`, then exits with code 183. The `--no-verification` option is set in
`scripts/scan_staged_secrets.py`, so TruffleHog does not call AWS to validate the key.

Capture the terminal output for the screenshot, then clean up:

```console
git restore --staged leak-test.txt
rm leak-test.txt
```

**What the screenshot must show:** the `trufflehog-staged` hook failing, the AWS
detector result, and the fact that `git commit` did not create a commit.

## 2. pytest coverage report

```console
poetry run pytest
```

The command runs 67 tests, prints the coverage table, writes `htmlcov/index.html` and
`coverage.xml`, and exits successfully only if total coverage is at least 75%. The
current result is **95.98%**.

To capture the HTML report instead:

```console
poetry run pytest
python -m http.server 8000 --directory htmlcov
```

Open <http://localhost:8000> and capture the browser window. Stop the server with
`Ctrl+C` afterwards.

**What the screenshot must show:** the test summary (`67 passed`), the per-file coverage
table, and the final `Required test coverage of 75% reached` line.

## 3. Branch protection for `main`

Open the repository settings in a browser:

1. Go to <https://github.com/at7282/at7282-assignment1/settings/branches>.
2. The rule named `main` shows **Require a pull request before merging**,
   **Require linear history**, and the force-push/deletion restrictions.
3. Capture the rule, including the branch name pattern and the enabled checkboxes.

The same configuration is applied and verified from the command line:

```console
gh api --method PUT repos/at7282/at7282-assignment1/branches/main/protection \
    --input .github/branch-protection.json
gh api repos/at7282/at7282-assignment1/branches/main/protection
```

**What the screenshot must show:** the branch protection rule for `main` with pull
requests and linear history enabled.

## Rebuilding the PDF

After refreshing the text captures in `docs/evidence/`, rebuild the PDF with the
standard library only:

```console
python docs/build_evidence_pdf.py docs/evidence docs/evidence-report.pdf
```

The generated PDF is plain text on a white background. If your submission requires
screenshots rather than terminal captures, take the screenshots described above and
replace the corresponding pages, or append the images to the PDF.
