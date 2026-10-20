# Security Policy

## Supported versions

Security fixes are provided for the latest release line. Older releases may be asked to
upgrade before a fix is issued.

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| < 0.1   | No        |

## Reporting a vulnerability

Do **not** open a public GitHub issue, pull request, or discussion for a suspected
vulnerability. Report it privately using one of these channels:

1. GitHub private vulnerability reporting for
   [`at7282/at7282-assignment1`](https://github.com/at7282/at7282-assignment1/security/advisories/new)
   (preferred).
2. Email `at7282@nyu.edu` with the subject `SECURITY: python-rekor-monitor`.

Please include:

- A description of the issue and the affected component.
- Reproduction steps or a proof of concept.
- The affected version or commit.
- Any known impact, such as signature bypass, proof forgery, or credential exposure.
- Whether you intend to disclose the issue publicly and your preferred timeline.

Do not include real credentials, tokens, or private keys in a report. Use redacted or
synthetic values.

## What to expect

- Acknowledgement of the report within 3 business days.
- Initial triage and a severity assessment within 7 business days.
- A status update at least every 10 business days while the issue is being fixed.
- Credit in the release notes if you would like to be acknowledged.

Please allow up to 90 days for a fix and coordinated disclosure. We will coordinate an
earlier disclosure date with you if the issue is being exploited or is already public.

## How security updates are handled

1. The report is reproduced privately and the affected versions are identified.
2. A fix is developed on a private branch or fork and reviewed by the code owner listed
   in `.github/CODEOWNERS`.
3. Tests are added that fail without the fix and pass with it.
4. A patch release is published with a security advisory that describes the impact,
   affected versions, and upgrade instructions.
5. Any leaked credential is revoked immediately. Removing the value from Git history is
   a separate cleanup step; revocation must happen first.

`main` is protected and requires pull requests and a linear commit history, so security
fixes reach it through reviewed pull requests rather than direct pushes.

## Secrets and dependency hygiene

- The `trufflehog-staged` pre-commit hook scans only the files staged for the pending
  commit. See [CONTRIBUTING.md](CONTRIBUTING.md) for setup.
- If a secret is committed, revoke or rotate it first, then remove it from history and
  notify the maintainer at `at7282@nyu.edu`.
- Report a vulnerable dependency through the private channels above rather than a public
  issue.
