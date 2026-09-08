# Security policy

This repository is covered by the organisation's vulnerability handling
process under the EU Cyber Resilience Act. Findings are tracked as issues
labelled `cra-triage` with a priority from P1 to P4.

## Supported versions

Only the `main` branch and the latest tagged release receive security fixes.
Older releases are not maintained.

## Reporting a vulnerability

Do not open a public issue for a vulnerability.

Use "Report a vulnerability" under the Security tab of this repository, which
opens a private report that only maintainers can read. If you cannot use
GitHub, write to security@cybertec.at.

What to include: the affected file, version or commit, steps to reproduce,
and the impact you believe it has. A proof of concept helps; live
exploitation of any system does not, and is not authorised.

## What to expect

| Step | Within |
|---|---|
| Acknowledgement of your report | 2 working days |
| First assessment with a priority | 5 working days |
| Status update while open | every 14 days |
| Fix for P1 (CVSS 9.0 or higher) | 7 days |
| Fix for P2 (CVSS 7.0 to 8.9) | 30 days |
| Fix for P3 and P4 | next planned release, 90 days at most |

Priorities use CVSS 3.1: a published score for a known CVE, or a reviewed
vector per weakness class for a code finding. The vector table is public in
the cra-gates repository.

When the fix is released we credit the reporter unless they ask otherwise,
and we publish a GitHub security advisory for the affected versions.

## Coordinated disclosure

We ask for 90 days from acknowledgement before public disclosure, or until
a fix is released, whichever comes first. We will agree an earlier date if
the vulnerability is being exploited or is already public.

## Actively exploited vulnerabilities

Evidence that a vulnerability is being exploited starts the organisation's
Cyber Resilience Act notification process, which is handled by
the Cybertec security team (security@cybertec.at) and is separate from the timelines above. Report such
evidence the same way and say so in the first line.
