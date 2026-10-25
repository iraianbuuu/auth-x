# Security policy

## Supported versions

Only the latest release gets security fixes. Until 1.0.0, fixes ship as a new minor or patch version of the latest 0.x release.

## Reporting a vulnerability

Do not open a public issue. Report it privately through [GitHub security advisories](https://github.com/iraianbuuu/auth-x/security/advisories/new).

Include the affected version, what an attacker can do, and steps or code that reproduce it. You will get a reply within 7 days. Once a fix is released, the advisory is published with credit to you unless you ask otherwise.

## Scope

In scope: wrong verification results, replay or timing weaknesses, encryption flaws, and anything that leaks secrets or recovery codes.

Out of scope: rate limiting, sessions, storage and key management in the application that uses auth-x. The README lists what the application is responsible for.
