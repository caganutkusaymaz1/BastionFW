# Security Policy

## Reporting a vulnerability

**Do not open a public GitHub issue for security problems.**

Report privately to the repository owner via GitHub Security Advisories
("Report a vulnerability" on this repository) or by contacting
**Cagan Utku Saymaz** through GitHub
([@caganutkusaymaz1](https://github.com/caganutkusaymaz1)).

Include: affected component, reproduction steps or PoC, impact assessment,
and any logs (with secrets redacted). You will receive an acknowledgment
within 72 hours and a status update at least every 7 days until resolution.

## Supported versions

| Version | Supported |
|---|---|
| 3.1.x (main branch) | yes |
| < 3.1 | no |

## Coordinated disclosure

We practice coordinated disclosure: fixes are developed privately, released
with the next patch version, and credited reporters are announced together
with the fix unless they prefer otherwise.

## Threat model and known limitations

The full threat model — what BastionFW protects, what it explicitly does
**not** protect, trust boundaries, and disclosed limitations — lives in
[`THREAT_MODEL.md`](THREAT_MODEL.md). Read it before deploying: it describes
verified current behavior, not aspirations.

## Automated security testing

Continuous-integration checks are defined in
`.github/workflows/ci.yml` and summarized in the README's
[Security Posture](README.md#security-posture) section.
