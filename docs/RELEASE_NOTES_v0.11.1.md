# ThreatForge Community v0.11.1 — IOC Enrichment Verdict and Status Hotfix

ThreatForge Community v0.11.1 corrects the semantics and public presentation
of IOC enrichment results.

## Fixed

- Unavailable or unconfigured intelligence sources are now distinguished from
  successful negative lookups.
- Skipped, empty, malformed or unrecognized connector responses no longer
  cause an observable to be classified as `no_known_threat`.
- When no recognized source proves that a lookup was executed, the verdict is
  `unknown`.
- Explicit negative results from recognized sources continue to produce
  `no_known_threat`.
- Positive scoring behavior for CISA KEV, EPSS and URLhaus remains preserved.
- Historical zero-score `no_known_threat` outcomes are normalized to `unknown`
  when no successful negative lookup is present.
- Enrichment skips produce sanitized source-level warnings without exposing
  connector exceptions or raw upstream errors.
- Public IOC enrichment and KEV/MITRE synchronization messages are presented
  in English.

## Security and reliability

- Connector execution is accepted only when a recognized result shape proves
  that the lookup ran.
- Missing credentials and skipped connectors cannot be interpreted as clean
  threat-intelligence results.
- Raw connector failures remain excluded from public responses.
- Existing tenant isolation, authorization and audit boundaries remain in
  effect.

## Database and compatibility

- Community application version: 0.11.1.
- No database migration is required.
- The v0.11.0 Telegram Intelligence migration and contracts remain unchanged.
- Historical v0.11.0 release documentation remains preserved.
- The Enterprise overlay remains on the `0.11.x` release train and requires
  final compatibility acceptance against the release image before publication.

## Validation

Release acceptance includes:

- CI-equivalent application import validation;
- the tenant-isolation selftest;
- regression coverage for skipped, negative and positive enrichment results;
- historical verdict normalization coverage;
- final image build and `/health` validation reporting version `0.11.1`;
- controlled IOC enrichment validation in the POC.

## Upgrade notes

1. Back up the database and evidence volumes before deployment.
2. Rebuild the application image from the v0.11.1 release commit.
3. No Alembic migration is required for this hotfix.
4. Confirm that `/health` reports version `0.11.1`.
5. Validate one unavailable-source result, one explicit negative result and
   one positive enrichment result.
6. Confirm compatibility with the installed Enterprise overlay before
   production promotion.
