"""Etapa 2 — URLhaus / enrichment error handling.

Covers the POC finding: when an external enrichment source (URLhaus) fails
with an HTTP error, the API must not leak the raw exception class (e.g.
"HTTPStatusError") to the client, must keep the observable as UNKNOWN instead
of registering it as clean, and must record the technical failure in the
audit trail.

Isolation: uses the shared `tenant_admin_client` fixture from `conftest.py`,
which purges cached `app.*` modules and rebuilds a fresh FastAPI app + fresh
SQLite DB per test. Previously each test file rolled its own fixture with
`os.environ` mutation, which left `app.database.engine` bound to the first
test's DB and produced `POST /setup/operator -> 409 Conflict` on every
follow-up test.
"""
from __future__ import annotations
import pytest


def _make_urlhaus_403(monkeypatch):
    """Force the URLhaus connector on the freshly-imported app to fail
    exactly like the POC log:
    ``POST https://urlhaus-api.abuse.ch/v1/host/ -> 403 Forbidden``.
    """
    import app.routers.observables as obs_router

    class _FakeResponse:
        status_code = 403

    class _FakeHTTPStatusError(Exception):
        def __init__(self):
            super().__init__("403 Forbidden")
            self.response = _FakeResponse()

    def _raise(self, observable_type, value, db):
        raise _FakeHTTPStatusError()

    for connector in obs_router.CONNECTORS:
        if connector.name == "urlhaus":
            monkeypatch.setattr(connector, "enrich", _raise.__get__(connector))


def test_enrich_urlhaus_403_returns_friendly_message_not_raw_exception(
    tenant_admin_client, monkeypatch
):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.10"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")

    # Controlled response: 200, not a 502 that reads as an internal platform
    # error.
    assert r.status_code == 200, r.text
    body = r.json()

    # Never leak the technical exception class or raw HTTP error text.
    raw_text = r.text.lower()
    for leaked in ("httpstatuserror", "403 forbidden", "traceback"):
        assert leaked not in raw_text, f"leaked technical detail: {leaked}"

    # Friendly, source-specific message instead.
    assert body["enrichment_warnings"], body
    assert any("urlhaus" in w.lower() for w in body["enrichment_warnings"])


def test_enrich_urlhaus_403_keeps_ioc_as_unknown(tenant_admin_client, monkeypatch):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.11"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()

    # IOC is neither removed nor corrupted; it stays registered as UNKNOWN
    # rather than being scored as "no known threat" (a check that never ran).
    assert body["verdict"] == "unknown", body
    assert body["score"] == 0, body

    still_there = client.get(f"/observables/{obs_id}")
    assert still_there.status_code == 200
    assert still_there.json()["verdict"] == "unknown"


def test_enrich_urlhaus_403_is_logged_to_audit(tenant_admin_client, monkeypatch):
    client = tenant_admin_client
    _make_urlhaus_403(monkeypatch)

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.12"})
    obs_id = created.json()["id"]
    client.post(f"/observables/{obs_id}/enrich")

    audit_entries = client.get("/audit").json()
    matches = [a for a in audit_entries if a.get("action") == "enrichment.source_failed"]
    assert matches, audit_entries
    detail = matches[0].get("detail") or {}
    assert detail.get("source") == "urlhaus"
    assert detail.get("status_code") == 403
    assert detail.get("error_type")


def _patch_urlhaus_return(monkeypatch, payload):
    """Make the freshly-imported app's URLhaus connector return ``payload``
    deterministically, without touching the host/CI environment or the network.
    """
    import app.routers.observables as obs_router

    for connector in obs_router.CONNECTORS:
        if connector.name == "urlhaus":
            monkeypatch.setattr(
                connector,
                "enrich",
                lambda observable_type, value, db, _p=payload: _p,
            )


def test_enrich_unconfigured_source_keeps_ioc_unknown(
    tenant_admin_client, monkeypatch
):
    """A connector that reports itself skipped (e.g. missing API key) is NOT a
    clean lookup: the IOC stays UNKNOWN, nothing is persisted for that source,
    and the skip is audited. Deterministic: URLhaus is monkeypatched to return
    an explicit skip marker rather than depending on ABUSECH_API_KEY."""
    client = tenant_admin_client
    _patch_urlhaus_return(
        monkeypatch,
        {"skipped": True, "reason": "ABUSECH_API_KEY is not configured"},
    )

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.20"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["verdict"] == "unknown", body
    assert body["score"] == 0, body
    assert body["enrichment_warnings"], body
    assert any("is not configured" in w for w in body["enrichment_warnings"]), body

    # No Enrichment row is persisted for a source that did not run.
    assert all(e.get("source") != "urlhaus" for e in body.get("enrichments", [])), body

    # The skip is recorded in the audit trail (distinct from source_failed).
    audit_entries = client.get("/audit").json()
    skips = [a for a in audit_entries if a.get("action") == "enrichment.source_skipped"]
    assert skips, audit_entries
    assert (skips[0].get("detail") or {}).get("source") == "urlhaus", skips[0]


def test_urlhaus_ip_no_match_keeps_ioc_unknown(
    tenant_admin_client, monkeypatch
):
    """A source that ran and returned an explicit NO MATCH no longer yields
    no_known_threat: the IOC stays UNKNOWN with score 0."""
    client = tenant_admin_client
    _patch_urlhaus_return(monkeypatch, {"listed": False, "query_status": "no_results"})

    created = client.post("/observables", json={"type": "ip", "value": "203.0.113.21"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    r = client.post(f"/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "unknown", body
    assert body["score"] == 0, body


@pytest.mark.parametrize(
    "enrichments, expected_verdict",
    [
        # No provider ran (e.g. an e-mail observable, no matching connector).
        ({}, "unknown"),
        ({"urlhaus": None}, "unknown"),
        ({"urlhaus": {}}, "unknown"),
        ({"urlhaus": {"skipped": True}}, "unknown"),
        ({"epss": {"epss": None}}, "unknown"),
        ({"unknown_source": {"status": "unavailable"}}, "unknown"),
        # A single source that ran and returned NO MATCH must never produce a
        # global no_known_threat verdict anymore — it stays UNKNOWN with score 0.
        ({"urlhaus": {"listed": False, "query_status": "no_results"}}, "unknown"),
        ({"urlhaus": {"listed": False, "url_status": "unknown"}}, "unknown"),
        ({"cisa_kev": {"listed": False}, "epss": {"epss": 0.0}}, "unknown"),
        ({"urlhaus": {"listed": False}}, "unknown"),
        (
            {"urlhaus": {"skipped": True}, "cisa_kev": {"listed": False}},
            "unknown",
        ),
    ],
)
def test_compute_score_zero_factor_contract(enrichments, expected_verdict):
    """unknown unless a recognized connector proves a lookup ran; a real
    explicit-negative result yields no_known_threat. Both zero-factor verdicts
    must have score 0 and no factors."""
    from app.scoring import compute_score

    score, verdict, factors = compute_score(enrichments)
    assert verdict == expected_verdict, (enrichments, score, verdict, factors)
    assert score == 0, (enrichments, score)
    assert factors == [], (enrichments, factors)


def test_no_known_threat_is_never_emitted_but_mapping_kept():
    """A historical row stored as 'no_known_threat' re-scores to 'unknown':
    compute_score never emits no_known_threat again, while the public mappings
    still RECOGNIZE the historical value (no data migration / rewrite)."""
    from app.scoring import compute_score
    from app.reporting import _VERDICT_PT
    from app.exporters import _VERDICT_INDICATOR_TYPE

    for enr in (
        {},
        {"urlhaus": {"listed": False}},
        {"cisa_kev": {"listed": False}},
        {"epss": {"epss": 0.0}},
        {"urlhaus": {"skipped": True}, "cisa_kev": {"listed": False}},
    ):
        assert compute_score(enr) == (0, "unknown", []), enr
    assert "no_known_threat" in _VERDICT_PT, _VERDICT_PT
    assert "no_known_threat" in _VERDICT_INDICATOR_TYPE, _VERDICT_INDICATOR_TYPE


def test_reenrich_historical_no_known_threat_becomes_unknown(
    tenant_admin_client, monkeypatch
):
    """Router/DB: an observable persisted as no_known_threat/score 0 (historical)
    is re-scored to unknown/0 when a source returns NO MATCH. Confirmed both in
    the /enrich response and in a subsequent GET (live path, no data migration)."""
    client = tenant_admin_client
    created = client.post("/observables", json={"type": "ip", "value": "198.51.100.7"})
    assert created.status_code == 201, created.text
    obs_id = created.json()["id"]

    # Simulate a historical row written before the verdict fix.
    from app.database import SessionLocal
    from app.models import Observable

    db = SessionLocal()
    try:
        row = db.get(Observable, obs_id)
        row.verdict = "no_known_threat"
        row.score = 0
        db.add(row)
        db.commit()
    finally:
        db.close()

    # A source that actually runs and returns NO MATCH.
    _patch_urlhaus_return(monkeypatch, {"listed": False, "query_status": "no_results"})

    r = client.post(f"/observables/{obs_id}/enrich")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["verdict"] == "unknown", body
    assert body["score"] == 0, body

    got = client.get(f"/observables/{obs_id}")
    assert got.status_code == 200, got.text
    detail = got.json()
    assert detail["verdict"] == "unknown", detail
    assert detail["score"] == 0, detail


def test_urlhaus_hash_positive_factor_is_english():
    """Positive hash lookup stays 45 / suspicious AND the payload factor reason
    is fully in English (no leftover Portuguese)."""
    from app.scoring import compute_score

    score, verdict, factors = compute_score(
        {"urlhaus": {"listed": True, "file_type": "exe", "signature": "abc123"}}
    )
    assert (score, verdict) == (45, "suspicious"), (score, verdict, factors)
    payload = [f for f in factors if f["name"] == "urlhaus_payload"]
    assert payload, factors
    assert payload[0]["reason"] == (
        "Payload listed in URLhaus (file type: exe, signature: abc123)."
    ), payload[0]["reason"]


@pytest.mark.parametrize(
    "enrichments, expected_score, expected_verdict",
    [
        # URLhaus positive URL (listed + online): 45 + 10 = 55 / suspicious.
        (
            {"urlhaus": {"listed": True, "url_status": "online",
                         "threat": "malware_download", "tags": ["x"]}},
            55, "suspicious",
        ),
        # URLhaus positive host/IP association: 35 / low.
        (
            {"urlhaus": {"listed": True, "url_count": 3}},
            35, "low",
        ),
        # URLhaus positive payload hash: 45 / suspicious.
        (
            {"urlhaus": {"listed": True, "file_type": "exe", "signature": "X"}},
            45, "suspicious",
        ),
        # CVE with KEV + ransomware + EPSS: 50 + 10 + 30 = 90 / malicious.
        (
            {"cisa_kev": {"listed": True, "known_ransomware": "Known",
                          "date_added": "2021-12-10"},
             "epss": {"epss": 1.0, "percentile": 1.0}},
            90, "malicious",
        ),
    ],
)
def test_compute_score_preserves_positive_scoring(
    enrichments, expected_score, expected_verdict
):
    """Positive scoring must be preserved: a real malicious signal still yields
    a non-zero score, the expected verdict and explanatory factors."""
    from app.scoring import compute_score

    score, verdict, factors = compute_score(enrichments)
    assert (score, verdict) == (expected_score, expected_verdict), (
        enrichments, score, verdict, factors,
    )
    assert factors, (enrichments, factors)
