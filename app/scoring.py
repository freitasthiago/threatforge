"""Engine de scoring explicável.

Cada regra retorna fatores com pontos + justificativa. O score final é a
soma limitada a 0–100. Nada de nota mágica: todo ponto tem um porquê.
"""
from dataclasses import asdict, dataclass


@dataclass
class ScoreFactor:
    name: str
    points: int
    reason: str
    source: str


VERDICTS = [(70, "malicious"), (40, "suspicious"), (1, "low")]


def _lookup_executed(name: str, data: object) -> bool:
    """True only when a *recognized* connector presents explicit evidence that a
    lookup actually ran and returned a result.

    A skipped connector, ``None``, a non-dict, an empty dict, or an unrecognized
    result shape is NOT proof that a lookup occurred and must never let an
    observable be scored as ``no_known_threat``.
    """
    if not isinstance(data, dict):
        return False
    if data.get("skipped") is True:
        return False
    if name in ("cisa_kev", "urlhaus"):
        return isinstance(data.get("listed"), bool)
    if name == "epss":
        return data.get("epss") is not None
    return False


def compute_score(enrichments: dict[str, dict | None]) -> tuple[int, str, list[dict]]:
    """Recebe {nome_do_conector: dados} e devolve (score, verdict, fatores).

    Contrato:
    - ``unknown``          : nenhuma fonte reconhecida comprovou consulta executada;
    - ``no_known_threat``  : ao menos uma fonte reconhecida executou e retornou
                             resultado negativo explícito.
    """
    executed = {
        name: data
        for name, data in enrichments.items()
        if _lookup_executed(name, data)
    }
    if not executed:
        return 0, "unknown", []

    factors: list[ScoreFactor] = []

    kev = executed.get("cisa_kev")
    if kev and kev.get("listed"):
        factors.append(
            ScoreFactor(
                "kev_listed",
                50,
                f"CVE is listed in the CISA KEV catalog (confirmed active exploitation). "
                f"Added on {kev.get('date_added')}.",
                "CISA KEV",
            )
        )
        if (kev.get("known_ransomware") or "").lower() == "known":
            factors.append(
                ScoreFactor(
                    "kev_ransomware",
                    10,
                    "Known use in ransomware campaigns according to CISA.",
                    "CISA KEV",
                )
            )

    epss = executed.get("epss")
    if epss and epss.get("epss") is not None:
        prob = float(epss["epss"])
        pts = round(prob * 30)
        if pts > 0:
            factors.append(
                ScoreFactor(
                    "epss",
                    pts,
                    f"EPSS exploitation probability in 30 days: {prob:.1%} "
                    f"(percentil {float(epss.get('percentile', 0)):.1%}).",
                    "FIRST EPSS",
                )
            )

    uh = executed.get("urlhaus")
    if uh and uh.get("listed"):
        if "url_status" in uh:  # consulta por URL
            factors.append(
                ScoreFactor(
                    "urlhaus_url",
                    45,
                    f"URL listed in URLhaus (threat: {uh.get('threat') or 'N/A'}, "
                    f"tags: {', '.join(uh.get('tags') or []) or 'N/A'}).",
                    "abuse.ch URLhaus",
                )
            )
            if uh.get("url_status") == "online":
                factors.append(
                    ScoreFactor(
                        "urlhaus_online",
                        10,
                        "Malicious URL was still ONLINE at query time.",
                        "abuse.ch URLhaus",
                    )
                )
        elif "blacklists" in uh or "url_count" in uh and "file_type" not in uh:
            factors.append(
                ScoreFactor(
                    "urlhaus_host",
                    35,
                    f"Host associated with {uh.get('url_count', '?')} malware-distribution "
                    f"URL(s) in URLhaus.",
                    "abuse.ch URLhaus",
                )
            )
        if "file_type" in uh:
            factors.append(
                ScoreFactor(
                    "urlhaus_payload",
                    45,
                    f"Payload listed in URLhaus (file type: {uh.get('file_type')}, "
                    f"signature: {uh.get('signature') or 'N/A'}).",
                    "abuse.ch URLhaus",
                )
            )

    score = min(100, max(0, sum(f.points for f in factors)))
    verdict = "unknown"
    for threshold, name in VERDICTS:
        if score >= threshold:
            verdict = name
            break
    return score, verdict, [asdict(f) for f in factors]
