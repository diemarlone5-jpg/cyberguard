"""Tests de l'API CyberGuard.

Ils vérifient les propriétés de sécurité, pas seulement le « bon
fonctionnement » : en-têtes présents, entrée hostile neutralisée, mot de passe
en clair refusé, corps trop gros refusé, martèlement bloqué, et — point
important — l'API ne promet jamais plus qu'elle ne sait.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.config import Reglages
from app.main import creer_application
from app.pwned import FuiteIndisponible


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    reglages = Reglages(
        environnement="test",
        taille_max_corps=2048,
        requetes_par_minute=5,
    )
    application = creer_application(reglages)

    async def fausse_plage(prefixe: str) -> dict[str, int]:
        return {"0000000000000000000000000000000000a": 42}

    monkeypatch.setattr(
        "app.main.VerificateurFuite.plage", lambda self, prefixe: fausse_plage(prefixe)
    )
    return TestClient(application)


def test_entetes_securite_sur_la_page(client: TestClient) -> None:
    reponse = client.get("/")
    assert reponse.status_code == 200
    assert "script-src 'self'" in reponse.headers["content-security-policy"]
    assert reponse.headers["x-content-type-options"] == "nosniff"
    assert reponse.headers["x-frame-options"] == "DENY"
    assert reponse.headers["referrer-policy"] == "no-referrer"


def test_entetes_securite_sur_une_erreur(client: TestClient) -> None:
    """Un 404 doit porter les mêmes protections qu'une réponse normale."""
    reponse = client.get("/route-inexistante")
    assert reponse.status_code == 404
    assert "content-security-policy" in reponse.headers


def test_entree_hostile_refusee_et_jamais_renvoyee(client: TestClient) -> None:
    charge = "<img src=x onerror=alert(1)>@exemple.com"
    reponse = client.post("/api/breach", json={"email": charge})
    assert reponse.status_code == 422
    assert charge not in reponse.text
    assert "<img" not in reponse.text


def test_mot_de_passe_en_clair_refuse(client: TestClient) -> None:
    """L'API n'accepte aucune route qui prendrait un mot de passe complet."""
    reponse = client.post("/api/audit", json={"password": "MotDePasse123!"})
    assert reponse.status_code == 422
    assert "MotDePasse123!" not in reponse.text


def test_prefixe_invalide_refuse(client: TestClient) -> None:
    for mauvais in ("abc", "zzzzz", "abcde" * 10, "<script>"):
        reponse = client.post("/api/audit", json={"prefixe_sha1": mauvais})
        assert reponse.status_code == 422, mauvais


def test_audit_renvoie_la_famille_d_empreintes(client: TestClient) -> None:
    reponse = client.post("/api/audit", json={"prefixe_sha1": "ABCDE"})
    assert reponse.status_code == 200
    corps = reponse.json()
    assert corps["prefixe"] == "abcde"
    assert corps["total_empreintes"] == 1


def test_mot_de_passe_complet_absent_de_toute_reponse(client: TestClient) -> None:
    """Le mot de passe ne doit apparaître nulle part, même en cas d'erreur."""
    secret = "MonSuperSecret123!"
    for charge in ({"password": secret}, {"prefixe_sha1": secret}, {"email": secret}):
        reponse = client.post("/api/audit", json=charge)
        assert secret not in reponse.text


def test_corps_trop_volumineux_refuse(client: TestClient) -> None:
    reponse = client.post(
        "/api/audit",
        content=b"x" * 4096,
        headers={"Content-Type": "application/json"},
    )
    assert reponse.status_code == 413


def test_martelage_bloque(client: TestClient) -> None:
    codes = [client.get("/api/health").status_code for _ in range(3)]
    codes += [client.post("/api/audit", json={"prefixe_sha1": "abcde"}).status_code for _ in range(6)]
    assert 429 in codes, codes


def test_sante_declare_l_etat_reel(client: TestClient) -> None:
    corps = client.get("/api/health").json()
    assert corps["etat"] == "ok"
    assert corps["verification_fuite_mot_de_passe"] is True
    assert corps["verification_fuite_email"] is False


def test_email_refuse_quand_aucune_cle_configuree(client: TestClient) -> None:
    """Sans clé HIBP : refus explicite, jamais un faux « aucune fuite »."""
    reponse = client.post("/api/breach", json={"email": "personne@exemple.com"})
    assert reponse.status_code == 503
    assert "configuré" in reponse.json()["detail"]


def test_service_indisponible_est_annonce(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    async def en_panne(self, prefixe: str) -> dict[str, int]:
        raise FuiteIndisponible("test")

    monkeypatch.setattr("app.main.VerificateurFuite.plage", en_panne)
    reponse = client.post("/api/audit", json={"prefixe_sha1": "abcde"})
    assert reponse.status_code == 503


def test_documentation_fermee_en_production() -> None:
    application = creer_application(Reglages(environnement="production"))
    client = TestClient(application)
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_calcul_de_robustesse() -> None:
    from app.scoring import evaluer

    faible = evaluer("123456")
    assert faible.score == 0
    assert faible.faiblesses

    solide = evaluer("C0rrect-Horse-Battery!")
    assert solide.robuste is True
    assert solide.score == 4
