"""Regression checks for the dashboard and original engine integration."""
import io
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def client(tmp_path, monkeypatch):
    from engine import store

    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "integration.db"))
    store.init()
    from app import app

    app.config.update(TESTING=True)
    return app.test_client()


def test_both_interfaces_load_their_own_assets(client):
    dashboard = client.get("/")
    advanced = client.get("/advanced")
    assert dashboard.status_code == advanced.status_code == 200
    assert b'/static/app.js' in dashboard.data
    assert b'/static/style.css' in dashboard.data
    assert b'/advanced' in dashboard.data
    assert b'/static/engine.js' in advanced.data
    assert b'/static/engine.css' in advanced.data
    for name in ("app.js", "style.css", "engine.js", "engine.css"):
        assert client.get("/static/" + name).status_code == 200


def test_health_exposes_real_engine_capabilities(client):
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json["ok"] is True
    assert {"safe_browsing", "virustotal", "urlscan"} <= response.json["intel"].keys()


def test_quick_url_scan_returns_engine_signals(client):
    response = client.post("/api/check/url?mode=quick", json={"url": "https://paypa1.com/login"})
    assert response.status_code == 200
    assert response.json["speed"] == "quick"
    assert response.json["label"] in {"suspicious", "malicious"}
    assert "typosquat" in {signal["id"] for signal in response.json["signals"]}


def test_dashboard_requests_full_verification_through_existing_route(client, monkeypatch):
    from engine import urlscan

    calls = []

    def analyze(url, do_preview=True):
        calls.append((url, do_preview))
        return {"score": 0, "label": "likely_safe", "facts": {"registrable_domain": "example.com"}}

    monkeypatch.setattr(urlscan, "analyze_full", analyze)
    response = client.post("/api/check/url?mode=full", json={"url": "https://example.com", "preview": False})
    assert response.status_code == 200
    assert calls == [("https://example.com", False)]
    assert response.json["cluster_hint"] == "example.com"


def test_sample_email_scan_saves_receipt(client):
    raw = client.get("/api/sample/bec_invoice").get_data(as_text=True)
    response = client.post("/api/check/email", json={"raw": raw})
    assert response.status_code == 200
    assert response.json["label"] == "malicious"
    receipt = client.get("/api/receipt/" + response.json["receipt_id"])
    assert receipt.status_code == 200
    assert receipt.json["verdict"]["score"] == response.json["score"]


def test_original_email_file_upload_still_works(client):
    raw = client.get("/api/sample/clean").data
    response = client.post("/api/check/email", data={"file": (io.BytesIO(raw), "clean.eml")})
    assert response.status_code == 200
    assert response.json["label"] != "malicious"


def test_reporting_and_campaign_views_share_engine_state(client):
    response = client.post("/api/report", json={"cluster_key": "integration", "score": 90, "verdict": "malicious"})
    assert response.status_code == 200
    assert client.get("/api/stats").json["reports"] == 1
    assert client.get("/api/clusters").json["clusters"][0]["cluster_key"] == "integration"
    assert client.get("/api/money-deterred").json["clusters_neutralised"] == 1


@pytest.mark.parametrize("endpoint", ["/api/check/url", "/api/check/email"])
def test_invalid_scan_input_returns_an_error(client, endpoint):
    response = client.post(endpoint, json={})
    assert response.status_code == 400
    assert "error" in response.json
