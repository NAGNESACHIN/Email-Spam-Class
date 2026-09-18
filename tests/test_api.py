import pytest
from fastapi.testclient import TestClient

from backend.main import app, analyze_url, detect_lookalike_domains

client = TestClient(app)

def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert "status" in response.json()

def test_url_analysis_flags_plain_http():
    result = analyze_url("http://example.com/login")
    assert result["risk_score"] >= 20
    assert result["suspicious"] is True

def test_url_intelligence_detects_punycode():
    response = client.post("/analyze/url", json={"url": "https://xn--pple-43d.com/login"})
    assert response.status_code == 200
    assert any(s["type"] == "punycode" for s in response.json()["signals"])

def test_lookalike_detection():
    findings = detect_lookalike_domains("micros0ft.com")
    assert any(item["brand"] == "Microsoft" for item in findings)

def test_validation_rejects_empty_prediction():
    response = client.post("/predict", json={"text": ""})
    assert response.status_code in (401, 422)

def test_url_validation_rejects_empty_url():
    response = client.post("/analyze/url", json={"url": ""})
    assert response.status_code == 422
