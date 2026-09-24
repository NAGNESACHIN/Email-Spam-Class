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

def test_html_link_mismatch():
    from backend.main import analyze_html_links
    result = analyze_html_links('<a href="https://evil.example/login">https://paypal.com/login</a>')
    assert len(result["mismatches"]) == 1
    assert result["mismatches"][0]["destination_host"] == "evil.example"

def test_html_benign_link():
    from backend.main import analyze_html_links
    result = analyze_html_links('<a href="https://example.com/help">https://example.com/help</a>')
    assert result["mismatches"] == []

def test_attachment_risk_metadata():
    from email.parser import Parser
    from backend.main import analyze_attachments
    msg = Parser().parsestr('Content-Type: multipart/mixed; boundary="x"\n\n--x\nContent-Disposition: attachment; filename="invoice.exe"\nContent-Type: application/octet-stream\n\nMZ\n--x--')
    result = analyze_attachments(msg)
    assert result["count"] == 1
    assert any(s["type"] == "executable_attachment" for s in result["attachments"][0]["signals"])

def test_malformed_html_is_safe():
    from backend.main import analyze_html_links
    result = analyze_html_links('<a href="https://example.com"><b>broken')
    assert "mismatches" in result


def test_unified_threat_assessment_escalates_phishing_signals():
    from backend.main import build_unified_threat_assessment
    result = build_unified_threat_assessment(
        {"risk_score": 70},
        {
            "signals": [{"type": "reply_to_mismatch", "severity": "high", "detail": "Mismatch"}],
            "html_analysis": {
                "mismatches": [{"visible_host": "paypal.com", "destination_host": "evil.example"}],
                "ip_host_count": 0,
                "punycode_count": 0,
            },
            "attachment_analysis": {
                "attachments": [{"filename": "invoice.exe", "flags": ["dangerous executable/script extension"]}]
            },
        },
    )
    assert result["risk_level"] == "high"
    assert result["threat_score"] >= 75
    assert result["high_signals"] >= 3


def test_url_domain_intelligence_flags_disposable_domain():
    from backend.main import analyze_url_intelligence
    result = analyze_url_intelligence("https://mailinator.com/login")
    assert result["domain_intelligence"]["is_disposable"] is True
    assert any(s["type"] == "disposable_domain" for s in result["signals"])

def test_unicode_homoglyph_detection():
    from backend.main import analyze_url_intelligence
    result = analyze_url_intelligence("https://раypal.example/login")
    assert any(s["type"] == "unicode_homoglyph" for s in result["signals"])


def test_display_name_spoof_detection():
    from backend.main import analyze_email_security
    result = analyze_email_security({"from": "PayPal Security <alerts@evil.example>", "reply_to": "", "return_path": "", "authentication_results": "", "subject": "Account notice"}, "Please verify")
    assert any(s["type"] == "display_name_spoof" for s in result["signals"])

def test_return_path_mismatch_detection():
    from backend.main import analyze_email_security
    result = analyze_email_security({"from": "Billing <billing@example.com>", "reply_to": "", "return_path": "bounce@other.example", "authentication_results": "", "subject": ""}, "Invoice")
    assert any(s["type"] == "return_path_mismatch" for s in result["signals"])
