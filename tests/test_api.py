import uuid

from fastapi.testclient import TestClient

from backend.auth import SessionLocal, Scan, User, OAuthState
from backend.main import app, analyze_url, detect_lookalike_domains

client = TestClient(app)


def test_health():
    response = client.get("/health")
    assert response.status_code in (200,503)
    payload=response.json()
    assert payload["status"] in {"ok","degraded"}
    assert "model_loaded" in payload
    assert "database" in payload


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
    msg = Parser().parsestr(
        'Content-Type: multipart/mixed; boundary="x"\n\n'
        '--x\nContent-Disposition: attachment; filename="invoice.exe"\n'
        'Content-Type: application/octet-stream\n\nMZ\n--x--'
    )
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
    result = analyze_email_security(
        {"from": "PayPal Security <alerts@evil.example>", "reply_to": "", "return_path": "",
         "authentication_results": "", "subject": "Account notice"},
        "Please verify"
    )
    assert any(s["type"] == "display_name_spoof" for s in result["signals"])


def test_return_path_mismatch_detection():
    from backend.main import analyze_email_security
    result = analyze_email_security(
        {"from": "Billing <billing@example.com>", "reply_to": "",
         "return_path": "bounce@other.example", "authentication_results": "", "subject": ""},
        "Invoice"
    )
    assert any(s["type"] == "return_path_mismatch" for s in result["signals"])


def test_unified_assessment_includes_domain_signal_and_categories():
    from backend.main import build_unified_threat_assessment
    result = build_unified_threat_assessment(
        {"risk_score": 20},
        {"sender_domain": "mailinator.com","signals":[],"html_analysis":{},
         "attachment_analysis": {"attachments":[]}},
    )
    assert any(s["type"] == "disposable_domain" for s in result["signals"])
    assert all("category" in s for s in result["signals"])


def _unique_email():
    return f"test-{uuid.uuid4().hex}@example.com"


def test_email_auth_uses_http_only_cookie_session():
    email=_unique_email()
    with TestClient(app) as isolated:
        registered=isolated.post("/auth/register",json={"email":email,"password":"StrongPass123!"})
        assert registered.status_code == 200
        assert "access_token" not in registered.json()

        logged_in=isolated.post("/auth/login",json={"email":email,"password":"StrongPass123!"})
        assert logged_in.status_code == 200
        assert logged_in.json()["authenticated"] is True
        cookie=isolated.cookies.get("mailguard_session")
        assert cookie
        assert any("HttpOnly" in value for value in logged_in.headers.get_list("set-cookie"))

        profile=isolated.get("/auth/me")
        assert profile.status_code == 200
        assert profile.json()["email"] == email

        logged_out=isolated.post("/auth/logout")
        assert logged_out.status_code == 200
        assert isolated.get("/auth/me").status_code == 401


def test_analytics_uses_database_aggregation():
    email=_unique_email()
    with TestClient(app) as isolated:
        assert isolated.post("/auth/register",json={"email":email,"password":"StrongPass123!"}).status_code == 200
        assert isolated.post("/auth/login",json={"email":email,"password":"StrongPass123!"}).status_code == 200

        with SessionLocal() as db:
            user=db.query(User).filter(User.email==email).first()
            assert user is not None
            db.add_all([
                Scan(user_id=user.id,prediction="spam",risk_level="high",risk_score=90,spam_probability=95,preview="one"),
                Scan(user_id=user.id,prediction="ham",risk_level="low",risk_score=5,spam_probability=1,preview="two"),
                Scan(user_id=user.id,prediction="spam",risk_level="medium",risk_score=55,spam_probability=70,preview="three"),
            ])
            db.commit()

        data=isolated.get("/analytics")
        assert data.status_code == 200
        payload=data.json()
        assert payload["total_scanned"] == 3
        assert payload["spam_detected"] == 2
        assert payload["ham_detected"] == 1
        assert payload["high_risk"] == 1
        assert payload["medium_risk"] == 1
        assert len(payload["recent"]) == 3


def test_batch_prediction_persists_in_one_request():
    import backend.main as backend_main

    class StubModel:
        classes_=["ham","spam"]

        def predict(self, values):
            return ["spam" if "free" in value.lower() else "ham" for value in values]

        def predict_proba(self, values):
            return [[0.1,0.9] if "free" in value.lower() else [0.95,0.05] for value in values]

    original=backend_main.model
    backend_main.model=StubModel()
    email=_unique_email()
    try:
        with TestClient(app) as isolated:
            assert isolated.post("/auth/register",json={"email":email,"password":"StrongPass123!"}).status_code == 200
            assert isolated.post("/auth/login",json={"email":email,"password":"StrongPass123!"}).status_code == 200
            response=isolated.post("/predict/batch",json={"emails":["Free prize now","Team meeting tomorrow"]})
            assert response.status_code == 200
            payload=response.json()
            assert payload["count"] == 2
            assert [item["prediction"] for item in payload["results"]] == ["spam","ham"]

            with SessionLocal() as db:
                user=db.query(User).filter(User.email==email).first()
                count=db.query(Scan).filter(Scan.user_id==user.id).count()
                assert count == 2
    finally:
        backend_main.model=original


def test_oauth_pkce_pair_uses_s256_and_binds_to_verifier():
    from backend.main import _pkce_pair, _pkce_pair_from_verifier
    verifier, challenge = _pkce_pair()
    assert len(verifier) >= 43
    assert challenge == _pkce_pair_from_verifier(verifier)[1]
    assert len(challenge) == 43


def test_oauth_start_creates_browser_bound_transaction(monkeypatch):
    import backend.main as backend_main
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-google-client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-google-secret")
    monkeypatch.setattr(
        backend_main,
        "_oidc_metadata",
        lambda provider, cfg: {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        },
    )

    with TestClient(app) as isolated:
        response=isolated.get("/auth/google/start", follow_redirects=False)
        assert response.status_code == 302
        location=response.headers["location"]
        assert "code_challenge=" in location
        assert "code_challenge_method=S256" in location
        assert "state=" in location
        assert "nonce=" in location
        assert isolated.cookies.get("mailguard_oauth_tx")
        assert isolated.cookies.get("mailguard_oauth_pkce")
        assert isolated.cookies.get("mailguard_oauth_tx_nonce")

        from urllib.parse import parse_qs, urlparse
        params=parse_qs(urlparse(location).query)
        state=params["state"][0]

        with SessionLocal() as db:
            row=db.query(OAuthState).filter(OAuthState.state_hash==backend_main._sha256(state)).first()
            assert row is not None
            assert row.browser_binding_hash
            assert row.code_challenge
            assert row.nonce_hash
            assert row.redirect_uri == "https://email-spam-class.vercel.app/api/auth/google/callback"


def test_oauth_callback_consumes_state_and_rejects_replay(monkeypatch):
    import backend.main as backend_main
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "test-google-client")
    monkeypatch.setenv("GOOGLE_CLIENT_SECRET", "test-google-secret")
    monkeypatch.setattr(
        backend_main,
        "_oidc_metadata",
        lambda provider, cfg: {
            "issuer": "https://accounts.google.com",
            "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_endpoint": "https://oauth2.googleapis.com/token",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        },
    )

    with TestClient(app) as isolated:
        start=isolated.get("/auth/google/start", follow_redirects=False)
        from urllib.parse import parse_qs, urlparse
        state=parse_qs(urlparse(start.headers["location"]).query)["state"][0]

        denied=isolated.get(
            f"/auth/google/callback?error=access_denied&state={state}",
            follow_redirects=False,
        )
        assert denied.status_code == 303
        assert "oauth_error=provider_denied" in denied.headers["location"]

        replay=isolated.get(
            f"/auth/google/callback?error=access_denied&state={state}",
            follow_redirects=False,
        )
        assert replay.status_code == 303
        assert "oauth_error=invalid_or_expired_state" in replay.headers["location"]


def test_legacy_oauth_code_exchange_endpoint_is_removed():
    with TestClient(app) as isolated:
        response=isolated.post("/auth/oauth/exchange", json={"code":"x"*32})
        assert response.status_code == 404
