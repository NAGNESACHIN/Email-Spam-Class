import uuid

from fastapi.testclient import TestClient

from backend.auth import SessionLocal, Scan, User
from backend.main import app, analyze_url, detect_lookalike_domains

client = TestClient(app)

undefined

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
        assert any("HttpOnly" in value for value in logged_in.headers.getlist("set-cookie"))

        profile=isolated.get("/auth/me")
        assert profile.status_code == 200
        assert profile.json()["email"] == email

        logged_out=isolated.post("/auth/logout")
        assert logged_out.status_code == 200
        assert isolated.get("/auth/me").status_code == 401


def test_analytics_counts_without_loading_full_history():
    email=_unique_email()
    with TestClient(app) as isolated:
        assert isolated.post("/auth/register",json={"email":email,"password":"StrongPass123!"}).status_code == 200
        assert isolated.post("/auth/login",json={"email":email,"password":"StrongPass123!"}).status_code == 200

        with SessionLocal() as db:
            user=db.query(User).filter(User.email==email).first()
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
            return ["spam" if "free" in values[0].lower() else "ham" for _ in values]
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
            assert response.json()["count"] == 2

            with SessionLocal() as db:
                user=db.query(User).filter(User.email==email).first()
                count=db.query(Scan).filter(Scan.user_id==user.id).count()
                assert count == 2
    finally:
        backend_main.model=original
