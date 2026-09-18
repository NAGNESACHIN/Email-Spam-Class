from pathlib import Path
import re
from urllib.parse import urlparse
import joblib
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "spam_classifier.joblib"
app = FastAPI(title="MailGuard AI API", version="2.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None

class EmailRequest(BaseModel):
    text: str

class BatchRequest(BaseModel):
    emails: list[str]

def extract_urls(text):
    return re.findall(r"https?://[^\s<>]+|www\.[^\s<>]+", text, re.I)

def url_analysis(text):
    urls = extract_urls(text)
    suspicious = []
    for raw in urls:
        try:
            p = urlparse(raw if raw.startswith("http") else "http://" + raw)
            host = p.netloc.lower()
            reasons = []
            if p.scheme != "https": reasons.append("not using HTTPS")
            if "@" in host: reasons.append("contains @ in hostname")
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host): reasons.append("uses an IP address")
            if len(host.split(".")) > 4: reasons.append("unusually deep subdomain")
            if any(x in host for x in ("bit.ly", "tinyurl.com", "t.co", "goo.gl")): reasons.append("URL shortener")
            if reasons: suspicious.append({"url": raw, "reasons": reasons})
        except ValueError:
            suspicious.append({"url": raw, "reasons": ["invalid URL format"]})
    return {"url_count": len(urls), "suspicious_urls": suspicious}

def risk_signals(text):
    lower = text.lower()
    signals = []
    checks = [
        (r"https?://|www\.", "Contains one or more URLs", text),
        (r"\b(password|otp|verify|verification|login|credential|account)\b", "Contains account or credential-related language", lower),
        (r"\b(urgent|immediately|act now|limited time|winner|congratulations)\b", "Contains urgency or promotional language", lower),
        (r"\b(prize|cash|free|offer|discount|loan|investment)\b", "Contains money, prize, or promotional terms", lower)
    ]
    for pattern, message, value in checks:
        if re.search(pattern, value, re.I): signals.append(message)
    if len(re.findall(r"[!?]", text)) >= 3: signals.append("Uses unusually frequent punctuation")
    if len(text) > 1000: signals.append("Message is unusually long")
    return signals



def explain_prediction(text, label):
    """Return human-readable model evidence using Logistic Regression coefficients."""
    if not model:
        return []
    try:
        features = model.named_steps["features"]
        classifier = model.named_steps["classifier"]
        transformed = features.transform([text])
        feature_names = features.get_feature_names_out()
        scores = transformed.toarray()[0] * classifier.coef_[0]
        # Positive score pushes toward the second class; normalize for display.
        if list(classifier.classes_).index("spam") == 0:
            scores = -scores
        ranked = sorted(zip(feature_names, scores), key=lambda x: x[1], reverse=True)
        evidence = []
        seen = set()
        for token, score in ranked:
            token = token.replace("word__", "").replace("char__", "")
            token = token.strip()
            if not token or token.lower() in seen or abs(score) < 0.01:
                continue
            seen.add(token.lower())
            evidence.append({"term": token, "impact": round(float(score), 4)})
            if len(evidence) >= 8:
                break
        return evidence
    except Exception:
        return []
\ndef classify(text):
    if not model: raise HTTPException(503, "Model not found. Run: python ml/train.py")
    prediction = model.predict([text])[0]
    probs = model.predict_proba([text])[0]
    probability_map = {str(c): float(p) for c, p in zip(model.classes_, probs)}
    spam_probability = probability_map.get("spam", 0.0)
    label = "spam" if prediction == "spam" else "ham"
    urls = url_analysis(text)
    signals = risk_signals(text)
    explanation = explain_prediction(text, label)
    if urls["suspicious_urls"]: signals.append("One or more URLs have suspicious characteristics")
    risk_score = min(100, round(spam_probability * 100 + min(25, len(signals) * 4)))
    return {"prediction": label, "label": "SPAM" if label == "spam" else "NOT SPAM",
            "confidence": round(max(probability_map.values()) * 100, 2),
            "spam_probability": round(spam_probability * 100, 2),
            "risk_level": "high" if risk_score >= 75 else "medium" if risk_score >= 40 else "low",
            "risk_score": risk_score, "risk_signals": signals, "url_analysis": urls, "explanation": explanation}

@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}

@app.get("/model-info")
def model_info():
    return {"model": "Logistic Regression", "features": "Word + character TF-IDF n-grams",
            "dataset": "UCI SMS Spam Collection", "api_version": app.version,
            "status": "loaded" if model else "not trained"}

@app.post("/predict")
def predict(request: EmailRequest):
    if not request.text.strip(): raise HTTPException(400, "Email text cannot be empty.")
    return classify(request.text)

@app.post("/predict/batch")
def predict_batch(request: BatchRequest):
    if not request.emails or len(request.emails) > 500:
        raise HTTPException(400, "Provide between 1 and 500 emails.")
    return {"count": len(request.emails), "results": [classify(email) for email in request.emails]}
