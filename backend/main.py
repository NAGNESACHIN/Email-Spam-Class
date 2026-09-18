from pathlib import Path
import re
import joblib
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "spam_classifier.joblib"

app = FastAPI(
    title="Email Spam Classification API",
    version="1.0.0",
    description="Explainable NLP-based email spam detection API."
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None


class EmailRequest(BaseModel):
    text: str


def extract_risk_signals(text: str) -> list[str]:
    signals = []
    lower = text.lower()

    if re.search(r"https?://|www\\.", text, re.I):
        signals.append("Contains one or more URLs")
    if re.search(r"\\b(password|otp|verify|verification|login|credential|account)\\b", lower):
        signals.append("Contains account or credential-related language")
    if re.search(r"\\b(urgent|immediately|act now|limited time|winner|congratulations)\\b", lower):
        signals.append("Contains urgency or promotional language")
    if re.search(r"\\b(prize|cash|free|offer|discount|loan|investment)\\b", lower):
        signals.append("Contains money, prize, or promotional terms")
    if len(re.findall(r"[!?]", text)) >= 3:
        signals.append("Uses unusually frequent punctuation")
    if len(text) > 1000:
        signals.append("Message is unusually long")

    return signals


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": model is not None}


@app.get("/model-info")
def model_info():
    return {
        "model": "Logistic Regression",
        "features": "TF-IDF word and character n-grams",
        "dataset": "UCI SMS Spam Collection",
        "status": "loaded" if model is not None else "not trained"
    }


@app.post("/predict")
def predict(request: EmailRequest):
    if not request.text.strip():
        return {"error": "Email text cannot be empty."}

    if model is None:
        return {"error": "Model not found. Run: python ml/train.py"}

    prediction = model.predict([request.text])[0]
    probabilities = model.predict_proba([request.text])[0]
    classes = list(model.classes_)
    probability_map = {str(c): float(p) for c, p in zip(classes, probabilities)}

    spam_probability = probability_map.get("spam", 0.0)
    label = "spam" if prediction == "spam" else "ham"

    return {
        "prediction": label,
        "label": "SPAM" if label == "spam" else "NOT SPAM",
        "confidence": round(max(probability_map.values()) * 100, 2),
        "spam_probability": round(spam_probability * 100, 2),
        "risk_level": (
            "high" if spam_probability >= 0.80
            else "medium" if spam_probability >= 0.50
            else "low"
        ),
        "risk_signals": extract_risk_signals(request.text)
    }
