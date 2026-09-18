from pathlib import Path
import os
import re
from email import policy
from email.parser import Parser
from urllib.parse import urlparse, parse_qs
import json
from datetime import datetime, timezone
from fastapi.responses import JSONResponse
import joblib
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from .auth import User, Scan, get_db, current_user, make_token, hash_password, verify_password

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "spam_classifier.joblib"
app = FastAPI(title="MailGuard AI API", version="3.3.0")

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"detail":"Internal server error."})
ALLOWED_ORIGINS=[x.strip() for x in os.getenv("CORS_ORIGINS","http://localhost:5173").split(",") if x.strip()]
app.add_middleware(CORSMiddleware, allow_origins=ALLOWED_ORIGINS, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    return response
model = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None

class EmailRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=100000)

class BatchRequest(BaseModel):
    emails: list[str] = Field(..., min_length=1, max_length=500)

class RawEmailRequest(BaseModel):
    raw_email: str = Field(..., min_length=1, max_length=500000)

class URLRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)

class AuthRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    password: str = Field(..., min_length=8, max_length=256)

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

# --- Threat intelligence helpers ---
def _hostname(url: str):
    try:
        host = (urlparse(url).hostname or "").lower().rstrip(".")
        return host
    except Exception:
        return ""

def _is_ip_host(host: str):
    return bool(re.fullmatch(r"(?:\\d{1,3}\\.){3}\\d{1,3}", host))

def _is_punycode(host: str):
    return any(label.startswith("xn--") for label in host.split("."))

def _domain_age_signal(host: str):
    return {"status": "not_checked", "reason": "Live WHOIS/DNS intelligence provider not configured"}

def analyze_url_intelligence(url: str):
    host = _hostname(url)
    parsed = urlparse(url)
    signals=[]
    if parsed.scheme.lower() != "https": signals.append({"severity":"medium","type":"insecure_transport","detail":"URL does not use HTTPS"})
    if _is_ip_host(host): signals.append({"severity":"high","type":"ip_host","detail":"URL uses an IPv4 address instead of a domain"})
    if _is_punycode(host): signals.append({"severity":"high","type":"punycode","detail":"Hostname contains punycode, which can be used in homograph attacks"})
    if "@" in url: signals.append({"severity":"high","type":"credential_obfuscation","detail":"URL contains @ before the host boundary"})
    if len(url) > 180: signals.append({"severity":"medium","type":"long_url","detail":"Unusually long URL"})
    query_keys={k.lower() for k in parse_qs(parsed.query).keys()}
    if query_keys & {"token","password","passwd","otp","session"}: signals.append({"severity":"medium","type":"sensitive_query","detail":"Sensitive credential/session parameter present"})
    score=min(100,sum(28 if s["severity"]=="high" else 12 for s in signals))
    return {"url":url,"hostname":host,"risk_score":score,"risk_level":"high" if score>=70 else "medium" if score>=30 else "low","signals":signals,"domain_intelligence":_domain_age_signal(host)}

def analyze_url(url):
    raw=url.strip()
    try:
        p=urlparse(raw if re.match(r"^https?://",raw,re.I) else "http://"+raw)
        host=p.hostname or ""
        reasons=[]; score=0
        if p.scheme!="https": reasons.append("Not using HTTPS"); score+=20
        if "@" in (p.netloc or ""): reasons.append("Contains @ in URL authority"); score+=25
        if re.match(r"^\\d{1,3}(\\.\\d{1,3}){3}$",host): reasons.append("Uses an IP address"); score+=30
        if len(host.split("."))>4: reasons.append("Deep subdomain structure"); score+=15
        if len(raw)>180: reasons.append("Unusually long URL"); score+=10
        if any(x in host for x in ("bit.ly","tinyurl.com","t.co","goo.gl")): reasons.append("Known URL shortener"); score+=15
        qs=parse_qs(p.query)
        if any(k.lower() in ("token","password","passwd","otp","session") for k in qs): reasons.append("Sensitive-looking query parameter"); score+=20
        return {"url":raw,"hostname":host,"scheme":p.scheme,"risk_score":min(100,score),"risk_level":"high" if score>=60 else "medium" if score>=30 else "low","suspicious":bool(reasons),"reasons":reasons}
    except Exception:
        return {"url":raw,"hostname":"","scheme":"","risk_score":80,"risk_level":"high","suspicious":True,"reasons":["Invalid URL format"]}

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

def explain_prediction(text):
    if not model: return []
    try:
        features = model.named_steps["features"]
        classifier = model.named_steps["classifier"]
        transformed = features.transform([text])
        scores = transformed.toarray()[0] * classifier.coef_[0]
        if list(classifier.classes_).index("spam") == 0: scores = -scores
        ranked = sorted(zip(features.get_feature_names_out(), scores), key=lambda x:x[1], reverse=True)
        out=[]; seen=set()
        for token,score in ranked:
            token=token.replace("word__","").replace("char__","").strip()
            if not token or token.lower() in seen or abs(score)<0.01: continue
            seen.add(token.lower()); out.append({"term":token,"impact":round(float(score),4)})
            if len(out)>=8: break
        return out
    except Exception: return []

def classify(text, user_id=None, db=None):
    if not model: raise HTTPException(503, "Model not found. Run: python ml/train.py")
    prediction=model.predict([text])[0]
    probs=model.predict_proba([text])[0]
    probability_map={str(c):float(p) for c,p in zip(model.classes_,probs)}
    spam_probability=probability_map.get("spam",0.0)
    label="spam" if prediction=="spam" else "ham"
    urls=url_analysis(text); signals=risk_signals(text)
    if urls["suspicious_urls"]: signals.append("One or more URLs have suspicious characteristics")
    risk_score=min(100,round(spam_probability*100+min(25,len(signals)*4)))
    result={"prediction":label,"label":"SPAM" if label=="spam" else "NOT SPAM",
            "confidence":round(max(probability_map.values())*100,2),
            "spam_probability":round(spam_probability*100,2),
            "risk_level":"high" if risk_score>=75 else "medium" if risk_score>=40 else "low",
            "risk_score":risk_score,"risk_signals":signals,"url_analysis":urls,
            "explanation":explain_prediction(text)}
    if user_id and db:
        db.add(Scan(user_id=user_id,prediction=result["prediction"],risk_level=result["risk_level"],risk_score=result["risk_score"],spam_probability=result["spam_probability"],preview=text[:90].replace("\n"," "))); db.commit()
    return result

def parse_email(raw):
    msg=Parser(policy=policy.default).parsestr(raw)
    body=msg.get_body(preferencelist=("plain","html"))
    body_text=body.get_content() if body else ""
    auth=msg.get("Authentication-Results","")
    received=list(msg.get_all("Received",[]))
    return {
        "from":msg.get("From",""), "reply_to":msg.get("Reply-To",""),
        "return_path":msg.get("Return-Path",""), "subject":msg.get("Subject",""),
        "date":msg.get("Date",""), "message_id":msg.get("Message-ID",""),
        "received_hops":len(received),
        "authentication_results":auth,
        "authentication": {
            "spf":"pass" if re.search(r"spf\\s*=\\s*pass",auth,re.I) else "fail_or_unknown",
            "dkim":"pass" if re.search(r"dkim\\s*=\\s*pass",auth,re.I) else "fail_or_unknown",
            "dmarc":"pass" if re.search(r"dmarc\\s*=\\s*pass",auth,re.I) else "fail_or_unknown"
        },
        "body":body_text
    }

@app.post("/auth/register")
def register(request: AuthRequest, db=Depends(get_db)):
    email=request.email.strip().lower()
    if "@" not in email: raise HTTPException(400,"Enter a valid email.")
    if len(request.password)<8: raise HTTPException(400,"Password must be at least 8 characters.")
    if db.query(User).filter(User.email==email).first(): raise HTTPException(409,"Account already exists.")
    user=User(email=email,password_hash=hash_password(request.password)); db.add(user); db.commit(); db.refresh(user)
    return {"access_token":make_token(user),"token_type":"bearer","user":{"id":user.id,"email":user.email}}

@app.post("/auth/login")
def login(request: AuthRequest, db=Depends(get_db)):
    user=db.query(User).filter(User.email==request.email.strip().lower()).first()
    if not user or not verify_password(request.password,user.password_hash): raise HTTPException(401,"Invalid email or password.")
    return {"access_token":make_token(user),"token_type":"bearer","user":{"id":user.id,"email":user.email}}

@app.get("/auth/me")
def me(user: User=Depends(current_user)): return {"id":user.id,"email":user.email}

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    if not request.url.strip(): raise HTTPException(400,"URL cannot be empty.")
    return analyze_url_intelligence(request.url)

@app.get("/analytics")
def analytics(user: User=Depends(current_user), db=Depends(get_db)):
    scans=db.query(Scan).filter(Scan.user_id==user.id).order_by(Scan.id.desc()).all()
    total=len(scans); spam=sum(x.prediction=="spam" for x in scans)
    recent=[{"timestamp":x.timestamp.isoformat(),"prediction":x.prediction,"risk_level":x.risk_level,"risk_score":x.risk_score,"spam_probability":x.spam_probability,"preview":x.preview} for x in scans[:20]]
    return {"total_scanned":total,"spam_detected":spam,"ham_detected":total-spam,"spam_rate":round(spam/total*100,2) if total else 0,"high_risk":sum(x.risk_level=="high" for x in scans),"medium_risk":sum(x.risk_level=="medium" for x in scans),"recent":recent}

@app.get("/health")
def health(): return {"status":"ok","model_loaded":model is not None}

@app.get("/model-comparison")
def model_comparison():
    path = MODEL_PATH.parent / "comparison_metrics.json"
    if not path.exists():
        return {"status":"not_trained","message":"Run python ml/train.py to generate comparison metrics.","metrics":[]}
    data=json.loads(path.read_text())
    for m in data.get("metrics",[]):
        m["false_positive_rate_percent"]=round(m.get("false_positive_rate",0)*100,2)
        m["false_negative_rate_percent"]=round(m.get("false_negative_rate",0)*100,2)
    return data

@app.get("/evaluation-reports")
def evaluation_reports():
    reports={}
    for key, filename in {
        "sms_benchmark":"comparison_metrics.json",
        "spambase":"spambase_evaluation_report.json",
        "custom_email":"email_evaluation_report.json"
    }.items():
        path=MODEL_PATH.parent / filename
        if path.exists():
            reports[key]=json.loads(path.read_text())
    return {"reports":reports}

@app.get("/model-info")
def model_info(): return {"model":"Logistic Regression","features":"Word + character TF-IDF n-grams","dataset":"UCI SMS Spam Collection","api_version":app.version,"status":"loaded" if model else "not trained"}

@app.post("/predict")
def predict(request: EmailRequest,user: User=Depends(current_user),db=Depends(get_db)):
    if not request.text.strip(): raise HTTPException(400,"Email text cannot be empty.")
    return classify(request.text,user.id,db)

@app.post("/predict/batch")
def predict_batch(request: BatchRequest,user: User=Depends(current_user),db=Depends(get_db)):
    if not request.emails or len(request.emails)>500: raise HTTPException(400,"Provide between 1 and 500 emails.")
    return {"count":len(request.emails),"results":[classify(x,user.id,db) for x in request.emails]}

@app.post("/analyze/raw-email")
def analyze_raw_email(request: RawEmailRequest,user: User=Depends(current_user),db=Depends(get_db)):
    if not request.raw_email.strip(): raise HTTPException(400,"Raw email cannot be empty.")
    parsed=parse_email(request.raw_email)
    analysis=classify(parsed["body"] or request.raw_email,user.id,db)
    security=analyze_email_security(parsed, parsed["body"] or request.raw_email)
    return {"headers":{k:v for k,v in parsed.items() if k!="body"},"body_analysis":analysis,"email_security":security}


# Advanced email-security heuristics
from difflib import SequenceMatcher

FREE_EMAIL_DOMAINS = {"gmail.com","outlook.com","hotmail.com","yahoo.com","proton.me","protonmail.com"}

def _domain_from_address(value):
    if not value or "@" not in value:
        return None
    return value.rsplit("@",1)[-1].strip().lower().strip("<>")

def _registeredish_domain(hostname):
    parts=(hostname or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts)>=2 else (parts[0] if parts else "")

def _lookalike_score(a,b):
    if not a or not b or a==b:
        return 0.0
    return SequenceMatcher(None,a,b).ratio()

def detect_lookalike_domains(domain):
    if not domain:
        return []
    known = {
        "paypal.com":"PayPal", "microsoft.com":"Microsoft", "google.com":"Google",
        "apple.com":"Apple", "amazon.com":"Amazon", "facebook.com":"Facebook",
        "instagram.com":"Instagram", "linkedin.com":"LinkedIn"
    }
    root = domain.lower().strip(".")
    normalized = root.replace("0","o").replace("1","l").replace("3","e").replace("5","s")
    findings = []
    for target, brand in known.items():
        score = _lookalike_score(normalized, target)
        if root != target and (score >= 0.86 or normalized == target):
            findings.append({"brand":brand, "domain":root, "similarity":round(score,3),
                             "detail":f"Domain resembles {target} and may be impersonating it."})
    return findings

def analyze_email_security(headers, body):
    sender=headers.get("from")
    reply=headers.get("reply_to")
    sender_domain=_domain_from_address(sender)
    reply_domain=_domain_from_address(reply)
    signals=[]
    lookalikes=detect_lookalike_domains(sender_domain)
    for item in lookalikes:
        signals.append({"type":"lookalike_domain","severity":"high","detail":item["detail"],"brand":item["brand"],"similarity":item["similarity"]})
    if sender_domain and reply_domain and sender_domain != reply_domain:
        signals.append({"type":"reply_to_mismatch","severity":"high","detail":f"Reply-To domain {reply_domain} differs from sender domain {sender_domain}."})
    auth=headers.get("authentication_results","")
    for mechanism in ("spf","dkim","dmarc"):
        if auth and re.search(rf"\\b{mechanism}\\s*=\\s*fail\\b",auth,re.I):
            signals.append({"type":f"{mechanism}_fail","severity":"high","detail":f"{mechanism.upper()} authentication failed."})
    subject=(headers.get("subject") or "").lower()
    if re.search(r"verify|suspend|urgent|password|account|payment|invoice",subject):
        signals.append({"type":"phishing_subject","severity":"medium","detail":"Subject contains common account, payment, or urgency language."})
    urls=extract_urls(body)
    for url in urls:
        info=analyze_url(url)
        if info["suspicious"]:
            signals.append({"type":"suspicious_url","severity":"high","detail":info["reasons"][0] if info["reasons"] else "URL triggered security heuristics.","url":url})
    high=sum(1 for x in signals if x["severity"]=="high")
    medium=sum(1 for x in signals if x["severity"]=="medium")
    threat_score=min(100, high*28 + medium*12)
    return {"sender_domain":sender_domain,"reply_to_domain":reply_domain,"lookalike_domains":lookalikes,"signals":signals,
            "risk_signal_count":len(signals),"high_signals":high,"medium_signals":medium,
            "threat_score":threat_score,
            "security_risk":"high" if threat_score>=70 else ("medium" if threat_score>=30 else "low")}
