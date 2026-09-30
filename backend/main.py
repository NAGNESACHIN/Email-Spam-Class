from pathlib import Path
import os
import re
import hashlib
import secrets
from email import policy
from email.parser import Parser
from html.parser import HTMLParser
from urllib.parse import urlparse, parse_qs, urlencode, quote
import json
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import time
import logging
import base64
import urllib.request
from urllib.error import HTTPError, URLError
from fastapi.responses import JSONResponse, RedirectResponse
import joblib
import jwt
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sqlalchemy import case, func, text as sql_text
from .auth import User, Scan, OAuthIdentity, OAuthState, OAuthCode, SESSION_COOKIE_NAME, get_db, current_user, make_token, hash_password, verify_password, valid_email

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = os.getenv("ENVIRONMENT", "development").lower()
MODEL_PATH = ROOT / "models" / "spam_classifier.joblib"
app = FastAPI(title="MailGuard AI API", version="4.0.0")
_oauth_logger = logging.getLogger("mailguard.oauth")
_RATE_WINDOW_SECONDS=60
_RATE_LIMIT=60
_rate_hits=defaultdict(deque)
_AUTH_RATE_WINDOW_SECONDS=int(os.getenv("AUTH_RATE_WINDOW_SECONDS","300"))
_AUTH_RATE_LIMIT=int(os.getenv("AUTH_RATE_LIMIT","10"))
_auth_hits=defaultdict(deque)
REDIS_URL=os.getenv("REDIS_URL","").strip()
try:
    import redis as _redis
    REDIS_CLIENT=_redis.Redis.from_url(REDIS_URL,decode_responses=True) if REDIS_URL else None
except ImportError:
    REDIS_CLIENT=None


def _memory_rate_limit(store,key,window,limit):
    now=time.monotonic(); hits=store[key]
    while hits and now-hits[0] > window: hits.popleft()
    if len(hits) >= limit: return False
    hits.append(now)
    return True


def _shared_rate_limit(key,window,limit):
    if not REDIS_CLIENT:
        return None
    try:
        count=int(REDIS_CLIENT.incr(key))
        if count == 1:
            REDIS_CLIENT.expire(key,window)
        return count <= limit
    except Exception:
        return None


def _rate_limit(request: Request):
    client_ip=request.client.host if request.client else "unknown"
    forwarded=request.headers.get("x-forwarded-for","").split(",")[0].strip()
    key_ip=forwarded or client_ip
    shared=_shared_rate_limit(f"mailguard:rate:{key_ip}",_RATE_WINDOW_SECONDS,_RATE_LIMIT)
    return _memory_rate_limit(_rate_hits,key_ip,_RATE_WINDOW_SECONDS,_RATE_LIMIT) if shared is None else shared

@app.exception_handler(Exception)
async def unhandled_exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"detail":"Internal server error."})
_cors_default="http://localhost:5173"
ALLOWED_ORIGINS=[x.strip() for x in os.getenv("CORS_ORIGINS",_cors_default).split(",") if x.strip()]
CORS_ORIGIN_REGEX=os.getenv("CORS_ORIGIN_REGEX","").strip() or None
if ENVIRONMENT in {"production","prod"} and (not ALLOWED_ORIGINS or any(x=="*" for x in ALLOWED_ORIGINS)) and not CORS_ORIGIN_REGEX:
    raise RuntimeError("Production CORS configuration must explicitly list trusted origins or provide CORS_ORIGIN_REGEX.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _set_session_cookies(response, token):
    secure=ENVIRONMENT in {"production","prod"}
    response.set_cookie(
        SESSION_COOKIE_NAME, token, max_age=24*60*60, httponly=True,
        secure=secure, samesite="lax", path="/"
    )
    response.set_cookie(
        "mailguard_csrf", secrets.token_urlsafe(32), max_age=24*60*60,
        httponly=False, secure=secure, samesite="lax", path="/"
    )


def _clear_session_cookies(response):
    secure=ENVIRONMENT in {"production","prod"}
    response.set_cookie(
        SESSION_COOKIE_NAME, "", max_age=0, expires=0, httponly=True,
        secure=secure, samesite="lax", path="/"
    )
    response.set_cookie(
        "mailguard_csrf", "", max_age=0, expires=0, httponly=False,
        secure=secure, samesite="lax", path="/"
    )


def _validate_csrf(request: Request):
    if ENVIRONMENT not in {"production","prod"}:
        return True
    if request.method in {"GET","HEAD","OPTIONS"}:
        return True
    path=request.url.path
    if path in {"/auth/register","/auth/login","/auth/oauth/exchange"}:
        return True
    if request.cookies.get(SESSION_COOKIE_NAME):
        cookie_token=request.cookies.get("mailguard_csrf","")
        header_token=request.headers.get("X-CSRF-Token","")
        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token,header_token):
            return False
    return True


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if not _rate_limit(request):
        return JSONResponse(status_code=429,content={"detail":"Too many requests. Please try again later."})
    if not _validate_csrf(request):
        return JSONResponse(status_code=403,content={"detail":"CSRF validation failed."})
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:; font-src 'self' https://fonts.gstatic.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; connect-src 'self' https: http://localhost:8000; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
    if ENVIRONMENT in {"production","prod"}:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
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

class OAuthExchangeRequest(BaseModel):
    code: str = Field(..., min_length=16, max_length=256)

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
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))

def _is_punycode(host: str):
    return any(label.startswith("xn--") for label in host.split("."))

DISPOSABLE_EMAIL_DOMAINS = {"mailinator.com","10minutemail.com","guerrillamail.com","tempmail.com","yopmail.com","trashmail.com","getnada.com","sharklasers.com"}

def _is_disposable_domain(host: str):
    return (host or "").lower().strip(".") in DISPOSABLE_EMAIL_DOMAINS

def _homoglyph_signals(host: str):
    suspicious_chars=set("аｅіоѕԁɡһјӏոрԛсԝу")
    if any(ch in (host or "").lower() for ch in suspicious_chars):
        return [{"severity":"high","type":"unicode_homoglyph","detail":"Hostname contains Unicode characters commonly used in lookalike domains."}]
    return []

def _domain_intelligence(host: str):
    host=(host or "").lower().strip(".")
    if not host:
        return {"status":"invalid"}
    result={"status":"heuristic","hostname":host,"is_disposable":_is_disposable_domain(host),"is_free_email":host in FREE_EMAIL_DOMAINS,"registration":_domain_age_signal(host)}
    if result["is_disposable"]:
        result["signal"]={"severity":"medium","type":"disposable_domain","detail":"Domain is in the configured disposable-email domain list."}
    return result

def _domain_age_signal(host: str):
    """Fetch public registration metadata through RDAP when enabled.

    RDAP is used instead of WHOIS because it is the standardized registration
    data protocol for gTLDs. The lookup is opt-in and failures never block
    email analysis.
    """
    host=(host or "").lower().strip(".")
    if not host or _is_ip_host(host) or _is_punycode(host):
        return {"status":"not_checked","reason":"Domain is not eligible for the RDAP lookup."}
    if os.getenv("RDAP_LOOKUP_ENABLED","true").lower() not in {"1","true","yes","on"}:
        return {"status":"disabled"}
    try:
        request=urllib.request.Request(
            f"https://rdap.org/domain/{quote(host,safe='.-')}",
            headers={"Accept":"application/rdap+json","User-Agent":"MailGuard-AI/4.0"},
            method="GET",
        )
        with urllib.request.urlopen(request,timeout=4) as response:
            data=json.loads(response.read().decode("utf-8"))
        events=data.get("events",[])
        created=None
        updated=None
        for event in events:
            action=str(event.get("eventAction","")).lower()
            date=event.get("eventDate")
            if action=="registration" and date: created=date
            elif action=="last changed" and date: updated=date
        result={"status":"available","domain":data.get("ldhName") or host,
                "registrar":None,"created":created,"last_changed":updated}
        entities=data.get("entities",[])
        for entity in entities:
            if "registrar" in entity.get("roles",[]):
                result["registrar"]=(entity.get("vcardArray") or [None,[]])[1]
                break
        if created:
            try:
                created_dt=datetime.fromisoformat(created.replace("Z","+00:00"))
                age_days=max(0,(datetime.now(timezone.utc)-created_dt).days)
                result["age_days"]=age_days
                result["age_signal"]="new_domain" if age_days < 30 else ("recent_domain" if age_days < 180 else "established_domain")
            except Exception:
                pass
        return result
    except (HTTPError,URLError,TimeoutError,ValueError,json.JSONDecodeError):
        return {"status":"unavailable"}
    except Exception:
        return {"status":"unavailable"}

def virustotal_url_lookup(url: str):
    """Optionally enrich URL analysis with VirusTotal reputation data.

    The integration is disabled unless VIRUSTOTAL_API_KEY is configured, so
    local development and CI never require an external network call.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not api_key:
        return {"status": "not_configured"}
    try:
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        request = urllib.request.Request(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key, "Accept": "application/json"},
            method="GET",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            payload = json.loads(response.read().decode("utf-8"))
        stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        return {
            "status": "available",
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0)),
            "undetected": int(stats.get("undetected", 0)),
        }
    except Exception as exc:
        return {"status": "unavailable", "reason": type(exc).__name__}

def analyze_url_intelligence(url: str):
    host = _hostname(url)
    parsed = urlparse(url)
    signals=[]
    if parsed.scheme.lower() != "https": signals.append({"severity":"medium","type":"insecure_transport","detail":"URL does not use HTTPS"})
    if _is_ip_host(host): signals.append({"severity":"high","type":"ip_host","detail":"URL uses an IPv4 address instead of a domain"})
    if _is_punycode(host): signals.append({"severity":"high","type":"punycode","detail":"Hostname contains punycode, which can be used in homograph attacks"})
    signals.extend(_homoglyph_signals(host))
    domain_info=_domain_intelligence(host)
    if domain_info.get("signal"): signals.append(domain_info["signal"])
    if "@" in url: signals.append({"severity":"high","type":"credential_obfuscation","detail":"URL contains @ before the host boundary"})
    if len(url) > 180: signals.append({"severity":"medium","type":"long_url","detail":"Unusually long URL"})
    query_keys={k.lower() for k in parse_qs(parsed.query).keys()}
    if query_keys & {"token","password","passwd","otp","session"}: signals.append({"severity":"medium","type":"sensitive_query","detail":"Sensitive credential/session parameter present"})
    reputation=virustotal_url_lookup(url)
    if reputation.get("status") == "available":
        if reputation.get("malicious", 0) > 0:
            signals.append({"severity":"high","type":"external_reputation","detail":f"VirusTotal reports {reputation['malicious']} malicious engine result(s)."})
        elif reputation.get("suspicious", 0) > 0:
            signals.append({"severity":"medium","type":"external_reputation","detail":f"VirusTotal reports {reputation['suspicious']} suspicious engine result(s)."})
    score=min(100,sum(28 if s["severity"]=="high" else 12 for s in signals))
    return {"url":url,"hostname":host,"risk_score":score,"risk_level":"high" if score>=70 else "medium" if score>=30 else "low","signals":signals,"domain_intelligence":domain_info,"reputation":reputation}

def analyze_url(url):
    raw=url.strip()
    try:
        p=urlparse(raw if re.match(r"^https?://",raw,re.I) else "http://"+raw)
        host=p.hostname or ""
        reasons=[]; score=0
        if p.scheme!="https": reasons.append("Not using HTTPS"); score+=20
        if "@" in (p.netloc or ""): reasons.append("Contains @ in URL authority"); score+=25
        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$",host): reasons.append("Uses an IP address"); score+=30
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

def classify(text, user_id=None, db=None, persist=True):
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
    if user_id and db and persist:
        db.add(Scan(user_id=user_id,prediction=result["prediction"],risk_level=result["risk_level"],risk_score=result["risk_score"],spam_probability=result["spam_probability"],preview=text[:90].replace("\n"," ")))
        db.commit()
    return result


class _HTMLLinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links=[]
        self._current_href=None
        self._text=[]
    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            attrs=dict(attrs)
            self._current_href=attrs.get("href")
            self._text=[]
    def handle_data(self, data):
        if self._current_href is not None:
            self._text.append(data)
    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href is not None:
            self.links.append({"text":" ".join("".join(self._text).split()),"href":self._current_href})
            self._current_href=None
            self._text=[]

def analyze_html_links(html):
    parser=_HTMLLinkParser()
    try:
        parser.feed(html or "")
        parser.close()
    except Exception:
        return {"link_count":0,"mismatches":[],"suspicious_links":[],"parse_error":True}
    mismatches=[]; suspicious=[]
    for link in parser.links:
        href=(link.get("href") or "").strip()
        text=(link.get("text") or "").strip()
        if not href or not re.match(r"^https?://",href,re.I):
            continue
        destination=_hostname(href)
        visible_match=re.search(r"(?:https?://)?(?:www\.)?([^/\s]+)",text,re.I)
        visible_host=(visible_match.group(1).lower().rstrip(".") if visible_match else "")
        if visible_host and destination and visible_host != destination:
            mismatches.append({"text":text,"href":href,"visible_host":visible_host,"destination_host":destination})
        if "@" in href or _is_ip_host(destination) or _is_punycode(destination):
            suspicious.append({"text":text,"href":href,"destination_host":destination})
    ip_host_count=sum(1 for item in suspicious if _is_ip_host(item.get("destination_host","")))
    punycode_count=sum(1 for item in suspicious if _is_punycode(item.get("destination_host","")))
    return {"link_count":len(parser.links),"mismatches":mismatches,"suspicious_links":suspicious,
            "ip_host_count":ip_host_count,"punycode_count":punycode_count,"parse_error":False}

DANGEROUS_ATTACHMENT_EXTENSIONS={"exe","scr","bat","cmd","com","js","jse","vbs","vbe","wsf","wsh","msi","jar","hta","ps1","dll","iso","img"}
MACRO_ATTACHMENT_EXTENSIONS={"docm","xlsm","pptm","xlam","dotm","xltm"}
ARCHIVE_ATTACHMENT_EXTENSIONS={"zip","rar","7z","iso","img"}

def analyze_attachments(msg):
    attachments=[]
    for part in msg.walk():
        filename=part.get_filename()
        if not filename:
            continue
        payload=part.get_payload(decode=True)
        size=len(payload) if payload is not None else 0
        extension=filename.rsplit(".",1)[-1].lower() if "." in filename else ""
        signals=[]
        lower_name=filename.lower()
        if extension in DANGEROUS_ATTACHMENT_EXTENSIONS:
            signals.append({"severity":"high","type":"executable_attachment","detail":"Attachment uses an executable or script-capable extension."})
        if extension in MACRO_ATTACHMENT_EXTENSIONS:
            signals.append({"severity":"high","type":"macro_attachment","detail":"Attachment can contain Office macros."})
        if extension in ARCHIVE_ATTACHMENT_EXTENSIONS:
            signals.append({"severity":"medium","type":"archive_attachment","detail":"Archive or disk-image attachment can conceal nested payloads."})
        if re.search(r"\.(?:exe|scr|bat|cmd|com|js|jse|vbs|vbe|wsf|wsh|msi|jar|hta|ps1)\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png)$",lower_name):
            signals.append({"severity":"high","type":"double_extension","detail":"Filename contains a dangerous extension before a benign-looking extension."})
        declared=(part.get_content_type() or "").lower()
        if extension in DANGEROUS_ATTACHMENT_EXTENSIONS and declared in {"application/pdf","text/plain","image/jpeg","image/png","application/zip"}:
            signals.append({"severity":"high","type":"attachment_type_mismatch","detail":"Attachment filename extension conflicts with its declared MIME type."})
        if size > 10*1024*1024:
            signals.append({"severity":"medium","type":"oversized_attachment","detail":"Attachment exceeds 10 MB."})
        flags=[item["detail"] for item in signals]
        attachments.append({"filename":filename,"content_type":part.get_content_type(),"extension":extension,
                            "size_bytes":size,"signals":signals,"flags":flags})
    return {"count":len(attachments),"attachments":attachments}

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
            "spf":"pass" if re.search(r"spf\s*=\s*pass",auth,re.I) else "fail_or_unknown",
            "dkim":"pass" if re.search(r"dkim\s*=\s*pass",auth,re.I) else "fail_or_unknown",
            "dmarc":"pass" if re.search(r"dmarc\s*=\s*pass",auth,re.I) else "fail_or_unknown"
        },
        "body":body_text,
        "html_body": (msg.get_body(preferencelist=("html",)).get_content() if msg.get_body(preferencelist=("html",)) else ""),
        "attachments": analyze_attachments(msg)
    }

def _auth_rate_limit(request: Request, email: str):
    client_ip=request.client.host if request.client else "unknown"
    forwarded=request.headers.get("x-forwarded-for","").split(",")[0].strip()
    ip=forwarded or client_ip
    normalized=email.strip().lower()
    email_key=_sha256(normalized)
    keys=(f"ip:{ip}",f"email:{email_key}")
    decisions=[]
    for key in keys:
        shared=_shared_rate_limit(f"mailguard:auth:{key}",_AUTH_RATE_WINDOW_SECONDS,_AUTH_RATE_LIMIT)
        decisions.append((key,shared))
    for key,shared in decisions:
        if shared is None and not _memory_rate_limit(_auth_hits,key,_AUTH_RATE_WINDOW_SECONDS,_AUTH_RATE_LIMIT):
            raise HTTPException(429,"Too many authentication attempts. Please try again later.")
        if shared is False:
            raise HTTPException(429,"Too many authentication attempts. Please try again later.")

# --- OAuth / SSO ---------------------------------------------------------
OAUTH_FRONTEND_URL=os.getenv("FRONTEND_URL","https://email-spam-class.vercel.app").rstrip("/")
_OAUTH_TX_COOKIE="__Host-mailguard_oauth_tx" if ENVIRONMENT in {"production","prod"} else "mailguard_oauth_tx"
_OAUTH_PKCE_COOKIE="__Host-mailguard_oauth_pkce" if ENVIRONMENT in {"production","prod"} else "mailguard_oauth_pkce"
_OAUTH_NONCE_COOKIE=_OAUTH_TX_COOKIE+"_nonce"
_OIDC_METADATA_CACHE={}
_OIDC_JWKS_CACHE={}
_OIDC_CACHE_TTL=3600

def _oauth_config(provider):
    provider=provider.lower()
    if provider != "google":
        return None
    return {
        "client_id":os.getenv("GOOGLE_CLIENT_ID","").strip(),
        "client_secret":os.getenv("GOOGLE_CLIENT_SECRET","").strip(),
        "redirect_uri":os.getenv("GOOGLE_REDIRECT_URI",f"{OAUTH_FRONTEND_URL}/api/auth/google/callback").strip(),
        "discovery":"https://accounts.google.com/.well-known/openid-configuration",
        "expected_issuer":"https://accounts.google.com",
        "scope":"openid email profile",
        "pkce":True,
    }

def _sha256(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()

def _oauth_now():
    return datetime.now(timezone.utc).replace(tzinfo=None)

def _oauth_enabled(provider):
    cfg=_oauth_config(provider)
    return bool(cfg and cfg.get("client_id") and cfg.get("client_secret"))

def _oauth_redirect_error(provider,message):
    safe_messages={
        "provider_not_configured","provider_denied","missing_oauth_response",
        "invalid_or_expired_state","invalid_oauth_transaction",
        "provider_authentication_failed","provider_did_not_return_a_valid_email",
        "provider_email_is_not_verified","linked_account_not_found",
        "account_already_exists","identity_issuer_mismatch","unsupported_id_token",
    }
    safe=message if message in safe_messages else "provider_authentication_failed"
    response=RedirectResponse(
        f"{OAUTH_FRONTEND_URL}?"+urlencode({"oauth_error":safe,"provider":provider}),
        status_code=303
    )
    response.headers["Cache-Control"]="no-store"
    return response

def _oauth_clear_transaction_cookies(response):
    secure=ENVIRONMENT in {"production","prod"}
    for name in (_OAUTH_TX_COOKIE,_OAUTH_PKCE_COOKIE,_OAUTH_NONCE_COOKIE):
        response.set_cookie(name,"",max_age=0,expires=0,httponly=True,
                            secure=secure,samesite="lax",path="/")

def _oauth_set_transaction_cookies(response,tx,verifier,nonce):
    secure=ENVIRONMENT in {"production","prod"}
    for name,value in (
        (_OAUTH_TX_COOKIE,tx),
        (_OAUTH_PKCE_COOKIE,verifier),
        (_OAUTH_NONCE_COOKIE,nonce),
    ):
        response.set_cookie(name,value,max_age=10*60,httponly=True,
                            secure=secure,samesite="lax",path="/")

def _pkce_pair():
    verifier=base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode("ascii")
    challenge=base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    return verifier,challenge

def _oauth_json(url,timeout=8):
    parsed=urlparse(url)
    if parsed.scheme!="https" or not parsed.netloc:
        raise ValueError("Only HTTPS OIDC endpoints are allowed.")
    request=urllib.request.Request(
        url,
        headers={"Accept":"application/json","User-Agent":"MailGuard-AI/5.0"},
        method="GET",
    )
    with urllib.request.urlopen(request,timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))

def _oidc_metadata(provider,cfg,force=False):
    cached=_OIDC_METADATA_CACHE.get(provider)
    if cached and not force and time.monotonic()-cached["at"] < _OIDC_CACHE_TTL:
        return cached["data"]
    metadata=_oauth_json(cfg["discovery"])
    required=("issuer","authorization_endpoint","token_endpoint","jwks_uri")
    if any(not metadata.get(key) for key in required):
        raise ValueError("OIDC provider metadata is incomplete.")
    for key in ("issuer","authorization_endpoint","token_endpoint","jwks_uri"):
        parsed=urlparse(str(metadata[key]))
        if parsed.scheme!="https" or not parsed.netloc:
            raise ValueError("OIDC metadata contains an insecure endpoint.")
    if provider=="google" and metadata["issuer"]!=cfg["expected_issuer"]:
        raise ValueError("OIDC issuer metadata mismatch.")
    if provider=="microsoft" and cfg.get("expected_issuer") and metadata["issuer"]!=cfg["expected_issuer"]:
        raise ValueError("Microsoft issuer metadata mismatch.")
    _OIDC_METADATA_CACHE[provider]={"at":time.monotonic(),"data":metadata}
    return metadata

def _oidc_jwks(provider,metadata,force=False):
    cached=_OIDC_JWKS_CACHE.get(provider)
    if cached and not force and time.monotonic()-cached["at"] < _OIDC_CACHE_TTL:
        return cached["data"]
    jwks=_oauth_json(metadata["jwks_uri"])
    if not isinstance(jwks.get("keys"),list):
        raise ValueError("OIDC JWKS response is invalid.")
    _OIDC_JWKS_CACHE[provider]={"at":time.monotonic(),"data":jwks}
    return jwks

def _oidc_signing_key(provider,metadata,kid):
    jwks=_oidc_jwks(provider,metadata)
    key=next((item for item in jwks["keys"] if item.get("kid")==kid),None)
    if key is None:
        jwks=_oidc_jwks(provider,metadata,force=True)
        key=next((item for item in jwks["keys"] if item.get("kid")==kid),None)
    if not key or key.get("kty")!="RSA":
        raise ValueError("OIDC signing key is unavailable.")
    return jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))

def _validate_id_token(provider,id_token,cfg,metadata,expected_nonce):
    if not id_token or not isinstance(id_token,str):
        raise ValueError("Provider did not return an ID token.")
    try:
        header=jwt.get_unverified_header(id_token)
    except Exception as exc:
        raise ValueError("Invalid ID token header.") from exc
    if header.get("alg")!="RS256" or not header.get("kid"):
        raise ValueError("Unsupported ID token signing algorithm.")
    key=_oidc_signing_key(provider,metadata,header["kid"])
    try:
        preliminary=jwt.decode(
            id_token,key,algorithms=["RS256"],
            options={
                "verify_aud":False,
                "verify_iss":False,
                "require":["exp","iat","iss","sub","aud"],
            },
            leeway=60,
        )
        expected_issuer=cfg["expected_issuer"]
        claims=jwt.decode(
            id_token,key,algorithms=["RS256"],
            audience=cfg["client_id"],
            issuer=expected_issuer,
            leeway=60,
            options={"require":["exp","iat","iss","sub","aud"]}
        )
    except jwt.PyJWTError as exc:
        raise ValueError("ID token validation failed.") from exc
    except Exception as exc:
        raise ValueError("ID token validation failed.") from exc

    aud=claims.get("aud")
    aud_list=aud if isinstance(aud,list) else [aud]
    if cfg["client_id"] not in aud_list:
        raise ValueError("ID token audience mismatch.")
    if claims.get("azp") is not None and claims.get("azp")!=cfg["client_id"]:
        raise ValueError("ID token authorized-party mismatch.")
    nonce=str(claims.get("nonce") or "")
    if not nonce or not expected_nonce or not secrets.compare_digest(nonce,expected_nonce):
        raise ValueError("ID token nonce mismatch.")
    try:
        iat=float(claims["iat"])
    except (TypeError,ValueError):
        raise ValueError("ID token issued-at timestamp is invalid.")
    if iat > datetime.now(timezone.utc).timestamp()+60:
        raise ValueError("ID token issued-at timestamp is in the future.")
    return claims

def _oauth_userinfo(access_token,metadata):
    endpoint=metadata.get("userinfo_endpoint")
    if not endpoint:
        return {}
    request=urllib.request.Request(
        endpoint,
        headers={
            "Authorization":f"Bearer {access_token}",
            "Accept":"application/json",
            "User-Agent":"MailGuard-AI/5.0",
        },
        method="GET"
    )
    with urllib.request.urlopen(request,timeout=10) as response:
        payload=json.loads(response.read().decode("utf-8"))
    return payload if isinstance(payload,dict) else {}

def _oauth_token_exchange(code,cfg,metadata,code_verifier=None):
    payload={
        "code":code,
        "client_id":cfg["client_id"],
        "client_secret":cfg["client_secret"],
        "redirect_uri":cfg["redirect_uri"],
        "grant_type":"authorization_code",
    }
    if cfg.get("pkce"):
        if not code_verifier:
            raise ValueError("PKCE verifier missing.")
        payload["code_verifier"]=code_verifier
    request=urllib.request.Request(
        metadata["token_endpoint"],
        data=urlencode(payload).encode("utf-8"),
        headers={
            "Content-Type":"application/x-www-form-urlencoded",
            "Accept":"application/json",
            "User-Agent":"MailGuard-AI/5.0",
        },
        method="POST"
    )
    with urllib.request.urlopen(request,timeout=10) as response:
        data=json.loads(response.read().decode("utf-8"))
    if not isinstance(data,dict) or not data.get("access_token") or not data.get("id_token"):
        raise ValueError("Provider did not return the required tokens.")
    return data

def _oauth_error_response(provider,message):
    response=_oauth_redirect_error(provider,message)
    _oauth_clear_transaction_cookies(response)
    return response

def _oauth_start(provider,db):
    provider=provider.lower()
    cfg=_oauth_config(provider)
    if not cfg:
        raise HTTPException(404,"Unsupported sign-in provider.")
    if not _oauth_enabled(provider):
        return _oauth_redirect_error(provider,"provider_not_configured")
    try:
        metadata=_oidc_metadata(provider,cfg)
    except Exception:
        return _oauth_redirect_error(provider,"provider_authentication_failed")

    state=secrets.token_urlsafe(32)
    tx=secrets.token_urlsafe(32)
    nonce=secrets.token_urlsafe(32)
    verifier,challenge=_pkce_pair()
    state_row=OAuthState(
        provider=provider,
        state_hash=_sha256(state),
        browser_binding_hash=_sha256(tx),
        code_challenge=challenge,
        nonce_hash=_sha256(nonce),
        redirect_uri=cfg["redirect_uri"],
        expires_at=_oauth_now()+timedelta(minutes=10),
    )
    db.add(state_row)
    db.commit()

    params={
        "client_id":cfg["client_id"],
        "redirect_uri":cfg["redirect_uri"],
        "response_type":"code",
        "scope":cfg["scope"],
        "state":state,
        "nonce":nonce,
    }
    if cfg.get("pkce"):
        params["code_challenge"]=challenge
        params["code_challenge_method"]="S256"
    if provider=="google":
        params["access_type"]="online"
        params["prompt"]="select_account"

    response=RedirectResponse(metadata["authorization_endpoint"]+"?"+urlencode(params),status_code=302)
    _oauth_set_transaction_cookies(response,tx,verifier,nonce)
    response.headers["Cache-Control"]="no-store"
    return response

def _oauth_consume_state(provider,state,request,db):
    state=state.strip()
    if not state or len(state)>512:
        return None,"invalid_oauth_transaction"
    row=db.query(OAuthState).filter(
        OAuthState.provider==provider,
        OAuthState.state_hash==_sha256(state),
        OAuthState.consumed_at==None,
    ).first()
    if not row or row.expires_at < _oauth_now():
        if row:
            row.consumed_at=_oauth_now()
            db.commit()
        return None,"invalid_or_expired_state"

    tx=request.cookies.get(_OAUTH_TX_COOKIE,"")
    verifier=request.cookies.get(_OAUTH_PKCE_COOKIE,"")
    if not tx or not verifier or not row.browser_binding_hash:
        return None,"invalid_oauth_transaction"
    if not secrets.compare_digest(_sha256(tx),row.browser_binding_hash):
        return None,"invalid_oauth_transaction"

    cfg=_oauth_config(provider)
    if not cfg or row.redirect_uri != cfg["redirect_uri"]:
        return None,"invalid_oauth_transaction"
    if cfg.get("pkce"):
        _,challenge=_pkce_pair_from_verifier(verifier)
        if not row.code_challenge or not secrets.compare_digest(challenge,row.code_challenge):
            return None,"invalid_oauth_transaction"

    nonce=request.cookies.get(_OAUTH_NONCE_COOKIE,"")
    if not nonce or not row.nonce_hash or not secrets.compare_digest(_sha256(nonce),row.nonce_hash):
        return None,"invalid_oauth_transaction"

    row.consumed_at=_oauth_now()
    db.commit()
    return {"row":row,"verifier":verifier,"nonce":nonce},""

def _pkce_pair_from_verifier(verifier):
    return verifier,base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")

def _oauth_complete(provider,code,state,request,db):
    cfg=_oauth_config(provider)
    if not cfg or not _oauth_enabled(provider):
        return _oauth_redirect_error(provider,"provider_not_configured")
    stage="metadata"
    try:
        metadata=_oidc_metadata(provider,cfg)
        stage="state"
        transaction,error=_oauth_consume_state(provider,state,request,db)
        if error:
            return _oauth_error_response(provider,error)

        if request.query_params.get("error"):
            return _oauth_error_response(provider,"provider_denied")
        if not code:
            return _oauth_error_response(provider,"missing_oauth_response")

        row=transaction["row"]
        verifier=transaction["verifier"]
        nonce=transaction["nonce"]
        stage="token_exchange"
        token_data=_oauth_token_exchange(code,cfg,metadata,verifier)
        stage="id_token_validation"
        claims=_validate_id_token(provider,token_data["id_token"],cfg,metadata,nonce)

        userinfo={}
        try:
            userinfo=_oauth_userinfo(token_data["access_token"],metadata)
        except (HTTPError,URLError,ValueError,json.JSONDecodeError):
            userinfo={}

        id_subject=str(claims.get("sub") or "").strip()
        info_subject=str(userinfo.get("sub") or "").strip()
        if info_subject and info_subject != id_subject:
            return _oauth_error_response(provider,"provider_authentication_failed")

        email=str(
            claims.get("email")
            or claims.get("preferred_username")
            or userinfo.get("email")
            or userinfo.get("preferred_username")
            or ""
        ).strip().lower()

        verified_values=[claims.get("email_verified"),userinfo.get("email_verified")]
        verified=any(value is True or str(value).lower()=="true" for value in verified_values)
        if provider=="google" and not verified:
            return _oauth_error_response(provider,"provider_email_is_not_verified")
        if not email or not id_subject or not valid_email(email):
            return _oauth_error_response(provider,"provider_did_not_return_a_valid_email")

        issuer=str(claims.get("iss") or "").strip()
        tenant_id=str(claims.get("tid") or "").strip() or None
        identity=db.query(OAuthIdentity).filter(
            OAuthIdentity.provider==provider,
            OAuthIdentity.issuer==issuer,
            OAuthIdentity.subject==id_subject,
        ).first()

        if not identity:
            legacy=db.query(OAuthIdentity).filter(
                OAuthIdentity.provider==provider,
                OAuthIdentity.subject==id_subject,
            ).first()
            if legacy:
                if legacy.issuer not in (None,"",issuer):
                    return _oauth_error_response(provider,"identity_issuer_mismatch")
                legacy.issuer=issuer
                legacy.tenant_id=tenant_id
                legacy.email=email
                identity=legacy
                db.commit()

        if identity:
            user=db.get(User,identity.user_id)
            if not user:
                return _oauth_error_response(provider,"linked_account_not_found")
            identity.email=email
            identity.issuer=issuer
            identity.tenant_id=tenant_id
            db.commit()
        else:
            user=db.query(User).filter(User.email==email).first()
            if user:
                return _oauth_error_response(provider,"account_already_exists")
            user=User(email=email,password_hash=hash_password(secrets.token_urlsafe(32)))
            db.add(user)
            db.flush()
            identity=OAuthIdentity(
                provider=provider,
                issuer=issuer,
                subject=id_subject,
                tenant_id=tenant_id,
                email=email,
                user_id=user.id,
            )
            db.add(identity)
            db.commit()

        # The OAuth callback is reached through the Vercel /api rewrite. Do not
        # rely on the callback response's session Set-Cookie surviving that proxy.
        # Instead issue a short-lived, one-time exchange code that the frontend
        # redeems on the same Vercel /api origin.
        exchange_code=secrets.token_urlsafe(48)
        db.add(OAuthCode(
            code_hash=_sha256(exchange_code),
            user_id=user.id,
            expires_at=_oauth_now()+timedelta(minutes=2),
        ))
        db.commit()
        response=RedirectResponse(
            f"{OAUTH_FRONTEND_URL}?" + urlencode({"oauth_code":exchange_code}) + "#details",
            status_code=303,
        )
        _oauth_clear_transaction_cookies(response)
        response.headers["Cache-Control"]="no-store"
        return response
    except (HTTPError,URLError,ValueError,json.JSONDecodeError,jwt.PyJWTError) as exc:
        status=getattr(exc,"code",None) if isinstance(exc,HTTPError) else None
        _oauth_logger.warning(
            "OAuth callback failed provider=%s stage=%s error_type=%s http_status=%s",
            provider,stage,type(exc).__name__,status
        )
        return _oauth_error_response(provider,"provider_authentication_failed")

@app.get("/auth/{provider}/start")
def oauth_start(provider: str,db=Depends(get_db)):
    return _oauth_start(provider,db)

@app.get("/auth/{provider}/callback")
def oauth_callback(provider: str,request: Request,db=Depends(get_db)):
    provider=provider.lower()
    if provider != "google":
        raise HTTPException(404,"Unsupported sign-in provider.")
    state=request.query_params.get("state","")
    if not state:
        return _oauth_error_response(provider,"invalid_or_expired_state")
    return _oauth_complete(provider,request.query_params.get("code",""),state,request,db)

@app.post("/auth/oauth/exchange")
def oauth_exchange(request: OAuthExchangeRequest, db=Depends(get_db)):
    code=request.code.strip()
    row=db.query(OAuthCode).filter(
        OAuthCode.code_hash==_sha256(code),
        OAuthCode.consumed_at==None,
    ).with_for_update().first()
    if not row or row.expires_at < _oauth_now():
        if row:
            row.consumed_at=_oauth_now()
            db.commit()
        raise HTTPException(400,"Invalid or expired OAuth exchange code.")

    user=db.get(User,row.user_id)
    if not user:
        row.consumed_at=_oauth_now()
        db.commit()
        raise HTTPException(400,"Linked account not found.")

    row.consumed_at=_oauth_now()
    db.commit()
    response=JSONResponse({
        "authenticated":True,
        "user":{"id":user.id,"email":user.email},
    })
    _set_session_cookies(response,make_token(user))
    return response

@app.post("/auth/register")
def register(request: AuthRequest, http_request: Request, db=Depends(get_db)):
    _auth_rate_limit(http_request, request.email)
    email=request.email.strip().lower()
    if not valid_email(email): raise HTTPException(400,"Enter a valid email.")
    if len(request.password)<8: raise HTTPException(400,"Password must be at least 8 characters.")
    if db.query(User).filter(User.email==email).first(): raise HTTPException(409,"Account already exists.")
    user=User(email=email,password_hash=hash_password(request.password))
    db.add(user); db.commit(); db.refresh(user)
    return {"created":True,"user":{"id":user.id,"email":user.email}}


@app.post("/auth/login")
def login(request: AuthRequest, http_request: Request, db=Depends(get_db)):
    _auth_rate_limit(http_request, request.email)
    user=db.query(User).filter(User.email==request.email.strip().lower()).first()
    if not user or not verify_password(request.password,user.password_hash):
        raise HTTPException(401,"Invalid email or password.")
    if user.password_hash.startswith("pbkdf2$"):
        user.password_hash=hash_password(request.password); db.commit()
    token=make_token(user)
    response=JSONResponse({"authenticated":True,"user":{"id":user.id,"email":user.email}})
    _set_session_cookies(response,token)
    return response


@app.post("/auth/logout")
def logout(request: Request):
    response=JSONResponse({"logged_out":True})
    _clear_session_cookies(response)
    return response


@app.get("/auth/me")
def me(user: User=Depends(current_user)): return {"id":user.id,"email":user.email}

@app.post("/analyze/url")
def analyze_url_endpoint(request: URLRequest):
    if not request.url.strip(): raise HTTPException(400,"URL cannot be empty.")
    return analyze_url_intelligence(request.url)

@app.get("/analytics")
def analytics(user: User=Depends(current_user), db=Depends(get_db)):
    total,spam,high,medium=db.query(
        func.count(Scan.id),
        func.coalesce(func.sum(case((Scan.prediction=="spam",1),else_=0)),0),
        func.coalesce(func.sum(case((Scan.risk_level=="high",1),else_=0)),0),
        func.coalesce(func.sum(case((Scan.risk_level=="medium",1),else_=0)),0),
    ).filter(Scan.user_id==user.id).one()
    recent=db.query(Scan).filter(Scan.user_id==user.id).order_by(Scan.id.desc()).limit(20).all()
    total=int(total or 0); spam=int(spam or 0); high=int(high or 0); medium=int(medium or 0)
    recent_payload=[{"id":x.id,"timestamp":x.timestamp.isoformat(),"prediction":x.prediction,"risk_level":x.risk_level,"risk_score":x.risk_score,"spam_probability":x.spam_probability,"preview":x.preview} for x in recent]
    return {"total_scanned":total,"spam_detected":spam,"ham_detected":total-spam,"spam_rate":round(spam/total*100,2) if total else 0,"high_risk":high,"medium_risk":medium,"recent":recent_payload}

@app.get("/health")
def health(db=Depends(get_db)):
    db_ok=True
    try:
        db.execute(sql_text("SELECT 1"))
    except Exception:
        db_ok=False
    model_ok=model is not None
    if db_ok and model_ok:
        return {"status":"ok","model_loaded":True,"database":"ok"}
    return JSONResponse(
        status_code=503,
        content={"status":"degraded","model_loaded":model_ok,"database":"ok" if db_ok else "unavailable"}
    )

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
        "spamassassin":"spamassassin_evaluation_report.json",
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
    result=classify(request.text,user.id,db,persist=False)
    try:
        db.add(Scan(user_id=user.id,prediction=result["prediction"],risk_level=result["risk_level"],risk_score=result["risk_score"],spam_probability=result["spam_probability"],preview=request.text[:90].replace("\n"," ")))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return result


@app.post("/predict/batch")
def predict_batch(request: BatchRequest,user: User=Depends(current_user),db=Depends(get_db)):
    emails=[x.strip() for x in request.emails if x and x.strip()]
    if not emails or len(emails)>500: raise HTTPException(400,"Provide between 1 and 500 non-empty emails.")
    results=[classify(x,user.id,db,persist=False) for x in emails]
    scans=[Scan(user_id=user.id,prediction=r["prediction"],risk_level=r["risk_level"],risk_score=r["risk_score"],spam_probability=r["spam_probability"],preview=emails[i][:90].replace("\n"," ")) for i,r in enumerate(results)]
    try:
        db.add_all(scans)
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"count":len(emails),"results":results}


@app.post("/analyze/raw-email")
def analyze_raw_email(request: RawEmailRequest,user: User=Depends(current_user),db=Depends(get_db)):
    if not request.raw_email.strip(): raise HTTPException(400,"Raw email cannot be empty.")
    parsed=parse_email(request.raw_email)
    analysis=classify(parsed["body"] or request.raw_email,user.id,db,persist=False)
    security=analyze_email_security(parsed, parsed["body"] or request.raw_email)
    security["html_analysis"]=analyze_html_links(parsed.get("html_body",""))
    security["attachment_analysis"]=parsed.get("attachments",{"count":0,"attachments":[]})
    security["unified_threat"]=build_unified_threat_assessment(analysis,security)
    try:
        db.add(Scan(user_id=user.id,prediction=analysis["prediction"],risk_level=analysis["risk_level"],risk_score=analysis["risk_score"],spam_probability=analysis["spam_probability"],preview=(parsed["body"] or request.raw_email)[:90].replace("\n"," ")))
        db.commit()
    except Exception:
        db.rollback()
        raise
    return {"headers":{k:v for k,v in parsed.items() if k not in ("body","html_body","attachments")},"body_analysis":analysis,"email_security":security}


# Advanced email-security heuristics
from difflib import SequenceMatcher

FREE_EMAIL_DOMAINS = {"gmail.com","outlook.com","hotmail.com","yahoo.com","proton.me","protonmail.com"}

def _domain_from_address(value):
    if not value or "@" not in value:
        return None
    domain=value.rsplit("@",1)[-1].strip().lower().strip("<>")
    return domain.split(">",1)[0].strip().strip(".")

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

def build_unified_threat_assessment(ml_result, security):
    signals=list(security.get("signals",[]))
    sender_domain=security.get("sender_domain")
    domain_intelligence=_domain_intelligence(sender_domain)
    if domain_intelligence.get("signal"):
        signals.append(domain_intelligence["signal"])
    html=security.get("html_analysis") or {}
    attachments=security.get("attachment_analysis") or {}

    for item in html.get("mismatches",[]):
        signals.append({"type":"html_destination_mismatch","severity":"high","category":"url","detail":item.get("detail","Visible link text differs from destination.")})
    if html.get("ip_host_count",0):
        signals.append({"type":"html_ip_destination","severity":"high","category":"url","detail":"HTML email contains a link whose destination uses an IP address."})
    if html.get("punycode_count",0):
        signals.append({"type":"html_punycode_destination","severity":"high","category":"url","detail":"HTML email contains a punycode destination."})
    for item in attachments.get("attachments",[]):
        for flag in item.get("flags",[]):
            severity="high" if "dangerous" in flag or "macro" in flag else "medium"
            signals.append({"type":"attachment_risk","severity":severity,"category":"attachment",
                            "detail":f"Attachment {item.get('filename','unknown')} flagged: {flag}."})

    category_map={"spf_fail":"authentication","dkim_fail":"authentication","dmarc_fail":"authentication",
                  "reply_to_mismatch":"identity","return_path_mismatch":"identity","display_name_spoof":"identity",
                  "lookalike_domain":"identity","disposable_domain":"domain","unicode_homoglyph":"domain",
                  "suspicious_url":"url","phishing_subject":"content"}
    normalized=[]
    for signal in signals:
        item=dict(signal)
        item.setdefault("category",category_map.get(item.get("type"),"security"))
        normalized.append(item)

    high=sum(1 for item in normalized if item.get("severity")=="high")
    medium=sum(1 for item in normalized if item.get("severity")=="medium")
    ml_score=float(ml_result.get("risk_score",0))
    heuristic_score=min(100,high*28+medium*12)
    threat_score=min(100,round(ml_score*0.55+heuristic_score*0.45))

    if threat_score >= 75:
        verdict="high"
    elif threat_score >= 45:
        verdict="medium"
    else:
        verdict="low"

    return {
        "threat_score":threat_score,
        "risk_level":verdict,
        "high_signals":high,
        "medium_signals":medium,
        "signal_count":len(normalized),
        "model_risk_score":round(ml_score,2),
        "domain_intelligence":domain_intelligence,
        "security_heuristic_score":round(heuristic_score,2),
        "signals":normalized[:30],
        "recommendation":(
            "Do not interact with links or attachments; verify the sender through a trusted channel."
            if verdict=="high" else
            "Review sender, authentication results, links, and attachments before interacting."
            if verdict=="medium" else
            "No strong phishing indicators were detected; continue normal email hygiene."
        )
    }

def _display_name_from_address(value):
    if not value:
        return ""
    match=re.match(r'^\s*"?([^"<]+?)"?\s*<[^>]+>', value)
    return match.group(1).strip() if match else ""

def _known_brand_display_name_mismatch(sender, sender_domain):
    display=_display_name_from_address(sender).lower()
    if not display or not sender_domain:
        return None
    brands={"paypal":"paypal.com","microsoft":"microsoft.com","google":"google.com","apple":"apple.com","amazon":"amazon.com","facebook":"facebook.com","instagram":"instagram.com","linkedin":"linkedin.com"}
    for brand,domain in brands.items():
        if brand in display and sender_domain != domain and not sender_domain.endswith("." + domain):
            return {"type":"display_name_spoof","severity":"high","category":"identity",
                    "detail":f"Display name references {brand.title()} but sender domain is {sender_domain}."}
    return None

def analyze_email_security(headers, body):
    sender=headers.get("from")
    reply=headers.get("reply_to")
    sender_domain=_domain_from_address(sender)
    reply_domain=_domain_from_address(reply)
    return_path_domain=_domain_from_address(headers.get("return_path"))
    signals=[]
    lookalikes=detect_lookalike_domains(sender_domain)
    display_spoof=_known_brand_display_name_mismatch(sender,sender_domain)
    if display_spoof:
        signals.append(display_spoof)
    for item in lookalikes:
        signals.append({"type":"lookalike_domain","severity":"high","category":"identity",
                        "detail":item["detail"],"brand":item["brand"],"similarity":item["similarity"]})
    if sender_domain and reply_domain and sender_domain != reply_domain:
        signals.append({"type":"reply_to_mismatch","severity":"high","category":"identity",
                        "detail":f"Reply-To domain {reply_domain} differs from sender domain {sender_domain}."})
    if sender_domain and return_path_domain and sender_domain != return_path_domain:
        signals.append({"type":"return_path_mismatch","severity":"medium","category":"identity",
                        "detail":f"Return-Path domain {return_path_domain} differs from sender domain {sender_domain}."})
    auth=headers.get("authentication_results","")
    for mechanism in ("spf","dkim","dmarc"):
        if auth and re.search(rf"\b{mechanism}\s*=\s*fail\b",auth,re.I):
            signals.append({"type":f"{mechanism}_fail","severity":"high","category":"authentication",
                            "detail":f"{mechanism.upper()} authentication failed."})
    subject=(headers.get("subject") or "").lower()
    if re.search(r"verify|suspend|urgent|password|account|payment|invoice",subject):
        signals.append({"type":"phishing_subject","severity":"medium","category":"content",
                        "detail":"Subject contains common account, payment, or urgency language."})
    for url in extract_urls(body):
        info=analyze_url(url)
        if info["suspicious"]:
            signals.append({"type":"suspicious_url","severity":"high","category":"url",
                            "detail":info["reasons"][0] if info["reasons"] else "URL triggered security heuristics.","url":url})
    high=sum(1 for item in signals if item["severity"]=="high")
    medium=sum(1 for item in signals if item["severity"]=="medium")
    threat_score=min(100,high*28 + medium*12)
    return {"sender_domain":sender_domain,"reply_to_domain":reply_domain,"return_path_domain":return_path_domain,
            "lookalike_domains":lookalikes,"signals":signals,"risk_signal_count":len(signals),
            "high_signals":high,"medium_signals":medium,"threat_score":threat_score,
            "security_risk":"high" if threat_score>=70 else ("medium" if threat_score>=30 else "low")}
