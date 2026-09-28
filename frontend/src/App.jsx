import { useEffect, useMemo, useState } from "react";

const API_URL = import.meta.env.DEV
  ? (import.meta.env.VITE_API_URL || "http://localhost:8000").replace(/\/+$/, "")
  : "/api";

const samples = {
  spam: "Congratulations! You have won a FREE cash prize. Click http://bit.ly/reward now to claim your reward!",
  safe: "Hi team, the meeting has been moved to 3 PM tomorrow. Please review the attached agenda before the call.",
};

const navItems = [
  { id: "details", label: "Details", icon: "◉" },
  { id: "scanner", label: "Scanner", icon: "✦" },
  { id: "history", label: "History", icon: "◷" },
  { id: "mail-settings", label: "Mail config", icon: "⚙" },
  { id: "models", label: "Models", icon: "◒" },
];

function viewFromHash() {
  const value = window.location.hash.replace("#", "");
  return ["details", "scanner", "history", "mail-settings", "models"].includes(value) ? value : "details";
}

function formatPercent(value) {
  return `${((value ?? 0) * 100).toFixed(1)}%`;
}

function riskClass(value) {
  return value === "high" ? "risk-high" : value === "medium" ? "risk-medium" : "risk-low";
}

export default function App() {
  const [token, setToken] = useState(localStorage.getItem("mailguard_authenticated") === "1" ? "session" : "");
  const [user, setUser] = useState(null);
  const [authMode, setAuthMode] = useState("login");
  const [authEmail, setAuthEmail] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [authProvider, setAuthProvider] = useState("email");
  const [view, setView] = useState(viewFromHash());

  const [text, setText] = useState("");
  const [raw, setRaw] = useState("");
  const [mode, setMode] = useState("message");
  const [result, setResult] = useState(null);
  const [header, setHeader] = useState(null);
  const [url, setUrl] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [batch, setBatch] = useState([]);
  const [analytics, setAnalytics] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [evaluationReports, setEvaluationReports] = useState(null);

  const [mailConfig, setMailConfig] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("mailguard_config")) || {
        defaultMode: "message",
        showAdvanced: true,
        compactResults: false,
      };
    } catch {
      return { defaultMode: "message", showAdvanced: true, compactResults: false };
    }
  });
  const [notice, setNotice] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [backendStatus, setBackendStatus] = useState("checking");
  const [modelLoaded, setModelLoaded] = useState(false);

  const analysis = result || header?.body_analysis;
  const security = header?.email_security;

  function navigate(next) {
    if (next === "scanner" && !result && !header) {
      setMode(mailConfig.defaultMode || "message");
    }
    window.location.hash = next;
    setView(next);
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  function getCookieValue(name) {
    const prefix=name+"=";
    const part=document.cookie.split("; ").find((item) => item.startsWith(prefix));
    return part ? decodeURIComponent(part.slice(prefix.length)) : "";
  }

  async function request(path, body, method = "POST") {
    const csrf=getCookieValue("mailguard_csrf");
    const response = await fetch(`${API_URL}${path}`, {
      method,
      credentials: "include",
      headers: {
        ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
        ...(csrf ? { "X-CSRF-Token": csrf } : {}),
      },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    });

    let data = null;
    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      throw new Error(data?.detail || `Request failed (${response.status})`);
    }
    return data;
  }

  async function checkBackend({ silent = false } = {}) {
    if (!silent) setBackendStatus("checking");
    try {
      const controller = new AbortController();
      const timer = window.setTimeout(() => controller.abort(), 65000);
      const response = await fetch(`${API_URL}/health`, {
        method: "GET",
        signal: controller.signal,
        cache: "no-store",
      });
      window.clearTimeout(timer);
      const data = await response.json();
      if (response.ok && data?.status === "ok") {
        setBackendStatus("online");
        setModelLoaded(Boolean(data?.model_loaded));
      } else {
        setBackendStatus("offline");
        setModelLoaded(false);
      }
    } catch (err) {
      setModelLoaded(false);
      setBackendStatus(err?.name === "AbortError" ? "waking" : "offline");
    }
  }

  async function loadProfile() {
    if (!token) return;
    try {
      const data = await request("/auth/me", undefined, "GET");
      setUser(data);
    } catch {
      logout();
    }
  }

  function startOAuth(provider) {
    setAuthProvider(provider);
    setError("");
    setNotice("");
    window.location.assign(`${API_URL}/auth/${provider}/start`);
  }

  async function authenticate() {
    setLoading(true);
    setError("");
    setNotice("");
    try {
      const data = await request(`/auth/${authMode}`, {
        email: authEmail,
        password: authPassword,
      });

      if (authMode === "register") {
        setAuthMode("login");
        setAuthPassword("");
        setNotice("Account created successfully. Please sign in to continue.");
        return;
      }

      localStorage.setItem("mailguard_authenticated", "1");
      setToken("session");
      setUser(data.user || null);
      setAuthPassword("");
      setShowPassword(false);
      setAuthProvider("email");
      setView("details");
      navigate("details");
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function logout() {
    try {
      await request("/auth/logout");
    } catch {
      // Clear local UI state even if the backend session is already expired.
    }
    localStorage.removeItem("mailguard_authenticated");
    setToken("");
    setUser(null);
    setAnalytics(null);
    setResult(null);
    setHeader(null);
    setBatch([]);
    setNotice("");
    setAuthMode("login");
    setShowPassword(false);
    setAuthProvider("email");
    window.history.replaceState(null, "", window.location.pathname);
    setView("scanner");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }

  async function analyze() {
    if (!text.trim()) return;
    setLoading(true);
    setError("");
    try {
      setResult(await request("/predict", { text }));
      setHeader(null);
    } catch (err) {
      setError(`${err.message}. Check that the API is online.`);
    } finally {
      setLoading(false);
    }
  }

  async function analyzeRaw() {
    if (!raw.trim()) return;
    setLoading(true);
    setError("");
    try {
      setHeader(await request("/analyze/raw-email", { raw_email: raw }));
      setResult(null);
    } catch (err) {
      setError(`${err.message}. Check that the API is online.`);
    } finally {
      setLoading(false);
    }
  }

  function parseCsvRows(source) {
    const rows=[]; let row=[]; let field=""; let inQuotes=false;
    for(let i=0;i<source.length;i+=1){
      const ch=source[i];
      if(inQuotes){
        if(ch==='"'){
          if(source[i+1]==='"'){ field+='"'; i+=1; } else { inQuotes=false; }
        } else { field+=ch; }
      } else if(ch==='"'){
        inQuotes=true;
      } else if(ch===','){
        row.push(field); field="";
      } else if(ch==='\n'){
        row.push(field); field="";
        if(row.some((cell)=>cell.trim())) rows.push(row);
        row=[];
      } else if(ch!=='\r'){
        field+=ch;
      }
    }
    if(field.length || row.length){
      row.push(field);
      if(row.some((cell)=>cell.trim())) rows.push(row);
    }
    if(inQuotes) throw new Error("CSV contains an unterminated quoted field.");
    return rows;
  }

  function extractCsvEmails(source) {
    const rows=parseCsvRows(source);
    if(!rows.length) throw new Error("CSV file is empty.");
    const normalized=rows[0].map((cell)=>cell.trim().toLowerCase());
    const emailIndex=normalized.findIndex((cell)=>["email","text","message","body","content","email_text"].includes(cell));
    const hasHeader=emailIndex>=0;
    const dataRows=hasHeader ? rows.slice(1) : rows;
    const index=hasHeader ? emailIndex : null;
    const emails=dataRows.map((cells)=>{
      if(index!==null) return cells[index] || "";
      if(cells.length===1) return cells[0];
      return cells.reduce((longest,current)=>current.length>longest.length?current:longest,"");
    }).map((value)=>value.trim()).filter(Boolean);
    if(emails.length>500) throw new Error("CSV contains more than 500 messages. Please upload a smaller batch.");
    if(!emails.length) throw new Error("CSV contains no usable email/message text.");
    return emails;
  }
  async function analyzeFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setError("");
    try {
      const contents = await file.text();
      if (file.name.toLowerCase().endsWith(".csv")) {
        const emails=extractCsvEmails(contents);
        const data=await request("/predict/batch",{emails});
        setBatch(data.results || []);
        setHeader(null);
        setResult(null);
      } else {
        setRaw(contents);
        setMode("raw");
        setHeader(await request("/analyze/raw-email", { raw_email: contents }));
        setResult(null);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
      event.target.value = "";
    }
  }

  async function analyzeUrl() {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    try {
      setUrlResult(await request("/analyze/url", { url }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadAnalytics() {
    setLoading(true);
    setError("");
    try {
      setAnalytics(await request("/analytics", undefined, "GET"));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadComparison() {
    setLoading(true);
    try {
      setComparison(await request("/model-comparison", undefined, "GET"));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  async function loadEvaluationReports() {
    setLoading(true);
    try {
      setEvaluationReports(await request("/evaluation-reports", undefined, "GET"));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    const onHashChange = () => setView(viewFromHash());
    window.addEventListener("hashchange", onHashChange);

    const params = new URLSearchParams(window.location.search);
    const oauthCode = params.get("oauth_code");
    const oauthError = params.get("oauth_error");

    if (oauthCode && !token) {
      setLoading(true);
      setError("");
      setNotice("");
      request("/auth/oauth/exchange", { code: oauthCode })
        .then((data) => {
          localStorage.setItem("mailguard_authenticated", "1");
          setToken("session");
          setUser(data.user || null);
          window.history.replaceState(null, "", window.location.pathname + "#details");
          setView("details");
        })
        .catch((err) => {
          setError(err.message || "OAuth sign-in failed.");
          window.history.replaceState(null, "", window.location.pathname);
        })
        .finally(() => setLoading(false));
    } else if (oauthError) {
      const provider = params.get("provider") || "provider";
      const message = oauthError === "provider_not_configured"
        ? provider + " SSO is not configured yet. Add the provider OAuth credentials on the backend."
        : "Unable to complete " + provider + " sign-in (" + oauthError + ").";
      setError(message);
      window.history.replaceState(null, "", window.location.pathname);
    }

    if (token) {
      if (!window.location.hash || !["details", "scanner", "history", "mail-settings", "models"].includes(window.location.hash.slice(1))) {
        window.location.hash = "details";
      }
      setView(viewFromHash());
    } else if (!oauthCode) {
      window.history.replaceState(null, "", window.location.pathname + window.location.hash);
      setView("scanner");
    }

    checkBackend();
    const retry = window.setInterval(() => checkBackend({ silent: true }), 20000);
    return () => {
      window.removeEventListener("hashchange", onHashChange);
      window.clearInterval(retry);
    };
  }, [token]);

  useEffect(() => {
    if (token && !user) loadProfile();
  }, [token]);

  useEffect(() => {
    if (view === "history" && token && !analytics) loadAnalytics();
    if (view === "models" && token && !comparison && !evaluationReports) {
      Promise.all([loadComparison(), loadEvaluationReports()]);
    }
  }, [view, token]);

  useEffect(() => {
    localStorage.setItem("mailguard_config", JSON.stringify(mailConfig));
  }, [mailConfig]);

  const authSubtitle = authMode === "login"
    ? "Access your secure personal scan history."
    : "Create an account to save and review your scans.";

  const backendLabel = useMemo(() => {
    if (backendStatus === "online") return modelLoaded ? "API online · model loaded" : "API online · model unavailable";
    if (backendStatus === "checking") return "Checking API…";
    if (backendStatus === "waking") return "Waking Render API…";
    return "API offline";
  }, [backendStatus, modelLoaded]);

  return (
    <main className={mailConfig.compactResults ? "app-shell compact-results" : "app-shell"}>
      <div className="ambient ambient-one" />
      <div className="ambient ambient-two" />

      <nav className="topbar">
        <button className="brand" onClick={() => navigate(token ? "details" : "scanner")} aria-label="MailGuard AI home">
          <span className="brand-icon">✉</span>
          <span>MailGuard <b>AI</b></span>
        </button>

        <div className="topbar-right">
          <div className={`api-status ${backendStatus}`} title={`Backend: ${API_URL}`}>
            <span className="status-dot" />
            {backendLabel}
          </div>

          {token && (
            <>
              <div className="nav-links">
                {navItems.map((item) => (
                  <button
                    key={item.id}
                    className={view === item.id ? "nav-link active" : "nav-link"}
                    onClick={() => navigate(item.id)}
                  >
                    <span>{item.icon}</span>
                    {item.label}
                  </button>
                ))}
              </div>
              <button className="ghost-button" onClick={logout}>Logout</button>
            </>
          )}
        </div>
      </nav>

      {!token ? (
        <section className="landing">
          <div className="landing-copy">
            <span className="eyebrow">AI-POWERED EMAIL SECURITY</span>
            <h1>Understand every message <span>before you click.</span></h1>
            <p>
              MailGuard AI combines explainable spam classification with phishing,
              URL, sender-identity, authentication, and attachment intelligence.
            </p>

            <div className="landing-actions">
              <button className="primary-button" onClick={() => document.querySelector(".auth-card")?.scrollIntoView({ behavior: "smooth" })}>
                Get started <span>↓</span>
              </button>
              <button className="secondary-button" onClick={checkBackend}>Check system</button>
            </div>

            <div className="feature-grid">
              <div className="feature-card">
                <span>01</span>
                <strong>Spam detection</strong>
                <p>Word + character TF-IDF with logistic regression.</p>
              </div>
              <div className="feature-card">
                <span>02</span>
                <strong>Phishing intelligence</strong>
                <p>Identity, authentication, lookalike, and link signals.</p>
              </div>
              <div className="feature-card">
                <span>03</span>
                <strong>URL intelligence</strong>
                <p>Structural risk checks and optional reputation enrichment.</p>
              </div>
              <div className="feature-card">
                <span>04</span>
                <strong>Explainable AI</strong>
                <p>See the evidence that contributed to the model decision.</p>
              </div>
            </div>
          </div>

          <section className="auth-card card">
            <div className="card-kicker">SECURE ACCESS</div>
            <h2>{authMode === "login" ? "Welcome back" : "Create your account"}</h2>
            <p>{authSubtitle}</p>

            <div className="provider-label">CONTINUE WITH</div>
            <div className="provider-grid">
              <button
                type="button"
                className={authProvider === "Google (Gmail)" ? "provider-button active" : "provider-button"}
                onClick={() => startOAuth("google")}
              >
                <span className="provider-icon google">G</span>
                <span>Google <small>Gmail</small></span>
              </button>
              <button
                type="button"
                className={authProvider === "Yahoo Mail" ? "provider-button active" : "provider-button"}
                onClick={() => startOAuth("yahoo")}
              >
                <span className="provider-icon yahoo">Y!</span>
                <span>Yahoo <small>Mail</small></span>
              </button>
              <button
                type="button"
                className={authProvider === "Microsoft" ? "provider-button active" : "provider-button"}
                onClick={() => startOAuth("microsoft")}
              >
                <span className="provider-icon microsoft"><i></i><i></i><i></i><i></i></span>
                <span>Microsoft <small>Outlook / 365</small></span>
              </button>
              <button
                type="button"
                className={authProvider === "email" ? "provider-button active" : "provider-button"}
                onClick={() => { setAuthProvider("email"); setError(""); setNotice(""); }}
              >
                <span className="provider-icon other">@</span>
                <span>Other <small>Email system</small></span>
              </button>
            </div>

            <div className="auth-divider"><span>OR USE EMAIL</span></div>

            <label className="field">
              <span>Email address</span>
              <input
                type="email"
                value={authEmail}
                onChange={(event) => setAuthEmail(event.target.value)}
                placeholder="you@example.com"
                autoComplete="email"
              />
            </label>

            <label className="field">
              <span>Password</span>
              <div className="password-field">
                <input
                  type={showPassword ? "text" : "password"}
                  value={authPassword}
                  onChange={(event) => setAuthPassword(event.target.value)}
                  placeholder="8+ characters"
                  autoComplete={authMode === "login" ? "current-password" : "new-password"}
                  onKeyDown={(event) => {
                    if (event.key === "Enter" && authEmail && authPassword) authenticate();
                  }}
                />
                <button
                  type="button"
                  className="password-toggle"
                  aria-label={showPassword ? "Hide password" : "Show password"}
                  title={showPassword ? "Hide password" : "Show password"}
                  onClick={() => setShowPassword((value) => !value)}
                >
                  {showPassword ? "◉" : "◌"}
                </button>
              </div>
            </label>

            {error && <div className="inline-error" role="alert">{error}</div>}

            {notice && <div className="inline-success" role="status">{notice}</div>}

            <button
              className="primary-button full"
              onClick={authenticate}
              disabled={loading || !authEmail || !authPassword}
            >
              {loading ? "Working…" : authMode === "login" ? "Sign in" : "Create account"}
            </button>

            <button
              className="switch-button"
              onClick={() => {
                setError("");
                setNotice("");
                setAuthMode(authMode === "login" ? "register" : "login");
              }}
            >
              {authMode === "login" ? "Need an account? Create one" : "Already have an account? Sign in"}
            </button>
          </section>
        </section>
      ) : (
        <>
          {view === "details" && (
            <section className="page-section">
              <section className="dashboard-header details-header">
                <div>
                  <span className="eyebrow">ACCOUNT OVERVIEW</span>
                  <h1>Your workspace</h1>
                  <p>Manage your account, review scans, and configure how MailGuard handles your email analysis workflow.</p>
                </div>
                <div className="user-chip">
                  <span>{user?.email?.slice(0, 1).toUpperCase() || "U"}</span>
                  <div>
                    <small>Authenticated account</small>
                    <strong>{user?.email || "Loading profile…"}</strong>
                  </div>
                </div>
              </section>

              <div className="details-grid">
                <section className="card profile-card">
                  <div className="section-heading">
                    <div>
                      <div className="card-kicker">YOUR DETAILS</div>
                      <h2>Account information</h2>
                    </div>
                    <span className="count-pill">SECURE</span>
                  </div>
                  <div className="detail-list">
                    <div><span>Email</span><strong>{user?.email || "—"}</strong></div>
                    <div><span>User ID</span><strong>{user?.id || "—"}</strong></div>
                    <div><span>Authentication</span><strong>HttpOnly session cookie</strong></div>
                    <div><span>API status</span><strong>{backendStatus === "online" ? "Online" : backendStatus === "checking" ? "Checking…" : "Offline"}</strong></div>
                    <div><span>ML model</span><strong>{modelLoaded ? "Loaded" : "Unavailable"}</strong></div>
                  </div>
                </section>

                <section className="card quick-card">
                  <div className="section-heading">
                    <div>
                      <div className="card-kicker">QUICK ACCESS</div>
                      <h2>MailGuard workspace</h2>
                    </div>
                  </div>
                  <div className="quick-actions">
                    <button onClick={() => navigate("scanner")}><span>✦</span><div><strong>Open scanner</strong><small>Analyze an email or raw .eml file.</small></div></button>
                    <button onClick={() => navigate("history")}><span>◷</span><div><strong>View history</strong><small>Review your saved scan activity.</small></div></button>
                    <button onClick={() => navigate("mail-settings")}><span>⚙</span><div><strong>Mail configuration</strong><small>Set your scanning preferences.</small></div></button>
                  </div>
                </section>
              </div>

              <section className="card status-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">SYSTEM STATUS</div>
                    <h2>Security services</h2>
                  </div>
                  <button className="secondary-button" onClick={checkBackend}>Refresh</button>
                </div>
                <div className="status-grid">
                  <div><span>API</span><strong className={backendStatus}>{backendStatus === "online" ? "Online" : backendStatus === "checking" ? "Checking" : "Offline"}</strong></div>
                  <div><span>Spam classifier</span><strong>{modelLoaded ? "Loaded" : "Unavailable"}</strong></div>
                  <div><span>Scan history</span><strong>Enabled</strong></div>
                  <div><span>Mail configuration</span><strong>Saved locally</strong></div>
                </div>
              </section>
            </section>
          )}

          {view === "mail-settings" && (
            <section className="page-section">
              <section className="dashboard-header">
                <div>
                  <span className="eyebrow">MAIL CONFIGURATION</span>
                  <h1>Scanning preferences</h1>
                  <p>Choose the default workflow and presentation preferences for your MailGuard workspace.</p>
                </div>
              </section>

              <section className="card settings-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">SCANNER DEFAULTS</div>
                    <h2>How MailGuard should open</h2>
                    <p>These preferences are saved in this browser for your account.</p>
                  </div>
                  <span className="count-pill">LOCAL</span>
                </div>

                <label className="setting-row">
                  <div><strong>Default scan mode</strong><span>Choose what opens when you enter the scanner.</span></div>
                  <select
                    value={mailConfig.defaultMode}
                    onChange={(event) => {
                      const value = event.target.value;
                      setMailConfig((current) => ({ ...current, defaultMode: value }));
                    }}
                  >
                    <option value="message">Message scanner</option>
                    <option value="raw">Raw email analyzer</option>
                  </select>
                </label>

                <label className="setting-row">
                  <div><strong>Advanced phishing intelligence</strong><span>Keep sender, URL, authentication, HTML, and attachment signals visible.</span></div>
                  <input
                    className="toggle"
                    type="checkbox"
                    checked={mailConfig.showAdvanced}
                    onChange={(event) => setMailConfig((current) => ({ ...current, showAdvanced: event.target.checked }))}
                  />
                </label>

                <label className="setting-row">
                  <div><strong>Compact results</strong><span>Use a denser result layout when reviewing several scans.</span></div>
                  <input
                    className="toggle"
                    type="checkbox"
                    checked={mailConfig.compactResults}
                    onChange={(event) => setMailConfig((current) => ({ ...current, compactResults: event.target.checked }))}
                  />
                </label>
              </section>

              <section className="card settings-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">MAIL ANALYSIS PIPELINE</div>
                    <h2>Active capabilities</h2>
                  </div>
                </div>
                <div className="capability-grid">
                  <div><span>Message model</span><strong>Word + character TF-IDF</strong></div>
                  <div><span>Raw email</span><strong>Headers + authentication + MIME</strong></div>
                  <div><span>URL checks</span><strong>Structural heuristics</strong></div>
                  <div><span>Domain intelligence</span><strong>RDAP enrichment</strong></div>
                  <div><span>External reputation</span><strong>VirusTotal optional</strong></div>
                  <div><span>Batch analysis</span><strong>Up to 500 messages</strong></div>
                </div>
              </section>

              <div className="settings-note">
                <strong>Note</strong>
                <span>Mail provider inbox connections are not enabled in this version. MailGuard analyzes email content you paste or upload; it does not access your inbox directly.</span>
              </div>
            </section>
          )}

          {view === "scanner" && (
            <>
              <section className="dashboard-header">
                <div>
                  <span className="eyebrow">MAILGUARD WORKSPACE</span>
                  <h1>Security scanner</h1>
                  <p>Analyze messages, inspect raw emails, and investigate suspicious links.</p>
                </div>
                <div className="user-chip">
                  <span>{user?.email?.slice(0, 1).toUpperCase() || "U"}</span>
                  <div>
                    <small>Signed in as</small>
                    <strong>{user?.email || "Authenticated user"}</strong>
                  </div>
                </div>
              </section>

              <div className="workspace-grid">
                <section className="card composer-card">
                  <div className="card-head">
                    <div>
                      <div className="card-kicker">ANALYSIS MODE</div>
                      <h2>{mode === "message" ? "Message scanner" : "Raw email analyzer"}</h2>
                      <p>{mode === "message" ? "Paste message text and inspect the model decision." : "Paste a complete .eml message with headers, body, and optional attachments."}</p>
                    </div>
                    <span className="mode-pill">{mode === "message" ? "NLP" : "RAW .EML"}</span>
                  </div>

                  <div className="mode-tabs">
                    <button className={mode === "message" ? "active" : ""} onClick={() => { setMode("message"); setError(""); }}>
                      Message
                    </button>
                    <button className={mode === "raw" ? "active" : ""} onClick={() => { setMode("raw"); setError(""); }}>
                      Raw email
                    </button>
                  </div>

                  <textarea
                    value={mode === "message" ? text : raw}
                    onChange={(event) => mode === "message" ? setText(event.target.value) : setRaw(event.target.value)}
                    placeholder={mode === "message" ? "Paste an email, SMS, or message here…" : "From: sender@example.com\nReply-To: …\nAuthentication-Results: …\nSubject: …\n\nEmail body…"}
                  />

                  <div className="composer-toolbar">
                    {mode === "message" ? (
                      <div className="sample-actions">
                        <span>Quick samples</span>
                        <button onClick={() => setText(samples.spam)}>Spam</button>
                        <button onClick={() => setText(samples.safe)}>Safe</button>
                      </div>
                    ) : (
                      <div className="sample-actions">
                        <span>Import</span>
                        <label className="file-button">
                          .eml / .txt
                          <input type="file" accept=".eml,.txt,text/plain,message/rfc822" onChange={analyzeFile} />
                        </label>
                      </div>
                    )}

                    <label className="file-button secondary-file">
                      CSV batch
                      <input type="file" accept=".csv,text/csv" onChange={analyzeFile} />
                    </label>
                  </div>

                  {error && <div className="inline-error" role="alert">{error}</div>}

                  <button
                    className="primary-button full"
                    onClick={mode === "message" ? analyze : analyzeRaw}
                    disabled={loading || !(mode === "message" ? text : raw).trim()}
                  >
                    {loading ? "Analyzing…" : mode === "message" ? "Analyze message →" : "Inspect raw email →"}
                  </button>
                </section>

                <section className="card result-card">
                  <div className="card-head">
                    <div>
                      <div className="card-kicker">AI RESULT</div>
                      <h2>Security report</h2>
                      <p>Classification, confidence, risk, and supporting evidence.</p>
                    </div>
                    {analysis && <span className={`result-badge ${analysis.prediction}`}>{analysis.label}</span>}
                  </div>

                  {!analysis ? (
                    <div className="empty-state">
                      <div className="empty-icon">◈</div>
                      <h3>Ready for analysis</h3>
                      <p>Run a scan to populate your security report and model evidence.</p>
                    </div>
                  ) : (
                    <>
                      <div className="score-row">
                        <div>
                          <span>RISK SCORE</span>
                          <strong>{analysis.risk_score}<em>/100</em></strong>
                        </div>
                        <span className={`risk-label ${riskClass(analysis.risk_level)}`}>
                          {analysis.risk_level.toUpperCase()} RISK
                        </span>
                      </div>

                      <div className="score-track"><span style={{ width: `${analysis.risk_score}%` }} /></div>

                      <div className="metric-strip">
                        <div><span>Spam probability</span><strong>{analysis.spam_probability}%</strong></div>
                        <div><span>Confidence</span><strong>{analysis.confidence}%</strong></div>
                        <div><span>URLs found</span><strong>{analysis.url_analysis?.url_count ?? 0}</strong></div>
                      </div>

                      {analysis.risk_signals?.length > 0 && (
                        <div className="report-section">
                          <div className="section-title">Risk signals</div>
                          <div className="signal-list compact">
                            {analysis.risk_signals.map((signal, index) => (
                              <div className="signal-row" key={index}>
                                <span className="signal-marker">!</span>
                                <span>{signal}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {analysis.explanation?.length > 0 && (
                        <div className="report-section">
                          <div className="section-title">Why the model decided this</div>
                          <div className="evidence-list">
                            {analysis.explanation.map((item, index) => (
                              <div className="evidence-row" key={index}>
                                <span className={item.impact >= 0 ? "evidence-positive" : "evidence-negative"}>
                                  {item.impact >= 0 ? "+" : "−"}
                                </span>
                                <strong>{item.term}</strong>
                                <small>{item.impact >= 0 ? "toward spam" : "away from spam"}</small>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </section>
              </div>

              {batch.length > 0 && (
                <section className="card section-card">
                  <div className="section-heading">
                    <div>
                      <div className="card-kicker">BATCH ANALYSIS</div>
                      <h2>CSV scan results</h2>
                    </div>
                    <span className="count-pill">{batch.length} messages</span>
                  </div>
                  <div className="batch-table">
                    {batch.map((item, index) => (
                      <div className="batch-row" key={index}>
                        <span>{index + 1}</span>
                        <strong className={item.prediction}>{item.label}</strong>
                        <p>{item.risk_signals?.[0] || "No obvious heuristic signals."}</p>
                        <span>{item.risk_score}/100</span>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              <section className="card section-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">LINK ANALYSIS</div>
                    <h2>URL intelligence</h2>
                    <p>Inspect structural phishing indicators without opening the link.</p>
                  </div>
                  {urlResult && <span className={`count-pill ${riskClass(urlResult.risk_level)}`}>{urlResult.risk_level.toUpperCase()}</span>}
                </div>

                <div className="url-form">
                  <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="https://example.com/login" />
                  <button className="primary-button" onClick={analyzeUrl} disabled={loading || !url.trim()}>
                    {loading ? "Checking…" : "Analyze URL"}
                  </button>
                </div>

                {urlResult && (
                  <div className="url-result">
                    <div className="url-score">
                      <strong>{urlResult.risk_score}</strong>
                      <span>/100</span>
                    </div>
                    <div>
                      <strong className="breakable">{urlResult.hostname || "Unknown host"}</strong>
                      <p>{urlResult.signals?.length ? urlResult.signals.map((signal) => signal.detail).join(" · ") : "No obvious structural red flags detected."}</p>
                      <small>
                        Reputation: {urlResult.reputation?.status === "available"
                          ? `${urlResult.reputation.malicious || 0} malicious · ${urlResult.reputation.suspicious || 0} suspicious`
                          : "local heuristics only"}
                      </small>
                    </div>
                  </div>
                )}
              </section>

              {security && mailConfig.showAdvanced && (
                <section className="card section-card">
                  <div className="section-heading">
                    <div>
                      <div className="card-kicker">RAW EMAIL SECURITY</div>
                      <h2>Phishing intelligence</h2>
                      <p>Identity, authentication, HTML links, domain signals, and attachments.</p>
                    </div>
                    <span className={`count-pill ${riskClass(security.unified_threat?.risk_level)}`}>
                      {security.unified_threat?.threat_score ?? security.threat_score}/100
                    </span>
                  </div>

                  <div className="threat-grid">
                    <div><span>Unified threat</span><strong>{security.unified_threat?.threat_score ?? "—"}</strong></div>
                    <div><span>ML risk</span><strong>{security.unified_threat?.model_risk_score ?? "—"}</strong></div>
                    <div><span>Security heuristics</span><strong>{security.unified_threat?.security_heuristic_score ?? "—"}</strong></div>
                    <div><span>Signals</span><strong>{security.unified_threat?.signal_count ?? security.risk_signal_count}</strong></div>
                  </div>

                  <div className="identity-grid">
                    <div><span>Sender domain</span><strong>{security.sender_domain || "Unknown"}</strong></div>
                    <div><span>Reply-To</span><strong>{security.reply_to_domain || "Not provided"}</strong></div>
                    <div><span>Return-Path</span><strong>{security.return_path_domain || "Not provided"}</strong></div>
                    <div><span>Lookalike domains</span><strong>{security.lookalike_domains?.length || 0}</strong></div>
                  </div>

                  {security.signals?.length > 0 && (
                    <div className="report-section">
                      <div className="section-title">Security signals</div>
                      <div className="signal-list">
                        {security.signals.map((signal, index) => (
                          <div className="intel-row" key={index}>
                            <strong>{signal.type?.replaceAll("_", " ")}</strong>
                            <span>{signal.detail}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  <div className="intel-grid">
                    <div className="intel-panel">
                      <div className="section-title">Authentication</div>
                      <div className="auth-mini-grid">
                        {["spf", "dkim", "dmarc"].map((key) => (
                          <div className={security.headers?.authentication?.[key] === "pass" ? "auth-mini pass" : "auth-mini"} key={key}>
                            <span>{key.toUpperCase()}</span>
                            <strong>{header?.headers?.authentication?.[key] || "fail_or_unknown"}</strong>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="intel-panel">
                      <div className="section-title">HTML links</div>
                      <p>{security.html_analysis?.link_count ?? 0} link(s) inspected</p>
                      {security.html_analysis?.mismatches?.length ? (
                        security.html_analysis.mismatches.map((item, index) => (
                          <div className="mini-row" key={index}>
                            <strong>Destination mismatch</strong>
                            <span>{item.visible_host} → {item.destination_host}</span>
                          </div>
                        ))
                      ) : <div className="muted">No visible-link mismatches detected.</div>}
                    </div>

                    <div className="intel-panel">
                      <div className="section-title">Attachments</div>
                      <p>{security.attachment_analysis?.count ?? 0} attachment(s) inspected</p>
                      {security.attachment_analysis?.attachments?.length ? (
                        security.attachment_analysis.attachments.map((item, index) => (
                          <div className="mini-row" key={index}>
                            <strong>{item.filename}</strong>
                            <span>{item.content_type} · {(item.size_bytes / 1024).toFixed(1)} KB</span>
                          </div>
                        ))
                      ) : <div className="muted">No attachments detected.</div>}
                    </div>

                    <div className="intel-panel">
                      <div className="section-title">Domain intelligence</div>
                      <p>{security.unified_threat?.domain_intelligence?.hostname || security.sender_domain || "Sender domain"}</p>
                      {security.unified_threat?.domain_intelligence?.registration?.status === "available" ? (
                        <div className="mini-row">
                          <strong>RDAP</strong>
                          <span>
                            {security.unified_threat.domain_intelligence.registration.age_signal?.replaceAll("_", " ") || "available"}
                            {security.unified_threat.domain_intelligence.registration.created
                              ? ` · created ${new Date(security.unified_threat.domain_intelligence.registration.created).toLocaleDateString()}`
                              : ""}
                          </span>
                        </div>
                      ) : <div className="muted">Registration data unavailable.</div>}
                    </div>
                  </div>
                </section>
              )}
            </>
          )}

          {view === "history" && (
            <section className="page-section">
              <section className="dashboard-header">
                <div>
                  <span className="eyebrow">PERSONAL DATA</span>
                  <h1>Scan history</h1>
                  <p>Review the predictions saved to your authenticated account.</p>
                </div>
                <button className="secondary-button" onClick={loadAnalytics}>Refresh</button>
              </section>

              {analytics && (
                <>
                  <div className="analytics-grid">
                    <div><span>Total scans</span><strong>{analytics.total_scanned}</strong></div>
                    <div><span>Spam detected</span><strong>{analytics.spam_detected}</strong></div>
                    <div><span>Spam rate</span><strong>{analytics.spam_rate}%</strong></div>
                    <div><span>High risk</span><strong>{analytics.high_risk}</strong></div>
                  </div>

                  <section className="card section-card">
                    <div className="section-heading">
                      <div>
                        <div className="card-kicker">RECENT ACTIVITY</div>
                        <h2>Latest scans</h2>
                      </div>
                      <span className="count-pill">{analytics.recent?.length || 0}</span>
                    </div>
                    {analytics.recent?.length ? (
                      <div className="history-table">
                        {analytics.recent.map((item, index) => (
                          <div className="history-row" key={index}>
                            <span>{new Date(item.timestamp).toLocaleString()}</span>
                            <strong className={item.prediction}>{item.prediction === "spam" ? "SPAM" : "SAFE"}</strong>
                            <span>{item.risk_level}</span>
                            <span>{item.risk_score}/100</span>
                            <p>{item.preview}</p>
                          </div>
                        ))}
                      </div>
                    ) : <div className="empty-state short"><h3>No scans yet</h3><p>Run your first message analysis from the Scanner.</p></div>}
                  </section>
                </>
              )}
            </section>
          )}

          {view === "models" && (
            <section className="page-section">
              <section className="dashboard-header">
                <div>
                  <span className="eyebrow">MODEL OBSERVABILITY</span>
                  <h1>Model evaluation</h1>
                  <p>Compare benchmark results and inspect classifier error metrics.</p>
                </div>
                <button className="secondary-button" onClick={() => Promise.all([loadComparison(), loadEvaluationReports()])}>Refresh</button>
              </section>

              <section className="card section-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">BENCHMARK REPORTS</div>
                    <h2>Evaluation runs</h2>
                  </div>
                </div>
                <div className="model-list">
                  {evaluationReports?.reports && Object.entries(evaluationReports.reports).map(([key, item]) => (
                    <div className="model-card" key={key}>
                      <div>
                        <strong>{key.replaceAll("_", " ")}</strong>
                        <span>{item.dataset || "Evaluation report"}</span>
                      </div>
                      <div className="model-metrics">
                        <span>Accuracy <b>{formatPercent(item.accuracy)}</b></span>
                        <span>F1 <b>{formatPercent(item.f1)}</b></span>
                        <span>ROC-AUC <b>{formatPercent(item.roc_auc)}</b></span>
                      </div>
                    </div>
                  ))}
                </div>
                {!evaluationReports?.reports && <div className="empty-state short"><h3>No reports loaded</h3><p>Refresh to read the evaluation artifacts packaged with the backend.</p></div>}
              </section>

              <section className="card section-card">
                <div className="section-heading">
                  <div>
                    <div className="card-kicker">CLASSIFIER COMPARISON</div>
                    <h2>Error analysis</h2>
                  </div>
                </div>
                <div className="model-list">
                  {comparison?.metrics?.map((item) => (
                    <div className="model-card expanded" key={item.model}>
                      <div>
                        <strong>{item.model}</strong>
                        <span>UCI SMS Spam Collection · test split</span>
                      </div>
                      <div className="model-metrics">
                        <span>Precision <b>{formatPercent(item.precision)}</b></span>
                        <span>Recall <b>{formatPercent(item.recall)}</b></span>
                        <span>F1 <b>{formatPercent(item.f1)}</b></span>
                        <span>FP rate <b>{formatPercent(item.false_positive_rate)}</b></span>
                        <span>FN rate <b>{formatPercent(item.false_negative_rate)}</b></span>
                      </div>
                    </div>
                  ))}
                </div>
              </section>
            </section>
          )}
        </>
      )}

      <footer className="footer">
        <span>MailGuard AI</span>
        <span>Explainable NLP · phishing intelligence · secure scan history</span>
        <span>v4.0</span>
      </footer>
    </main>
  );
}
