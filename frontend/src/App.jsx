import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const samples = {
  spam: "Congratulations! You have won a FREE cash prize. Click https://example.com now to claim your reward!",
  safe: "Hi team, the meeting has been moved to 3 PM tomorrow. Please review the attached agenda before the call."
};

export default function App() {
  const [text, setText] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  async function analyze() {
    if (!text.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text })
      });
      const data = await response.json();
      if (!response.ok || data.error) throw new Error(data.error || "Prediction failed");
      setResult(data);
    } catch (err) {
      setError(err.message + ". Check that the FastAPI server is running.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="shell">
      <nav className="nav">
        <div className="brand"><span className="brand-mark">✉</span><span>MailGuard <b>AI</b></span></div>
        <span className="status"><i /> AI engine ready</span>
      </nav>

      <section className="hero">
        <div className="eyebrow">INTELLIGENT EMAIL SECURITY</div>
        <h1>Know what’s in your inbox<br/><span>before you click.</span></h1>
        <p>Analyze suspicious messages with NLP-powered spam detection, confidence scoring, and actionable risk signals.</p>
      </section>

      <section className="workspace">
        <div className="card composer">
          <div className="card-head"><div><h2>Analyze an email</h2><p>Paste the message content below.</p></div><span className="pill">NLP</span></div>
          <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Paste an email, SMS, or message here..." />
          <div className="samples">
            <span>Try a sample:</span>
            <button onClick={()=>setText(samples.spam)}>Spam</button>
            <button onClick={()=>setText(samples.safe)}>Safe</button>
          </div>
          <button className="analyze" onClick={analyze} disabled={loading || !text.trim()}>
            {loading ? "Analyzing…" : "Analyze message →"}
          </button>
          {error && <div className="error">{error}</div>}
        </div>

        <div className="card result">
          {!result ? (
            <div className="empty"><div className="shield">◈</div><h2>Your result will appear here</h2><p>We’ll classify the message and show its risk profile.</p></div>
          ) : (
            <>
              <div className="card-head"><div><h2>Analysis result</h2><p>Model prediction and security signals.</p></div><span className={`badge ${result.prediction}`}>{result.label}</span></div>
              <div className="score"><div><small>SPAM PROBABILITY</small><strong>{result.spam_probability}%</strong></div><div className={`risk ${result.risk_level}`}>{result.risk_level.toUpperCase()} RISK</div></div>
              <div className="meter"><span style={{width: `${result.spam_probability}%`}} /></div>
              <div className="signals"><h3>Risk signals</h3>{result.risk_signals.length ? result.risk_signals.map((s,i)=><div className="signal" key={i}><span>!</span>{s}</div>) : <div className="signal safe-signal"><span>✓</span>No obvious rule-based risk signals detected.</div>}</div>
              <div className="confidence">Model confidence <b>{result.confidence}%</b></div>
            </>
          )}
        </div>
      </section>

      <footer>MailGuard AI · Explainable NLP spam detection</footer>
    </main>
  );
}