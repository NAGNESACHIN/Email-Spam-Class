import { useState } from "react";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const samples = {
  spam: "Congratulations! You have won a FREE cash prize. Click http://bit.ly/reward now to claim your reward!",
  safe: "Hi team, the meeting has been moved to 3 PM tomorrow. Please review the attached agenda before the call."
};

export default function App() {
  const [text,setText]=useState(""); const [result,setResult]=useState(null);
  const [loading,setLoading]=useState(false); const [error,setError]=useState("");

  async function analyze(){
    if(!text.trim()) return; setLoading(true); setError(""); setResult(null);
    try{
      const r=await fetch(API_URL+"/predict",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({text})});
      const d=await r.json(); if(!r.ok||d.error) throw new Error(d.detail||d.error||"Prediction failed"); setResult(d);
    }catch(e){setError(e.message+". Check that the FastAPI server is running.");}finally{setLoading(false);}
  }

  return <main className="shell">
    <nav className="nav"><div className="brand"><span className="brand-mark">✉</span><span>MailGuard <b>AI</b></span></div><span className="status"><i/> AI engine ready</span></nav>
    <section className="hero"><div className="eyebrow">INTELLIGENT EMAIL SECURITY</div>
      <h1>Know what’s in your inbox<br/><span>before you click.</span></h1>
      <p>Analyze suspicious messages with NLP-powered classification, confidence scoring, URL inspection, and actionable risk signals.</p>
    </section>
    <section className="workspace">
      <div className="card composer"><div className="card-head"><div><h2>Analyze an email</h2><p>Paste the message content below.</p></div><span className="pill">NLP</span></div>
        <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Paste an email, SMS, or message here..."/>
        <div className="samples"><span>Try a sample:</span><button onClick={()=>setText(samples.spam)}>Spam</button><button onClick={()=>setText(samples.safe)}>Safe</button></div>
        <button className="analyze" onClick={analyze} disabled={loading||!text.trim()}>{loading?"Analyzing…":"Analyze message →"}</button>
        {error&&<div className="error">{error}</div>}
      </div>
      <div className="card result">{!result?<div className="empty"><div className="shield">◈</div><h2>Your result will appear here</h2><p>We’ll classify the message and show its complete risk profile.</p></div>:
        <><div className="card-head"><div><h2>Security analysis</h2><p>Prediction, risk score and URL intelligence.</p></div><span className={`badge ${result.prediction}`}>{result.label}</span></div>
          <div className="score"><div><small>RISK SCORE</small><strong>{result.risk_score}<em>/100</em></strong></div><div className={`risk ${result.risk_level}`}>{result.risk_level.toUpperCase()} RISK</div></div>
          <div className="meter"><span style={{width:`${result.risk_score}%`}}/></div>
          <div className="stats"><div><small>SPAM PROBABILITY</small><b>{result.spam_probability}%</b></div><div><small>CONFIDENCE</small><b>{result.confidence}%</b></div><div><small>URLS FOUND</small><b>{result.url_analysis?.url_count??0}</b></div></div>
          <div className="signals"><h3>Risk signals</h3>{result.risk_signals.length?result.risk_signals.map((s,i)=><div className="signal" key={i}><span>!</span>{s}</div>):<div className="signal safe-signal"><span>✓</span>No obvious risk signals detected.</div>}</div>
          {result.explanation?.length>0&&<div className="signals explanation"><h3>Why the model decided this</h3><div className="evidence">{result.explanation.map((x,i)=><div className="evidence-item" key={i}><span>{x.impact>=0?"+":"−"}</span><b>{x.term}</b><small>{x.impact>=0?"pushes toward spam":"pushes away from spam"}</small></div>)}</div></div>}
          {result.url_analysis?.suspicious_urls?.length>0&&<div className="signals urls"><h3>Suspicious URLs</h3>{result.url_analysis.suspicious_urls.map((u,i)=><div className="signal" key={i}><span>↗</span><div><b>{u.url}</b><small>{u.reasons.join(" · ")}</small></div></div>)}</div>}
        </>}
      </div>
    </section>
    <footer>MailGuard AI · Explainable NLP spam detection · v2.0</footer>
  </main>;
}