# MailGuard AI — Explainable Email Security

An explainable NLP-based email spam classification system using TF-IDF, Logistic Regression, FastAPI, and a risk-signal engine.

## Features

- Spam / Not Spam classification
- Spam probability and confidence
- Risk-level assessment
- Explainable rule-based risk signals
- Word and character TF-IDF features
- Class-balanced Logistic Regression
- REST API with FastAPI
- UCI SMS Spam Collection dataset
- Clean separation between ML training and API serving
- Raw `.eml` header, authentication, HTML link, and attachment analysis
- URL risk intelligence, optional VirusTotal reputation, and lookalike-domain detection
- Unified 0–100 email threat score
- User authentication and personal scan history
- Batch CSV scanning
- Model comparison and evaluation dashboard
- Docker deployment configuration

## Architecture

Email / raw .eml → NLP classification → URL intelligence → header/authentication checks → phishing heuristics → threat score → explainable security report

## Project structure

```
Email-Spam-Class/
├── backend/
│   ├── __init__.py
│   ├── main.py
│   ├── auth.py
├── ml/
│   └── train.py
├── data/
├── frontend/
├── models/
├── requirements.txt
├── run.py
└── README.md
```

## Run locally

### 1. Create a virtual environment

```bash
python -m venv .venv
```

Windows:
```bash
.venv\\Scripts\\activate
```

macOS/Linux:
```bash
source .venv/bin/activate
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Train the model

```python
python ml/train.py
```

The training script downloads the UCI SMS Spam Collection, trains the model, prints accuracy/ROC-AUC/classification metrics, and saves `models/spam_classifier.joblib`.

### 4. Start the API

```bash
uvicorn backend.main:app --reload
```

API docs:
- `/docs`
- `/redoc`

### 5. Test prediction

POST to `/predict`:

```json
{
  "text": "Congratulations! You have won a free prize. Click here now!"
}
```

## Dataset & Evaluation

The baseline model uses the UCI SMS Spam Collection. This is a benchmark for the NLP pipeline, not a representative production email corpus. For deployment decisions, evaluate on a labeled email dataset with realistic phishing, transactional, marketing, and legitimate messages, while keeping train/test sources separated to avoid leakage.

Run model comparison with:

```bash
python ml/train.py
```

This produces `models/comparison_metrics.json` containing accuracy, precision, recall, F1, ROC-AUC, false-positive rate, false-negative rate, and confusion-matrix counts for Logistic Regression, Multinomial Naive Bayes, and Linear SVM.

### Email-domain benchmark

UCI Spambase is available as an engineered-feature email benchmark. Run:

```bash
python ml/train.py --spambase
```

This writes `models/spambase_evaluation_report.json`. Spambase is useful for validating an email-oriented classifier pipeline, but its 57 numeric features are not raw email text, so its results must not be presented as direct validation of the raw-email NLP classifier.

### Custom labeled email corpus

For a representative email evaluation, provide a CSV with exactly these required columns:

```text
label,text
ham,"Your order has shipped..."
spam,"Urgent: verify your account..."
```

Then run:

```bash
python ml/train.py --email-dataset data/email_dataset.csv
```

The evaluator performs a stratified 80/20 holdout split and writes `models/email_evaluation_report.json`. Keep messages or source campaigns separated across train/test when constructing the dataset to reduce duplicate/template leakage.

## Important note

The initial training dataset is the UCI SMS Spam Collection. It is useful for establishing the NLP pipeline, but the next project phase should add a genuine email corpus and email-specific header/URL features before claiming production-grade email filtering performance.

## Roadmap

- [x] React frontend
- [x] Email header parsing
- [x] URL risk analysis
- [x] Explainable model evidence
- [x] Batch CSV prediction
- [x] Model comparison dashboard
- [x] Authentication and prediction history
- [x] Docker deployment configuration
- [x] Unified phishing threat score
- [x] Email benchmark evaluation tooling (UCI Spambase + custom labeled-email CSV)
- [x] Raw-email benchmark evaluation with Apache SpamAssassin Public Corpus
- [ ] Representative current real-world labeled email dataset evaluation
- [x] HTML phishing link mismatch and attachment-risk analysis
- [x] Optional VirusTotal URL reputation integration
- [x] Automated API/frontend test suite
- [ ] Production deployment

## Advanced evaluation

For a labeled raw-email CSV with `label,text`, evaluate the email model with:

```bash
python ml/train.py --email-dataset data/email_dataset.csv
```

If the dataset contains a campaign/source column, use grouped evaluation to reduce template or campaign leakage:

```bash
python ml/train.py --email-dataset data/email_dataset.csv --group-column campaign_id
```

The report records the split strategy. A grouped split is preferred when multiple messages can originate from the same campaign, sender batch, or template family.

## Production security checklist

- Set a unique 32+ character `JWT_SECRET` in production.
- Use PostgreSQL rather than SQLite for multi-instance deployments.
- Set explicit production `CORS_ORIGINS` and serve the frontend/API over HTTPS.
- Keep VirusTotal and other threat-intelligence credentials in the deployment secret manager.
- Put rate limiting behind a shared Redis/store when running multiple API instances.
- Do not execute uploaded attachments or fetch arbitrary user-controlled URLs.
- Treat the SMS-trained model as a baseline until representative labeled email evaluation is available.

## Production notes

Set `JWT_SECRET`, `DATABASE_URL`, `CORS_ORIGINS`, and `VITE_API_URL` through deployment secrets/environment variables. Do not commit `.env` files or production credentials. The current ML baseline is trained on the UCI SMS Spam Collection and should not be presented as production-grade email-filtering performance until a representative labeled email corpus has been evaluated.


## Optional threat intelligence

MailGuard can optionally enrich URL analysis with VirusTotal reputation data when `VIRUSTOTAL_API_KEY` is configured. The integration is disabled when no key is present, so the application remains functional without an external provider. VirusTotal exposes URL reports containing multi-engine analysis statistics and reputation context. See the official API documentation for current quota and usage terms.


## Production deployment

Backend deployment variables:
- ENVIRONMENT=production
- JWT_SECRET=<long random secret>
- DATABASE_URL=<PostgreSQL connection string>
- CORS_ORIGINS=<frontend origin>
- VIRUSTOTAL_API_KEY=<optional URL reputation key>

Frontend build variable:
- VITE_API_URL=<public backend API URL>

Run pytest and the frontend production build before deployment. Never commit production secrets or .env files.


### Domain intelligence

MailGuard can optionally enrich sender domains with public RDAP registration metadata, including registration date and domain-age signals. RDAP is the standardized replacement for WHOIS for gTLD registration data. Set `RDAP_LOOKUP_ENABLED=false` to disable live lookups.

For production deployments, configure PostgreSQL with `DATABASE_URL`, a strong `JWT_SECRET`, explicit `CORS_ORIGINS`, and appropriate database pool settings.
