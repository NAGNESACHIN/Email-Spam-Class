# Email Spam Classifier

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

## Architecture

Email text -> TF-IDF feature extraction -> Logistic Regression -> prediction + probability -> risk signals -> API response

## Project structure

```
Email-Spam-Class/
├── backend/
│   ├── __init__.py
│   └── main.py
├── ml/
│   └── train.py
├── data/
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

## Dataset & Evaluation\n\nThe baseline model uses the UCI SMS Spam Collection. This is a benchmark for the NLP pipeline, not a representative production email corpus. For deployment decisions, evaluate on a labeled email dataset with realistic phishing, transactional, marketing, and legitimate messages, while keeping train/test sources separated to avoid leakage.\n\nRun model comparison with:\n\n```bash\npython ml/train.py\n```\n\nThis produces `models/comparison_metrics.json` containing accuracy, precision, recall, F1, and ROC-AUC for Logistic Regression, Multinomial Naive Bayes, and Linear SVM.\n\n## Important note

The initial training dataset is the UCI SMS Spam Collection. It is useful for establishing the NLP pipeline, but the next project phase should add a genuine email corpus and email-specific header/URL features before claiming production-grade email filtering performance.

## Roadmap

- [ ] React frontend
- [ ] Email header parsing
- [ ] URL reputation/risk analysis
- [ ] Explainable token highlighting
- [ ] Batch CSV prediction
- [ ] Model comparison dashboard
- [ ] Authentication and prediction history
- [ ] Docker deployment
- [ ] Production email dataset evaluation
