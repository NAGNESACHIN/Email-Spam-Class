from pathlib import Path
import io
import zipfile
import urllib.request
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.pipeline import FeatureUnion, Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.metrics import accuracy_score, roc_auc_score, precision_score, recall_score, f1_score, confusion_matrix

ROOT = Path(__file__).resolve().parents[1]
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
DATA_DIR.mkdir(exist_ok=True)
MODEL_DIR.mkdir(exist_ok=True)

DATA_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
ZIP_PATH = DATA_DIR / "sms_spam_collection.zip"
TXT_PATH = DATA_DIR / "SMSSpamCollection"


def download_dataset():
    if TXT_PATH.exists():
        return
    print("Downloading UCI SMS Spam Collection...")
    urllib.request.urlretrieve(DATA_URL, ZIP_PATH)
    with zipfile.ZipFile(ZIP_PATH, "r") as z:
        z.extractall(DATA_DIR)
    print(f"Dataset saved to {TXT_PATH}")


def load_data():
    df = pd.read_csv(
        TXT_PATH,
        sep="\\t",
        header=None,
        names=["label", "text"],
        encoding="utf-8",
        quoting=3,
    )
    df = df.dropna().drop_duplicates()
    df["label"] = df["label"].str.lower().str.strip()
    df["text"] = df["text"].astype(str)
    return df


def build_model():
    features = FeatureUnion([
        ("word", TfidfVectorizer(
            lowercase=True,
            strip_accents="unicode",
            sublinear_tf=True,
            min_df=2,
            max_df=0.98,
            ngram_range=(1, 2),
            max_features=60000,
        )),
        ("char", TfidfVectorizer(
            analyzer="char",
            sublinear_tf=True,
            min_df=2,
            ngram_range=(3, 5),
            max_features=40000,
        )),
    ])

    return Pipeline([
        ("features", features),
        ("classifier", LogisticRegression(
            max_iter=1500,
            class_weight="balanced",
            C=3.0,
        )),
    ])


def main():
    download_dataset()
    df = load_data()

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["label"], test_size=0.20, random_state=42, stratify=df["label"]
    )

    models = {
        "Logistic Regression": build_model(),
        "Multinomial Naive Bayes": Pipeline([
            ("features", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=80000)),
            ("classifier", MultinomialNB()),
        ]),
        "Linear SVM": Pipeline([
            ("features", TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=80000)),
            ("classifier", LinearSVC(class_weight="balanced", C=1.0)),
        ]),
    }

    comparison = []
    for name, candidate in models.items():
        print(f"Training {name} on {len(X_train)} samples...")
        candidate.fit(X_train, y_train)
        predictions = candidate.predict(X_test)

        if hasattr(candidate, "predict_proba"):
            probabilities = candidate.predict_proba(X_test)[:, list(candidate.classes_).index("spam")]
        else:
            probabilities = candidate.decision_function(X_test)

        spam_true = (y_test == "spam").astype(int)
        tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=["ham","spam"]).ravel()
        metrics = {
            "model": name,
            "accuracy": round(accuracy_score(y_test, predictions), 4),
            "precision": round(precision_score(y_test, predictions, pos_label="spam"), 4),
            "recall": round(recall_score(y_test, predictions, pos_label="spam"), 4),
            "f1": round(f1_score(y_test, predictions, pos_label="spam"), 4),
            "roc_auc": round(roc_auc_score(spam_true, probabilities), 4),
            "true_negative": int(tn), "false_positive": int(fp), "false_negative": int(fn), "true_positive": int(tp),
            "false_positive_rate": round(fp / (fp + tn), 4) if (fp + tn) else 0,
            "false_negative_rate": round(fn / (fn + tp), 4) if (fn + tp) else 0,
        }
        comparison.append(metrics)
        print(f"{name}: accuracy={metrics['accuracy']:.4f}, F1={metrics['f1']:.4f}, ROC-AUC={metrics['roc_auc']:.4f}")

    joblib.dump(models["Logistic Regression"], MODEL_DIR / "spam_classifier.joblib")
    import json
    (MODEL_DIR / "comparison_metrics.json").write_text(
        json.dumps({"dataset": "UCI SMS Spam Collection", "test_size": 0.20, "random_state": 42, "metrics": comparison}, indent=2)
    )
    print("\nPrimary model saved to models/spam_classifier.joblib")
    print("Comparison metrics saved to models/comparison_metrics.json")


if __name__ == "__main__":
    main()
