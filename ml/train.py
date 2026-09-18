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
from sklearn.metrics import classification_report, accuracy_score, roc_auc_score

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
        df["text"],
        df["label"],
        test_size=0.20,
        random_state=42,
        stratify=df["label"],
    )

    model = build_model()
    print(f"Training on {len(X_train)} samples...")
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)
    probabilities = model.predict_proba(X_test)[:, list(model.classes_).index("spam")]

    print("\n=== Email Spam Classifier ===")
    print(f"Accuracy: {accuracy_score(y_test, predictions):.4f}")
    print(f"ROC-AUC:  {roc_auc_score((y_test == 'spam').astype(int), probabilities):.4f}")
    print("\nClassification Report:")
    print(classification_report(y_test, predictions))

    output = MODEL_DIR / "spam_classifier.joblib"
    joblib.dump(model, output)
    print(f"\nModel saved to: {output}")


if __name__ == "__main__":
    main()
