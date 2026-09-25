from pathlib import Path
import io
import zipfile
import tarfile
import urllib.request
from email import policy
from email.parser import BytesParser
import pandas as pd
import joblib
import json

from sklearn.model_selection import train_test_split, StratifiedGroupKFold
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
SPAMBASE_URL = "https://archive.ics.uci.edu/static/public/94/spambase.zip"
SPAMBASE_ZIP = DATA_DIR / "spambase.zip"
SPAMBASE_DATA = DATA_DIR / "spambase.data"
ZIP_PATH = DATA_DIR / "sms_spam_collection.zip"
TXT_PATH = DATA_DIR / "SMSSpamCollection"
EMAIL_DATASET = DATA_DIR / "email_dataset.csv"


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


def download_spambase():
    if SPAMBASE_DATA.exists(): return
    print('Downloading UCI Spambase...')
    urllib.request.urlretrieve(SPAMBASE_URL, SPAMBASE_ZIP)
    with zipfile.ZipFile(SPAMBASE_ZIP, 'r') as z:
        members=[m for m in z.namelist() if m.endswith('spambase.data')]
        if not members: raise FileNotFoundError('spambase.data not found in UCI archive')
        with z.open(members[0]) as source, open(SPAMBASE_DATA, 'wb') as target: target.write(source.read())

def evaluate_spambase():
    download_spambase()
    df=pd.read_csv(SPAMBASE_DATA,header=None); X=df.iloc[:,:-1]; y=df.iloc[:,-1].astype(int)
    X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=0.20,random_state=42,stratify=y)
    from sklearn.ensemble import RandomForestClassifier
    candidate=RandomForestClassifier(n_estimators=300,random_state=42,class_weight='balanced',n_jobs=-1)
    candidate.fit(X_train,y_train); pred=candidate.predict(X_test); prob=candidate.predict_proba(X_test)[:,1]
    tn,fp,fn,tp=confusion_matrix(y_test,pred).ravel()
    report={'dataset':'UCI Spambase','instances':int(len(df)),'features':int(X.shape[1]),'model':'Random Forest',
      'accuracy':round(accuracy_score(y_test,pred),4),'precision':round(precision_score(y_test,pred),4),
      'recall':round(recall_score(y_test,pred),4),'f1':round(f1_score(y_test,pred),4),'roc_auc':round(roc_auc_score(y_test,prob),4),
      'true_negative':int(tn),'false_positive':int(fp),'false_negative':int(fn),'true_positive':int(tp)}
    (MODEL_DIR/'spambase_evaluation_report.json').write_text(json.dumps(report,indent=2)); print(json.dumps(report,indent=2)); return report
SPAMASSASSIN_DIR = DATA_DIR / "spamassassin_corpus"
SPAMASSASSIN_URLS = {
    "easy_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_easy_ham.tar.bz2",
    "hard_ham": "https://spamassassin.apache.org/old/publiccorpus/20030228_hard_ham.tar.bz2",
    "spam": "https://spamassassin.apache.org/old/publiccorpus/20030228_spam.tar.bz2",
}

def _extract_mail_text(raw: bytes):
    msg=BytesParser(policy=policy.default).parsebytes(raw)
    parts=[]
    if msg.get("Subject"):
        parts.append("Subject: "+str(msg.get("Subject")))
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type()=="text/plain":
                try:
                    parts.append(part.get_content())
                except Exception:
                    pass
    else:
        try:
            parts.append(msg.get_content())
        except Exception:
            pass
    return "\n".join(x for x in parts if x).strip()

def download_spamassassin_corpus():
    SPAMASSASSIN_DIR.mkdir(exist_ok=True)
    for label,url in SPAMASSASSIN_URLS.items():
        archive=SPAMASSASSIN_DIR/f"{label}.tar.bz2"
        target=SPAMASSASSIN_DIR/label
        if target.exists() and any(target.rglob("*")):
            continue
        print(f"Downloading SpamAssassin {label}...")
        urllib.request.urlretrieve(url, archive)
        target.mkdir(exist_ok=True)
        with tarfile.open(archive,"r:bz2") as tar:
            tar.extractall(target, filter="data")

def evaluate_spamassassin():
    download_spamassassin_corpus()
    rows=[]
    for label in ("easy_ham","hard_ham","spam"):
        normalized="spam" if label=="spam" else "ham"
        for path in (SPAMASSASSIN_DIR/label).rglob("*"):
            if path.is_file() and not path.name.startswith("."):
                try:
                    text=_extract_mail_text(path.read_bytes())
                    if text:
                        rows.append({"label":normalized,"text":text,"source":label})
                except Exception:
                    continue
    df=pd.DataFrame(rows).drop_duplicates(subset=["text"])
    if df["label"].nunique()<2:
        raise ValueError("SpamAssassin corpus did not contain both classes.")
    X_train,X_test,y_train,y_test=train_test_split(
        df["text"],df["label"],test_size=0.20,random_state=42,stratify=df["label"]
    )
    candidate=build_model()
    candidate.fit(X_train,y_train)
    predictions=candidate.predict(X_test)
    probabilities=candidate.predict_proba(X_test)[:,list(candidate.classes_).index("spam")]
    spam_true=(y_test=="spam").astype(int)
    tn,fp,fn,tp=confusion_matrix(y_test,predictions,labels=["ham","spam"]).ravel()
    report={
        "dataset":"Apache SpamAssassin Public Corpus (20030228)",
        "samples":int(len(df)),
        "train_samples":int(len(X_train)),
        "test_samples":int(len(X_test)),
        "class_counts":{str(k):int(v) for k,v in df["label"].value_counts().items()},
        "model":"Logistic Regression",
        "split_strategy":"stratified_random",
        "accuracy":round(accuracy_score(y_test,predictions),4),
        "precision":round(precision_score(y_test,predictions,pos_label="spam"),4),
        "recall":round(recall_score(y_test,predictions,pos_label="spam"),4),
        "f1":round(f1_score(y_test,predictions,pos_label="spam"),4),
        "roc_auc":round(roc_auc_score(spam_true,probabilities),4),
        "true_negative":int(tn),"false_positive":int(fp),
        "false_negative":int(fn),"true_positive":int(tp),
        "false_positive_rate":round(fp/(fp+tn),4) if fp+tn else 0,
        "false_negative_rate":round(fn/(fn+tp),4) if fn+tp else 0
    }
    (MODEL_DIR/"spamassassin_evaluation_report.json").write_text(json.dumps(report,indent=2))
    print(json.dumps(report,indent=2))
    return report

def load_email_dataset(path=EMAIL_DATASET):
    if not path.exists():
        raise FileNotFoundError(
            f"Email dataset not found: {path}. Expected CSV columns: label,text"
        )
    df = pd.read_csv(path)
    required = {"label", "text"}
    if not required.issubset(df.columns):
        raise ValueError("Email dataset must contain CSV columns: label,text")
    df = df[["label", "text"]].dropna().drop_duplicates()
    df["label"] = df["label"].astype(str).str.lower().str.strip().replace({
        "1":"spam", "0":"ham", "not spam":"ham", "legitimate":"ham"
    })
    df["text"] = df["text"].astype(str)
    df = df[df["label"].isin(["spam","ham"])]
    if df["label"].nunique() < 2:
        raise ValueError("Email dataset must contain both spam and ham labels.")
    return df

def evaluate_email_dataset(path=EMAIL_DATASET, group_column=None):
    df = load_email_dataset(Path(path))
    split_strategy = "stratified_random"
    if group_column:
        raw = pd.read_csv(path)
        if group_column not in raw.columns:
            raise ValueError(f"Group column not found: {group_column}")
        groups = raw.loc[df.index, group_column].astype(str).fillna("")
        if groups.nunique() < 2:
            raise ValueError("Group column must contain at least two distinct groups.")
        splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
        train_idx, test_idx = next(splitter.split(df["text"], df["label"], groups))
        X_train, X_test = df["text"].iloc[train_idx], df["text"].iloc[test_idx]
        y_train, y_test = df["label"].iloc[train_idx], df["label"].iloc[test_idx]
        split_strategy = f"stratified_group:{group_column}"
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            df["text"], df["label"], test_size=0.20, random_state=42, stratify=df["label"]
        )
    candidate = build_model()
    candidate.fit(X_train, y_train)
    predictions = candidate.predict(X_test)
    probabilities = candidate.predict_proba(X_test)[:, list(candidate.classes_).index("spam")]
    spam_true = (y_test == "spam").astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, predictions, labels=["ham","spam"]).ravel()
    report = {
        "dataset": str(Path(path)),
        "samples": int(len(df)),
        "train_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "class_counts": {str(k): int(v) for k,v in df["label"].value_counts().items()},
        "model": "Logistic Regression",
        "split_strategy": split_strategy,
        "accuracy": round(accuracy_score(y_test,predictions),4),
        "precision": round(precision_score(y_test,predictions,pos_label="spam"),4),
        "recall": round(recall_score(y_test,predictions,pos_label="spam"),4),
        "f1": round(f1_score(y_test,predictions,pos_label="spam"),4),
        "roc_auc": round(roc_auc_score(spam_true,probabilities),4),
        "true_negative": int(tn), "false_positive": int(fp),
        "false_negative": int(fn), "true_positive": int(tp),
        "false_positive_rate": round(fp/(fp+tn),4) if fp+tn else 0,
        "false_negative_rate": round(fn/(fn+tp),4) if fn+tp else 0
    }
    (MODEL_DIR / "email_evaluation_report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))
    return report

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
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--email-dataset", type=str, help="CSV with label,text for real-email evaluation")
    parser.add_argument("--group-column", type=str, help="Optional email campaign/source column used for leakage-safe grouped evaluation")
    parser.add_argument("--spambase", action="store_true", help="Evaluate the UCI Spambase email benchmark")
    parser.add_argument("--spamassassin", action="store_true", help="Evaluate the Apache SpamAssassin raw-email corpus")
    args = parser.parse_args()
    if args.spamassassin:
        evaluate_spamassassin()
    elif args.spambase:
        evaluate_spambase()
    elif args.email_dataset:
        evaluate_email_dataset(args.email_dataset, args.group_column)
    else:
        main()
