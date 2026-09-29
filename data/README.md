# Real-world labeled email dataset

MailGuard AI uses the **Apache SpamAssassin Public Corpus (20030228)** as its production training corpus.

## Source

Official Apache SpamAssassin public corpus:
https://spamassassin.apache.org/old/publiccorpus/

The training script downloads these labeled archives automatically:
- `20030228_easy_ham.tar.bz2` -> `ham`
- `20030228_hard_ham.tar.bz2` -> `ham`
- `20030228_spam.tar.bz2` -> `spam`

The corpus contains raw email messages, which are parsed into subject + plain-text content before training.

## Training

From the repository root:

```bash
python ml/train.py
```

The production model is written to `models/spam_classifier.joblib` and metrics to `models/comparison_metrics.json`.

## Benchmark

The UCI SMS Spam Collection is retained as an optional legacy benchmark:

```bash
python ml/train.py --sms-benchmark
```

It is not the default production training source.

## Important limitation

The SpamAssassin corpus is historical public data. A production deployment should eventually be refreshed with newer, permissioned/consented email data to address concept drift.
