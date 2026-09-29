# MailGuard AI Dataset Card

## Production dataset

**Apache SpamAssassin Public Corpus (20030228)**

- Task: binary email spam classification
- Labels: `spam`, `ham`
- Input: raw email messages
- Processing: RFC/MIME parsing; subject and plain-text parts are extracted
- Training split: 80%
- Test split: 20%
- Stratification: by spam/ham label
- Random seed: 42

## Provenance

Dataset source: https://spamassassin.apache.org/old/publiccorpus/

The official corpus directory lists the 20030228 easy-ham, hard-ham, and spam archives. The corpus is maintained as part of the Apache SpamAssassin project. citeturn0search0turn0search3

## Limitations

The corpus is historical and may not represent modern phishing, business-email compromise, multilingual mail, current marketing patterns, or adversarial spam. Results on this corpus should therefore be described as a benchmark, not proof of current real-world performance.

The raw corpus is downloaded during training rather than committed to Git.

## Reproducibility

```bash
python ml/train.py
```

The script downloads the corpus, parses messages, trains Logistic Regression, Multinomial Naive Bayes, and Linear SVM candidates, saves the Logistic Regression model as the production classifier, and records evaluation metrics.

For the legacy SMS benchmark:

```bash
python ml/train.py --sms-benchmark
```
