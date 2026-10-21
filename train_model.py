
from pathlib import Path

import joblib
import pandas as pd

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


data_path = Path("data/SMSSpamCollection/SMSSpamCollection")
model_path = Path("data/scam_lens_model.joblib")

if not data_path.exists():
    raise FileNotFoundError(
        "Dataset not found. Put SMSSpamCollection inside the data folder."
    )

messages = pd.read_csv(
    data_path,
    sep="\t",
    header=None,
    names=["label", "message"],
    encoding="utf-8"
)

messages = messages.dropna()
messages = messages[messages["label"].isin(["ham", "spam"])]
messages = messages.drop_duplicates(subset=["message"])

messages["label"] = messages["label"].map({
    "ham": 0,
    "spam": 1
})

train_text, test_text, train_labels, test_labels = train_test_split(
    messages["message"],
    messages["label"],
    test_size=0.2,
    random_state=42,
    stratify=messages["label"]
)

model = Pipeline([
    (
        "tfidf",
        TfidfVectorizer(
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=10000
        )
    ),
    (
        "classifier",
        LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=42
        )
    )
])

model.fit(train_text, train_labels)

predictions = model.predict(test_text)

print("Dataset size:", len(messages))
print("Training messages:", len(train_text))
print("Test messages:", len(test_text))

print("\nClassification report:")
print(
    classification_report(
        test_labels,
        predictions,
        labels=[0, 1],
        target_names=["ham", "spam"],
        zero_division=0
    )
)

print("Confusion matrix:")
print(confusion_matrix(test_labels, predictions, labels=[0, 1]))

model_path.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(model, model_path)

print("\nModel saved to:", model_path)
