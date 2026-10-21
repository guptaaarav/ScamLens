
import joblib
from pathlib import Path


model_path = Path("data/scam_lens_model.joblib")
model = joblib.load(model_path)

messages = [
    "URGENT: Your bank account will be blocked. Share your OTP now.",
    "Congratulations! You have won a prize. Claim it today.",
    "Your monthly bank statement is available in your banking app.",
    "Please transfer the money immediately to confirm your payment.",
    "Hey, are we still meeting at 5 pm today?"
]

for message in messages:
    prediction = model.predict([message])[0]
    probabilities = model.predict_proba([message])[0]

    label = "Spam" if prediction == 1 else "Ham"
    confidence = max(probabilities) * 100

    print("\nMessage:", message)
    print("Prediction:", label)
    print(f"Model confidence: {confidence:.1f}%")
