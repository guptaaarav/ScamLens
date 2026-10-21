
from detector import analyse_message


messages = [
    "URGENT: Your bank account will be blocked. Share your OTP now.",
    "Congratulations! You have won a prize. Claim it today.",
    "Your monthly bank statement is available in your banking app.",
    "Please transfer the money immediately to confirm your payment.",
    "Hey, are we still meeting at 5 pm today?"
]


for message in messages:
    result = analyse_message(message)

    print("\nMessage:", message)
    print("Rule-based risk:", result["risk_level"])
    print("Detection score:", result["score"])
    print("Evidence:")

    if result["signals"]:
        for signal in result["signals"]:
            print("-", signal["evidence"], ":", signal["explanation"])
    else:
        print("- No configured warning signs found")
