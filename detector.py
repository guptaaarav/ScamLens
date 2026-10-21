
import re
from urllib.parse import urlparse

#rules have all the warning patterns and the weights. 
rules = [
    
    {
        "name": "otp_request",
        "patterns": [
            r"\bshare (?:your )?(?:otp|pin|password)\b",
            r"\b(?:send|provide|reveal|tell) (?:me )?(?:your )?(?:otp|pin|password)\b",
            r"\benter (?:your )?(?:otp|pin|password)\b",
            r"\bconfirm (?:your )?(?:otp|pin|password)\b",
            r"\b(?:otp|pin|password).{0,30}\b(?:share|send|provide|reveal)\b"
        ],
        "weight": 5,
        "explanation": "The message asks the recipient to disclose or enter sensitive login information."
    },

    {
        "name": "urgent_language",
        "patterns": [
            r"\burgent\b",
            r"\bimmediately\b",
            r"\bact now\b",
            r"\baccount.{0,30}\bblocked\b",
            r"\baccount.{0,30}\bsuspended\b"
        ],
        "weight": 2,
        "explanation": "The message uses urgency or threatens account access."
    },
    {
        "name": "payment_request",
        "patterns": [
            r"\btransfer (?:the )?money\b",
            r"\bsend (?:the )?money\b",
            r"\bpay immediately\b",
            r"\bmake a payment of\b",
            r"\bdeposit (?:a )?(?:fee|charge|fine)\b"
            r"\bpay (?:a )?(?:fee|charge|fine)\b"
        ],
        "weight": 3,
        "explanation": "The message asks for money or an urgent payment."
    },
    {
        "name": "suspicious_reward",
        "patterns": [
            r"\byou have won\b",
            r"\bclaim your prize\b",
            r"\bguaranteed returns?\b",
            r"\bdouble your money\b"
        ],
        "weight": 3,
        "explanation": "The message mentions a prize, which in most cases is unsafe. Varify with the organisation mentioned."
    },
    {
        "name": "account_verification",
        "patterns": [
            r"\bverify your account\b",
            r"\bconfirm your account\b",
            r"\bupdate your kyc\b"
        ],
        "weight": 2,
        "explanation": "The message asks the recipient to verify account details."
    },

    {
        "name": "payment_deadline",
        "patterns": [
            r"\bwithin \d+\s*(?:hours?|days?)\b",
            r"\b(?:final|last) notice\b",
            r"\b(?:pay|payment|fine).{0,40}\b(?:deadline|due)\b",
            r"\bdeadline to pay\b"
        ],
        "weight": 2,
        "explanation": "The message uses a payment deadline or time pressure."
    },
    {
        "name": "fine_or_penalty",
        "patterns": [
            r"\byou have been fined\b",
            r"\bpay (?:this|the) fine\b",
            r"\bpenalty for failing to\b",
            r"\bunpaid (?:fine|toll|fee)\b"
        ],
        "weight": 3,
        "explanation": "The message claims a fine or penalty must be paid."
    },
    {
        "name": "login_link_request",
        "patterns": [
            r"\blog in below\b",
            r"\blog in (?:here|using this link)\b",
            r"\bclick (?:the )?link to (?:pay|verify|claim)\b",
            r"\bpay (?:the )?fine (?:here|online)\b"
        ],
        "weight": 2,
        "explanation": "The message directs the recipient to a link to log in or make a payment."
    },

    
]

#find_urls extracts links from the message. 
def find_urls(message):
    pattern = r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
    matches = re.findall(pattern, message)

    return [url.rstrip(".,!?;:)]}") for url in matches]

#This checks the url without opening it. It checks for common safeguards such as https and host name
def check_url(url):
    normalised = url if "://" in url else "https://" + url
    parsed = urlparse(normalised)
    host = (parsed.hostname or "").lower()
    warnings = []

    shortener_domains = {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "shorturl.at",
        "is.gd",
        "cutt.ly",
        "rebrand.ly"
    }

    if host in shortener_domains:
        warnings.append(
            "The URL uses a shortening service that obscures its destination."
        )


    if not host:
        warnings.append("The destination could not be identified.")
        return warnings

    if parsed.username or parsed.password:
        warnings.append("The URL contains user-information fields.")

    if host.startswith("xn--") or ".xn--" in host:
        warnings.append("The domain contains an encoded domain label.")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host):
        warnings.append("The URL uses an IP address as its host.")

    if host.count(".") >= 4:
        warnings.append("The URL has an unusually large number of subdomains.")

    return warnings


def is_safety_warning(message):
    warning_patterns = [
        r"\bnever\s+(?:ever\s+)?(?:share|give|reveal|disclose)\s+(?:your\s+)?(?:otp|pin|password)\b",
        r"\bdo not\s+(?:share|give|reveal|disclose)\s+(?:your\s+)?(?:otp|pin|password)\b",
        r"\bdon't\s+(?:share|give|reveal|disclose)\s+(?:your\s+)?(?:otp|pin|password)\b"
    ]

    return any(
        re.search(pattern, message, re.IGNORECASE)
        for pattern in warning_patterns
    )


#this finds matching patterns, adds their weights and returns the result. 
def analyse_message(message):
    if not isinstance(message, str) or not message.strip():
        raise ValueError("Enter a message before analysing it.")

    signals = []
    score = 0

    for rule in rules:
        evidence = []

        for pattern in rule["patterns"]:
            for match in re.finditer(pattern, message, re.IGNORECASE):
                phrase = match.group(0)

                if phrase not in evidence:
                    evidence.append(phrase)

       
        
        if evidence and not (
            rule["name"] == "otp_request"
            and is_safety_warning(message)
        ):
            score += rule["weight"]
            signals.append({
                "type": rule["name"],
                "evidence": evidence,
                "explanation": rule["explanation"]
            })


    urls = find_urls(message)

    for url in urls:
        warnings = check_url(url)

        if warnings:
            score += 2
            signals.append({
                "type": "url_warning",
                "evidence": [url],
                "explanation": " ".join(warnings)
            })

    if score >= 7:
        risk_level = "High"
    elif score >= 3:
        risk_level = "Medium"
    elif score > 0:
        risk_level = "Low"
    else:
        risk_level = "Uncertain"

    if signals:
        recommendation = (
            "Do not share passwords, PINs or OTPs. Verify the "
            "request through the organisation's official app, "
            "website or a trusted phone number."
        )
    else:
        recommendation = (
            "No configured warning signs were found. This does "
            "not prove the message is genuine. Check the sender "
            "and verify any request independently."
        )

    return {
        "risk_level": risk_level,
        "score": score,
        "signals": signals,
        "urls": urls,
        "recommendation": recommendation

    
    }


if __name__ == "__main__":
    print("ScamLens Message Analyzer")
    print("Type 'quit' to close the program.")

    while True:
        message = input("\nEnter a message: ")

        if message.strip().lower() == "quit":
            break

        try:
            result = analyse_message(message)
        except ValueError as error:
            print(error)
            continue

        print("\nRisk level:", result["risk_level"])
        print("Detection score:", result["score"])

        for signal in result["signals"]:
            print("\nWarning:", signal["type"])
            print("Evidence:", ", ".join(signal["evidence"]))
            print("Explanation:", signal["explanation"])

        print("\nRecommendation:", result["recommendation"])
