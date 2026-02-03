SUSPICIOUS_KEYWORDS = {
    "phishing": ["login", "verify", "update", "secure", "account", "bank", "wallet", "reset"],
    "impersonation": ["support", "helpdesk", "official", "admin", "service"],
    "trademark": ["paypal", "microsoft", "facebook", "apple", "netflix", "unicc"],  # Customize!
}

def score_threat(result_url: str, target: str) -> dict:
    score = 0
    reasons = []

    url_lower = result_url.lower()
    if target.lower() in url_lower:
        score += 2
        reasons.append("Target in URL")

    for category, keywords in SUSPICIOUS_KEYWORDS.items():
        for word in keywords:
            if word in url_lower:
                score += 1
                reasons.append(f"{category} keyword: {word}")

    return {
        "score": score,
        "reasons": list(set(reasons)),
        "label": classify_score(score)
    }

def classify_score(score: int) -> str:
    if score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    else:
        return "NONE"
