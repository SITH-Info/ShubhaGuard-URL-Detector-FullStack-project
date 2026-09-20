from flask import Flask, render_template, request, jsonify
from urllib.parse import urlparse
import re

app = Flask(__name__)

# Known URL shorteners
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
}

# Words commonly found in suspicious URLs
SUSPICIOUS_WORDS = {
    "login",
    "signin",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "bank",
    "wallet",
    "bonus",
    "free",
    "claim",
    "urgent",
    "alert",
    "recover",
    "unlock",
    "support",
}


def normalize_url(value):
    value = value.strip()

    if not value:
        return ""

    # Add HTTP scheme if the user didn't provide one
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value):
        value = "http://" + value

    return value


def analyze_url(raw_url):
    url = normalize_url(raw_url)

    if not url:
        return {"error": "Please enter a URL."}

    try:
        parsed = urlparse(url)

        host = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""

    except Exception:
        return {"error": "Invalid URL format."}

    if not host:
        return {"error": "Could not find a domain in the URL."}

    score = 0
    reasons = []

    
    # Explainable URL features
    

    # HTTPS check
    if parsed.scheme.lower() != "https":
        score += 15
        reasons.append("The URL does not use HTTPS.")

    # @ symbol
    if "@" in url:
        score += 25
        reasons.append(
            "The URL contains '@', which can hide the real destination."
        )

    # URL length
    if len(url) > 100:
        score += 10
        reasons.append("The URL is unusually long.")

    elif len(url) > 75:
        score += 5
        reasons.append("The URL is longer than typical.")

    # Punycode
    if host.startswith("xn--") or ".xn--" in host:
        score += 20
        reasons.append(
            "The domain uses punycode, which can be abused for look-alike domains."
        )

    # IP address instead of domain
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        score += 20
        reasons.append(
            "The hostname is an IP address instead of a normal domain."
        )

    # Many subdomains
    if host.count(".") >= 3:
        score += 10
        reasons.append("The domain contains many subdomains.")

    # Multiple hyphens
    if host.count("-") >= 2:
        score += 8
        reasons.append("The domain contains multiple hyphens.")

    # URL shortener
    if host in SHORTENERS or any(
        host.endswith("." + domain) for domain in SHORTENERS
    ):
        score += 20
        reasons.append("The URL uses a known URL-shortening service.")

    # Suspicious keywords
    text = (host + path + query).lower()

    found_words = sorted(
        {word for word in SUSPICIOUS_WORDS if word in text}
    )

    if found_words:
        score += min(25, 5 * len(found_words))

        reasons.append(
            "It contains security/account-related keywords: "
            + ", ".join(found_words)
            + "."
        )

    # Very high number of subdomain parts
    if host.count(".") > 5:
        score += 10
        reasons.append(
            "The hostname has an unusually high number of "
            "dot-separated parts."
        )

    # Special/query characters
    special_count = len(re.findall(r"[%_=&]", url))

    if special_count > 12:
        score += 8
        reasons.append(
            "The URL contains many special/query characters."
        )

    
    # Common safe domains
    

    common_safe = {
        "google.com",
        "www.google.com",
        "youtube.com",
        "www.youtube.com",
        "github.com",
        "www.github.com",
        "microsoft.com",
        "www.microsoft.com",
        "apple.com",
        "www.apple.com",
        "amazon.com",
        "www.amazon.com",
    }

    if host in common_safe and score < 35:
        score = max(0, score - 10)

    # Keep score between 0 and 100
    score = max(0, min(100, score))

    
    # Verdict
    

    if score >= 60:
        verdict = "Likely Phishing"
        level = "danger"

    elif score >= 35:
        verdict = "Suspicious"
        level = "warning"

    else:
        verdict = "Likely Safe"
        level = "safe"

    # If no suspicious characteristics were found
    if not reasons:
        reasons.append(
            "No major suspicious URL characteristics were detected."
        )

    
    # Explanation note
    

    if score >= 60:
        note = (
            "High risk detected. Avoid entering passwords, payment "
            "details, or personal information on this website."
        )

    elif score >= 35:
        note = (
            "This URL has some suspicious characteristics. Verify "
            "the website and domain before continuing."
        )

    else:
        note = (
            "No major phishing indicators were detected. Still, "
            "verify the website before entering sensitive information."
        )

    
    # Return result
    

    return {
        "url": raw_url,
        "normalized_url": url,
        "domain": host,
        "score": score,
        "verdict": verdict,
        "level": level,
        "reasons": reasons,
        "note": note,
    }



# Flask routes


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/analyze")
def api_analyze():
    data = request.get_json(silent=True) or {}

    return jsonify(
        analyze_url(str(data.get("url", "")))
    )


@app.get("/api/health")
def health():
    return jsonify({"status": "ok"})



# Run application


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )
