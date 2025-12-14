import os
from datetime import datetime, timezone
from urllib.parse import urlparse

from flask import Flask, render_template, request, jsonify
from dotenv import load_dotenv
import requests

# ------------------------------------------------------------------
# LOAD ENV
# ------------------------------------------------------------------
load_dotenv(dotenv_path=".env")

app = Flask(__name__)

GSB_API_KEY = os.getenv("GSB_API_KEY")


# ------------------------------------------------------------------
# HELPERS
# ------------------------------------------------------------------
def now_iso():
    return datetime.now(timezone.utc).isoformat()


def normalize_url(raw: str) -> str:
    if not raw:
        return ""
    url = raw.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ------------------------------------------------------------------
# HEURISTIC CHECK (OFFLINE)
# ------------------------------------------------------------------
def heuristic_check(url: str) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    full = url.lower()

    keywords = [
        "login", "verify", "update", "secure",
        "account", "bank", "paypal", "confirm", "password"
    ]

    keyword_hits = [k for k in keywords if k in full]

    score = 0
    if keyword_hits: score += 30
    if host.replace(".", "").isdigit(): score += 25
    if host.count(".") >= 3: score += 15
    if len(url) > 120: score += 10
    if "@" in url: score += 10
    if "-" in host: score += 10

    if score >= 60:
        verdict = "Phishing Detected"
    elif score >= 30:
        verdict = "Suspicious"
    else:
        verdict = "Likely Safe"

    return {
        "verdict": verdict,
        "score": score,
        "features": {
            "keyword_hits": keyword_hits,
            "ip_in_host": host.replace(".", "").isdigit(),
            "many_subdomains": host.count(".") >= 3,
            "long_url": len(url) > 120,
            "at_symbol": "@" in url,
            "dash_in_domain": "-" in host,
        }
    }


# ------------------------------------------------------------------
# GOOGLE SAFE BROWSING
# ------------------------------------------------------------------
def check_google_safe_browsing(url: str) -> dict:
    if not GSB_API_KEY:
        return {"enabled": False, "match": False, "details": "GSB not configured"}

    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}"

    payload = {
        "client": {"clientId": "smart-phishing-detector", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["SOCIAL_ENGINEERING", "MALWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }

    try:
        r = requests.post(endpoint, json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()
        return {
            "enabled": True,
            "match": bool(data.get("matches")),
            "details": "match" if data.get("matches") else "no match",
        }
    except Exception as e:
        return {"enabled": True, "match": False, "details": f"error: {e}"}


# ------------------------------------------------------------------
# PHISHTANK (NO API KEY)
# ------------------------------------------------------------------
def check_phishtank(url: str) -> dict:
    endpoint = "https://checkurl.phishtank.com/checkurl/"

    data = {
        "url": url,
        "format": "json"
    }

    headers = {
        "User-Agent": "phishtank/merril-academic-project"
    }

    try:
        r = requests.post(endpoint, data=data, headers=headers, timeout=15)

        if r.status_code == 509:
            return {"enabled": True, "match": False, "details": "rate limited"}

        r.raise_for_status()
        result = r.json().get("results", {})

        match = result.get("in_database") and result.get("valid")

        return {
            "enabled": True,
            "match": bool(match),
            "details": "verified phishing" if match else "not found in database",
        }

    except Exception as e:
        return {"enabled": True, "match": False, "details": f"error: {e}"}


# ------------------------------------------------------------------
# COMBINE ALL RESULTS
# ------------------------------------------------------------------
def analyse_url(url: str) -> dict:
    heur = heuristic_check(url)
    gsb = check_google_safe_browsing(url)
    pt = check_phishtank(url)

    verdict = heur["verdict"]
    score = heur["score"]

    if gsb["enabled"] and gsb["match"]:
        verdict = "Phishing Detected"
        score = max(score, 90)

    if pt["enabled"] and pt["match"]:
        verdict = "Phishing Detected"
        score = max(score, 85)

    return {
        "verdict": verdict,
        "score": score,
        "sources": [
            {
                "name": "Google Safe Browsing",
                "match": gsb["match"],
                "details": gsb["details"],
            },
            {
                "name": "PhishTank",
                "match": pt["match"],
                "details": pt["details"],
            },
            {
                "name": "Local Heuristics",
                "match": heur["verdict"] != "Likely Safe",
                "details": heur["features"],
            },
        ]
    }


# ------------------------------------------------------------------
# ROUTES
# ------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/check", methods=["POST"])
def api_check():
    data = request.get_json(force=True, silent=True) or {}
    raw_url = data.get("url", "")

    url = normalize_url(raw_url)
    if not url:
        return jsonify({"error": "URL required"}), 400

    result = analyse_url(url)

    return jsonify({
        "input": url,
        "verdict": result["verdict"],
        "score": result["score"],
        "checked_at": now_iso(),
        "sources": result["sources"],
    }), 200


# ------------------------------------------------------------------
# RUN
# ------------------------------------------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001, debug=True)