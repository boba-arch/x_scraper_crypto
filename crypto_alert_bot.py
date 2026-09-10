"""
Crypto Exploit/Hack/Incident Monitor
-------------------------------------
Searches X (Twitter) for recent tweets about crypto exploits, hacks, and
security incidents, scores each one for risk, translates it to Chinese,
and pushes an alert to a Telegram chat.

Runs as a persistent 24/7 process (not a scheduled job) — it loops forever,
polling every POLL_INTERVAL_SECONDS, and only ever reads tweets newer than
the last one it saw (via since_id) so it never re-reads or re-pays for the
same tweet twice. Meant to be deployed on an always-on host like Railway or
Render. You should not need to edit this file — configuration is done
entirely through environment variables. See SETUP_GUIDE.md.
"""

import os
import sys
import time
import html
import json
import requests
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Configuration (all pulled from environment variables / GitHub Secrets)
# ---------------------------------------------------------------------------

X_BEARER_TOKEN = os.environ.get("X_BEARER_TOKEN")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
DEEPL_API_KEY = os.environ.get("DEEPL_API_KEY")  # optional but strongly recommended
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")  # optional — enables AI scoring
AI_MODEL = os.environ.get("AI_MODEL", "claude-haiku-4-5-20251001")

# How often to poll, in seconds. 30-60s gives near-real-time alerts without
# hammering X's rate limit (450 search requests / 15 min per app).
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "45"))

# On first startup only (no since_id yet), how far back to look so we don't
# miss anything but also don't backfill hours of history.
INITIAL_LOOKBACK_MINUTES = int(os.environ.get("INITIAL_LOOKBACK_MINUTES", "5"))

# Minimum likes a tweet needs to trigger an alert. Applied client-side
# after fetching — X's pay-per-use tier doesn't support engagement-based
# query operators (min_faves), so this reduces alert noise, not read cost.
MIN_ENGAGEMENT_FILTER = int(os.environ.get("MIN_ENGAGEMENT_FILTER", "5"))

# Common false-positive phrases that share words with our incident terms
# but are almost never real crypto security incidents (growth hacking,
# hackathons, unrelated giveaway/airdrop spam). Excluded directly in the
# X query to cut billed noise.
NOISE_EXCLUSIONS = ["hackathon", "giveaway", "airdrop"]

# Hard cap on how many tweets we pull per poll — mainly a safety ceiling for
# traffic bursts, since since_id tracking already prevents re-reads.
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "10"))

# Only alert if the computed risk score is at least this high (0-100).
MIN_RISK_SCORE_TO_ALERT = int(os.environ.get("MIN_RISK_SCORE_TO_ALERT", "25"))

# ---------------------------------------------------------------------------
# Keyword / query strategy
# ---------------------------------------------------------------------------

INCIDENT_TERMS = [
    "exploit", "hacked", "hack", "breach", "drained", "compromised",
    "rugpull", "reentrancy", "private key leaked", "wallet drained",
    "bridge exploit",
]

CRYPTO_CONTEXT_TERMS = [
    "crypto", "bitcoin", "ethereum", "solana", "defi", "web3",
    "exchange", "dex", "protocol", "token", "bsc", "bnb", "polygon",
    "arbitrum", "avalanche", "chain",
]

# Accounts whose reporting is generally high-signal for security incidents.
# Boosts risk score and helps filter noise. Edit freely.
TRUSTED_ACCOUNTS = {
    "zachxbt", "peckshieldalert", "peckshield", "officer_cia",
    "certikalert", "certik", "slowmist_team", "cyversealerts",
    "bitcoin_infoBTC", "whale_alert","exvulsec",
}

# Words that indicate the incident is resolved/false-positive/hypothetical —
# used to reduce score and cut noise.
DAMPENERS = [
    "patched", "resolved", "false alarm", "test transaction", "not a hack",
    "rumor", "unconfirmed", "hypothetical", "simulation", "poc only",
]

HIGH_SEVERITY = [
    "drained", "private key leaked", "seed phrase", "wallet drained",
    "unauthorized withdrawal", "bridge exploit", "exploited",
]

MEDIUM_SEVERITY = [
    "exploit", "hacked", "hack", "breach", "compromised", "rug pull",
    "rugpull", "reentrancy", "flash loan attack", "oracle manipulation",
]

LOW_SEVERITY = [
    "incident", "vulnerability", "smart contract vulnerability",
    "security incident",
]


def build_query() -> str:
    incident_clause = " OR ".join(f'"{t}"' if " " in t else t for t in INCIDENT_TERMS)
    context_clause = " OR ".join(CRYPTO_CONTEXT_TERMS)
    exclusions = " ".join(
        f'-"{t}"' if " " in t else f"-{t}" for t in NOISE_EXCLUSIONS
    )
    # (incident terms) AND (crypto context terms), minus common
    # false-positive phrases, English only, no retweets.
    # Note: min_faves / engagement-based query operators require a higher
    # X API access tier than pay-per-use includes, so engagement filtering
    # happens client-side after fetch instead (see MIN_ENGAGEMENT_FILTER
    # in run_once) — it reduces alert noise, not the billed read count.
    return f"({incident_clause}) ({context_clause}) {exclusions} -is:retweet lang:en"


def search_recent_tweets(since_id: str | None):
    if not X_BEARER_TOKEN:
        print("ERROR: X_BEARER_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)

    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {X_BEARER_TOKEN}"}
    params = {
        "query": build_query(),
        "max_results": max(10, min(MAX_RESULTS, 100)),  # API requires 10-100
        "tweet.fields": "created_at,public_metrics,author_id,text",
        "expansions": "author_id",
        "user.fields": "username,name,verified",
    }

    if since_id:
        # Only fetch tweets newer than the last one we already processed —
        # this is what keeps cost proportional to actual new incidents,
        # not to how often we poll.
        params["since_id"] = since_id
    else:
        # First run: just look back a few minutes so we don't backfill
        # hours. Enforce a floor well above X's "must be 10+ seconds in
        # the past" requirement, as a safety margin against any clock
        # skew between this container and X's servers.
        lookback_seconds = max(INITIAL_LOOKBACK_MINUTES * 60, 60) + 30
        start_time = (
            datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        params["start_time"] = start_time

    resp = requests.get(url, headers=headers, params=params, timeout=30)
    if resp.status_code == 429:
        print("Rate limited by X API, will back off and retry next poll.", file=sys.stderr)
        return [], since_id
    if resp.status_code != 200:
        print(f"X API error {resp.status_code}: {resp.text}", file=sys.stderr)
        return [], since_id

    data = resp.json()
    tweets = data.get("data", [])
    users = {u["id"]: u for u in data.get("includes", {}).get("users", [])}

    results = []
    for t in tweets:
        author = users.get(t.get("author_id"), {})
        results.append({
            "id": t["id"],
            "text": t["text"],
            "created_at": t.get("created_at"),
            "metrics": t.get("public_metrics", {}),
            "username": author.get("username", "unknown"),
            "name": author.get("name", ""),
        })

    # meta.newest_id tells us where to resume from next poll
    newest_id = data.get("meta", {}).get("newest_id", since_id)
    return results, newest_id


def classify_with_ai(tweet_text: str):
    """
    Asks Claude to judge whether a tweet describes a real crypto security
    incident and assign a risk score. Returns (score, label, reasoning) or
    None if AI scoring isn't configured or the call fails — callers should
    fall back to the keyword-based score_risk() in that case.
    """
    if not ANTHROPIC_API_KEY:
        return None

    system_prompt = (
        "You are a crypto security risk analyst. Given a tweet, decide whether it "
        "describes a REAL crypto security incident (exploit, hack, breach, funds "
        "drained, private key compromise, rug pull, bridge exploit, etc.) as opposed "
        "to unrelated content (memes, marketing, hackathons, general opinions, "
        "giveaways, or vague/unconfirmed rumors with no real detail).\n\n"
        "Respond with ONLY a JSON object, no other text, no markdown fences:\n"
        '{"is_real_incident": true or false, "risk_score": <integer 0-100>, '
        '"reasoning": "<one short sentence>"}\n\n'
        "Scoring guide: 0-24 = not a real incident, or a trivial/unconfirmed rumor. "
        "25-44 = low-severity or early/unconfirmed report. 45-69 = confirmed "
        "incident, moderate scale. 70-100 = confirmed major incident, large funds "
        "lost or critical infrastructure compromised."
    )

    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": AI_MODEL,
                "max_tokens": 150,
                "system": system_prompt,
                "messages": [{"role": "user", "content": tweet_text}],
            },
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        text = "".join(
            block.get("text", "") for block in data.get("content", [])
            if block.get("type") == "text"
        ).strip()
        text = text.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(text)
        score = max(0, min(100, int(parsed.get("risk_score", 0))))
        is_real = bool(parsed.get("is_real_incident", False))
        reasoning = parsed.get("reasoning", "").strip()
        if not is_real:
            score = min(score, 15)  # force low if the AI says it's not real

        if score >= 70:
            label = "CRITICAL"
        elif score >= 45:
            label = "HIGH"
        elif score >= 25:
            label = "MEDIUM"
        else:
            label = "LOW"
        return score, label, reasoning

    except Exception as e:
        print(f"AI classification failed, falling back to keyword scoring: {e}",
              file=sys.stderr)
        return None


def score_risk(tweet: dict) -> tuple[int, str]:
    text_lower = tweet["text"].lower()
    score = 0

    if any(term in text_lower for term in HIGH_SEVERITY):
        score += 45
    elif any(term in text_lower for term in MEDIUM_SEVERITY):
        score += 30
    elif any(term in text_lower for term in LOW_SEVERITY):
        score += 15

    if tweet["username"].lower() in TRUSTED_ACCOUNTS:
        score += 25

    metrics = tweet.get("metrics", {})
    engagement = metrics.get("like_count", 0) + metrics.get("retweet_count", 0) * 2
    if engagement >= 500:
        score += 20
    elif engagement >= 100:
        score += 12
    elif engagement >= 20:
        score += 5

    if any(term in text_lower for term in DAMPENERS):
        score -= 35

    score = max(0, min(100, score))

    if score >= 70:
        label = "CRITICAL"
    elif score >= 45:
        label = "HIGH"
    elif score >= 25:
        label = "MEDIUM"
    else:
        label = "LOW"

    return score, label


def translate_to_chinese(text: str) -> str:
    """
    Translates to Simplified Chinese. Tries DeepL first (reliable, your own
    quota, needs DEEPL_API_KEY) then falls back to two free keyless
    endpoints if DeepL isn't configured or has an outage.
    """
    # Primary: DeepL, if a key is configured. Reliable, authenticated,
    # 500,000 free characters/month — no shared-IP throttling like the
    # free public endpoints below.
    if DEEPL_API_KEY:
        try:
            resp = requests.post(
                "https://api-free.deepl.com/v2/translate",
                headers={"Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}"},
                data={"text": text, "target_lang": "ZH"},
                timeout=15,
            )
            resp.raise_for_status()
            translated = resp.json()["translations"][0]["text"]
            if translated.strip():
                return translated
        except Exception as e:
            print(f"Primary translation (DeepL) failed: {e}", file=sys.stderr)
    else:
        print("DEEPL_API_KEY not set — using free fallback translators "
              "(less reliable). See SETUP_GUIDE.md to add DeepL.", file=sys.stderr)

    # Fallback 1: Google Translate's public endpoint, with a browser-like
    # User-Agent — some hosts get silently rejected without one. Prone to
    # rate limiting (429) from shared cloud-host IPs.
    try:
        resp = requests.get(
            "https://translate.googleapis.com/translate_a/single",
            params={
                "client": "gtx",
                "sl": "en",
                "tl": "zh-CN",
                "dt": "t",
                "q": text,
            },
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36"
            },
            timeout=15,
        )
        resp.raise_for_status()
        segments = resp.json()[0]
        translated = "".join(seg[0] for seg in segments if seg[0])
        if translated.strip():
            return translated
    except Exception as e:
        print(f"Fallback translation (Google) failed: {e}", file=sys.stderr)

    # Fallback 2: MyMemory's free translation API (no key required, rate
    # limited but fine for occasional fallback use).
    try:
        resp = requests.get(
            "https://api.mymemory.translated.net/get",
            params={"q": text, "langpair": "en|zh-CN"},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        translated = data.get("responseData", {}).get("translatedText", "")
        if translated.strip():
            return translated
    except Exception as e:
        print(f"Fallback translation (MyMemory) failed: {e}", file=sys.stderr)

    return "(translation unavailable — see logs for the underlying error)"


def send_telegram_alert(message: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set.", file=sys.stderr)
        return
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    resp = requests.post(url, data={
        "chat_id": TELEGRAM_CHAT_ID,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": "false",
    }, timeout=15)
    if resp.status_code != 200:
        print(f"Telegram send failed: {resp.status_code} {resp.text}", file=sys.stderr)


def format_alert(tweet: dict, score: int, label: str, zh_text: str) -> str:
    url = f"https://x.com/{tweet['username']}/status/{tweet['id']}"
    metrics = tweet.get("metrics", {})
    engagement = f"{metrics.get('like_count', 0)} likes / {metrics.get('retweet_count', 0)} RT"

    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}[label]

    msg = (
        f"{icon} <b>Risk: {label} ({score}/100)</b>\n"
        f"👤 @{html.escape(tweet['username'])} ({html.escape(tweet.get('name',''))})\n"
        f"📊 {engagement}\n\n"
        f"<b>EN:</b> {html.escape(tweet['text'])}\n\n"
        f"<b>中文:</b> {html.escape(zh_text)}\n\n"
        f"🔗 {url}"
    )
    return msg


def run_self_test():
    """
    Sends one fake, clearly-labeled TEST alert through the full pipeline
    (scoring, translation, Telegram formatting) so you can verify everything
    is wired correctly without waiting for a real incident tweet.
    Triggered by setting SELF_TEST_ON_START=true.
    """
    print("Running self-test: sending a sample alert through the full pipeline...")
    fake_tweet = {
        "id": "0000000000000000000",
        "text": "TEST ALERT: This is a sample tweet simulating a wallet drained "
                "in a DeFi exploit, used only to verify your bot setup.",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "metrics": {"like_count": 123, "retweet_count": 45},
        "username": "test_account",
        "name": "Self-Test",
    }
    score, label = score_risk(fake_tweet)
    zh_text = translate_to_chinese(fake_tweet["text"])
    message = "🧪 <b>SELF-TEST — not a real incident</b>\n\n" + format_alert(
        fake_tweet, score, label, zh_text
    )
    send_telegram_alert(message)
    print("Self-test message sent. Check your Telegram chat now.")


def run_once(since_id):
    tweets, newest_id = search_recent_tweets(since_id)
    if tweets:
        print(f"[{datetime.now(timezone.utc).isoformat()}] {len(tweets)} new candidate tweet(s).")

    for tweet in tweets:
        metrics = tweet.get("metrics", {})
        likes = metrics.get("like_count", 0)

        ai_result = classify_with_ai(tweet["text"])
        if ai_result:
            score, label, reasoning = ai_result
            source = "AI"
        else:
            score, label = score_risk(tweet)  # fallback: keyword heuristic
            reasoning = ""
            source = "keyword"

        preview = tweet["text"][:80].replace("\n", " ")

        # Always log the score, even for tweets that won't alert — this is
        # what you want to watch to calibrate MIN_RISK_SCORE_TO_ALERT and
        # MIN_ENGAGEMENT_FILTER against real traffic.
        print(f"  [{label} {score}/100 via {source}] {likes} likes @{tweet['username']}: {preview}")
        if reasoning:
            print(f"    reasoning: {reasoning}")

        if likes < MIN_ENGAGEMENT_FILTER:
            print(f"    -> skipped (below MIN_ENGAGEMENT_FILTER={MIN_ENGAGEMENT_FILTER})")
            continue
        if score < MIN_RISK_SCORE_TO_ALERT:
            print(f"    -> skipped (below MIN_RISK_SCORE_TO_ALERT={MIN_RISK_SCORE_TO_ALERT})")
            continue

        zh_text = translate_to_chinese(tweet["text"])
        message = format_alert(tweet, score, label, zh_text)
        send_telegram_alert(message)
        print(f"    -> ALERT SENT")
        time.sleep(1)  # be gentle with Telegram's rate limits

    return newest_id


def main():
    print(f"[{datetime.now(timezone.utc).isoformat()}] Crypto incident monitor starting up.")
    print(f"Polling every {POLL_INTERVAL_SECONDS}s. Alert threshold: {MIN_RISK_SCORE_TO_ALERT}. "
          f"Min engagement filter: {MIN_ENGAGEMENT_FILTER} likes.")
    print(f"Search query: {build_query()}")

    if not X_BEARER_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: Missing one or more required env vars: X_BEARER_TOKEN, "
              "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID.", file=sys.stderr)
        sys.exit(1)

    if os.environ.get("SELF_TEST_ON_START", "false").lower() == "true":
        run_self_test()

    since_id = None
    while True:
        try:
            since_id = run_once(since_id)
        except Exception as e:
            # Never let a single bad poll kill the 24/7 process.
            print(f"Unexpected error during poll: {e}", file=sys.stderr)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
