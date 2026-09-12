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

# How long (hours) an alerted incident stays in memory for duplicate
# detection. New reports of the same incident within this window get
# suppressed by the AI unless they add genuinely new information.
DEDUPE_WINDOW_HOURS = float(os.environ.get("DEDUPE_WINDOW_HOURS", "12"))
DEDUPE_MAX_ENTRIES = 20  # cap memory size regardless of window

# In-memory record of recently alerted incidents, so the AI can recognize
# "this is the same story another account already told me about" instead
# of re-alerting every time a different account tweets the same news.
# Resets on restart — same caveat as since_id.
recent_alerts: list[dict] = []


def remember_alert(summary: str):
    recent_alerts.append({"time": datetime.now(timezone.utc), "summary": summary})
    prune_recent_alerts()


def prune_recent_alerts():
    cutoff = datetime.now(timezone.utc) - timedelta(hours=DEDUPE_WINDOW_HOURS)
    while recent_alerts and recent_alerts[0]["time"] < cutoff:
        recent_alerts.pop(0)
    while len(recent_alerts) > DEDUPE_MAX_ENTRIES:
        recent_alerts.pop(0)


def recent_alerts_context() -> str:
    prune_recent_alerts()
    if not recent_alerts:
        return "(none yet)"
    return "\n".join(f"- {a['summary']}" for a in recent_alerts)

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
    "exploit", "hacked", "breach", "drained", "compromised",
    "rugpull", "reentrancy", "private key leaked", "wallet drained",
    "bridge exploit",
]

# NOTE: currently unused — build_query() now restricts search to
# TRUSTED_ACCOUNTS only (from:...), which is far cheaper than matching
# these context words across all of Twitter. Left here in case you ever
# want to revert to a broader, non-source-restricted search.
CRYPTO_CONTEXT_TERMS = [
    "crypto", "bitcoin", "ethereum", "solana", "defi", "web3",
    "exchange", "dex", "bsc", "bnb", "polygon", "arbitrum", "avalanche",
]

# Accounts whose reporting is generally high-signal for security incidents.
# Boosts risk score and helps filter noise. Edit freely.
TRUSTED_ACCOUNTS = {
    "zachxbt", "peckshieldalert", "peckshield", "officer_cia",
    "certikalert", "certik", "slowmist_team", "cyversealerts",
    "bitcoin_infoBTC", "whale_alert", "exvulsec",
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
    # Broad search across all of Twitter (not source-restricted) — trades
    # lower cost for wider coverage. The AI classification step is what
    # keeps this usable: it judges source credibility and current/active
    # status per-tweet instead of relying on a pre-vetted account list.
    return f"({incident_clause}) ({context_clause}) {exclusions} -is:retweet -is:quote lang:en"


def search_recent_tweets(since_id: str | None):
    """
    Returns (tweets, newest_id, error_message). error_message is None on
    success (even if zero tweets matched — that's a normal quiet period,
    not a failure). It's set to a short description on any API error, so
    the caller can distinguish "nothing happened" from "something broke".
    """
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

    if resp.status_code == 402:
        return [], since_id, "X API credits depleted (402) — no credit left to fetch tweets."
    if resp.status_code == 401:
        return [], since_id, "X API authentication failed (401) — bearer token may be invalid/expired."
    if resp.status_code == 429:
        print("Rate limited by X API, will back off and retry next poll.", file=sys.stderr)
        return [], since_id, None  # transient, not worth paging over on its own
    if resp.status_code != 200:
        print(f"X API error {resp.status_code}: {resp.text}", file=sys.stderr)
        return [], since_id, f"X API error {resp.status_code}: {resp.text[:200]}"

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
    return results, newest_id, None


def classify_with_ai(tweet: dict):
    """
    Asks Claude to judge whether a tweet describes a real, currently-active
    crypto security incident and assign a risk score. Returns
    (score, label, summary, reasoning) or None if AI scoring isn't
    configured or the call fails — callers should fall back to the
    keyword-based score_risk() in that case.
    """
    if not ANTHROPIC_API_KEY:
        return None

    username = tweet.get("username", "unknown")
    is_known_trusted = username.lower() in TRUSTED_ACCOUNTS
    trusted_list = ", ".join(sorted(TRUSTED_ACCOUNTS))

    system_prompt = (
        "You are a crypto security journalist and threat-intel analyst, in "
        "the same vein as Blockaid or SlowMist's team — your job is to track "
        "ACTIVE, ONGOING, or JUST-BROKE crypto security incidents in real "
        "time for a risk officer at an exchange, not to catalog history.\n\n"
        "This search is NOT restricted to pre-vetted accounts — you will "
        "see tweets from anyone, including random or unverified accounts "
        "making claims. Judge source credibility yourself: known reputable "
        f"security researchers/firms include: {trusted_list}. A tweet from "
        "one of these can be treated as credible on its own. A tweet from "
        "an unknown/unverified account needs concrete supporting detail "
        "(specific contract address, tx hash, dollar amount, on-chain "
        "evidence) to be treated as credible — vague claims with no "
        "specifics from an unknown source should score low even if "
        "alarming-sounding.\n\n"
        "You'll be told the tweet's author username. Weigh that alongside "
        "the tweet's own content.\n\n"
        "Respond with ONLY a JSON object, no other text, no markdown fences:\n"
        '{"is_real_incident": true or false, "risk_score": <integer 0-100>, '
        '"summary": "<Start with a line in EXACTLY this format: '
        "'Affected project/tokens: <name(s), or \\'Unknown\\' if not stated>'. "
        "Then, on a new line, 2-3 plain-English sentences explaining what "
        "happened, in clear non-technical language a risk officer can act "
        'on — what was exploited, how, and the scale of loss if known>", '
        '"reasoning": "<one short sentence on why this score, including '
        'your source-credibility judgment>"}\n\n'
        "Set is_real_incident to FALSE if this is NOT a fresh or currently "
        "unfolding incident — this includes general commentary, educational "
        "threads about attack techniques in the abstract, retrospectives or "
        "anniversaries of old hacks (e.g. '2 years ago today...', 'revisiting "
        "the X hack'), or a rehash of previously reported news with no new "
        "development. Also set it FALSE if the claim is unsubstantiated and "
        "from an unverified source. Set it TRUE for incidents that are "
        "newly disclosed, actively unfolding (funds still moving, "
        "investigation ongoing), or a meaningful update to a very recent "
        "incident (new loss figures, attacker identified, funds frozen).\n\n"
        "Scoring guide — weight recency, active status, AND source "
        "credibility heavily: 0-24 = not current, unsubstantiated, or from "
        "an unverified source with no supporting detail. 25-44 = confirmed, "
        "small-scale, or recent but low-impact. 45-69 = confirmed, "
        "moderate scale, actively unfolding or very recent, credible "
        "source. 70-100 = confirmed MAJOR incident that is currently "
        "active or just happened, from a credible source or with strong "
        "supporting evidence — large funds lost, attacker still moving "
        "funds, or critical infrastructure compromised.\n\n"
        "DUPLICATE CHECK — incidents already alerted on recently (within "
        f"the last {DEDUPE_WINDOW_HOURS:.0f}h):\n{recent_alerts_context()}\n\n"
        "If this tweet is reporting the SAME underlying incident as one "
        "already listed above — even from a different account, with "
        "different wording — set is_real_incident to FALSE and score low, "
        "with reasoning noting it's a duplicate already alerted on. "
        "EXCEPTION: if it adds genuinely new, material information (a "
        "significantly updated loss figure, the attacker identified/"
        "arrested, funds frozen or recovered, a new protocol/chain "
        "affected that wasn't previously known), still report it — set "
        "is_real_incident TRUE and note in the summary what's new."
    )

    user_message = f"Tweet author: @{username}\nTweet text: {tweet['text']}"

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
                "max_tokens": 500,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}],
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
        summary = parsed.get("summary", "").strip()
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
        return score, label, summary, reasoning

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


def format_alert(tweet: dict, score: int, label: str, zh_text: str, summary: str = "") -> str:
    url = f"https://x.com/{tweet['username']}/status/{tweet['id']}"
    metrics = tweet.get("metrics", {})
    engagement = f"{metrics.get('like_count', 0)} likes / {metrics.get('retweet_count', 0)} RT"

    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}[label]

    summary_block = ""
    if summary:
        zh_summary = translate_to_chinese(summary)
        summary_block = (
            f"<b>What happened:</b> {html.escape(summary)}\n"
            f"<b>发生了什么:</b> {html.escape(zh_summary)}\n\n"
        )

    msg = (
        f"{icon} <b>Risk: {label} ({score}/100)</b>\n"
        f"👤 @{html.escape(tweet['username'])} ({html.escape(tweet.get('name',''))})\n"
        f"📊 {engagement}\n\n"
        f"{summary_block}"
        f"<b>Original tweet (EN):</b> {html.escape(tweet['text'])}\n\n"
        f"<b>原文翻译 (中文):</b> {html.escape(zh_text)}\n\n"
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


def send_system_alert(message: str):
    """
    Sends a bot-health alert (distinct from incident alerts) — used when
    the bot itself is broken (credits depleted, auth failure, etc.) so you
    find out you've gone blind instead of silently missing coverage.
    """
    full_message = f"🔧 <b>BOT HEALTH ALERT</b>\n\n{message}"
    send_telegram_alert(full_message)


def run_once(since_id):
    tweets, newest_id, error = search_recent_tweets(since_id)
    if tweets:
        print(f"[{datetime.now(timezone.utc).isoformat()}] {len(tweets)} new candidate tweet(s).")

    for tweet in tweets:
        metrics = tweet.get("metrics", {})
        likes = metrics.get("like_count", 0)

        ai_result = classify_with_ai(tweet)
        if ai_result:
            score, label, summary, reasoning = ai_result
            source = "AI"
        else:
            score, label = score_risk(tweet)  # fallback: keyword heuristic
            summary, reasoning = "", ""
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
        message = format_alert(tweet, score, label, zh_text, summary)
        send_telegram_alert(message)
        if summary:
            remember_alert(summary)  # so future duplicates of this get suppressed
        print(f"    -> ALERT SENT")
        time.sleep(1)  # be gentle with Telegram's rate limits

    return newest_id, error


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
    consecutive_failures = 0
    last_health_alert_at = None
    HEALTH_ALERT_COOLDOWN_SECONDS = 1800  # don't re-page more than once per 30 min

    while True:
        try:
            since_id, error = run_once(since_id)

            if error:
                consecutive_failures += 1
                print(f"Poll failed ({consecutive_failures} in a row): {error}", file=sys.stderr)

                # Page immediately for unambiguous, important failures
                # (credits depleted / bad auth), or after 3 consecutive
                # failures for anything else — either way, respect a
                # cooldown so a stuck failure doesn't spam Telegram.
                is_urgent = "credits depleted" in error or "authentication failed" in error
                should_alert = is_urgent or consecutive_failures >= 3
                cooldown_elapsed = (
                    last_health_alert_at is None
                    or (datetime.now(timezone.utc) - last_health_alert_at).total_seconds()
                    > HEALTH_ALERT_COOLDOWN_SECONDS
                )
                if should_alert and cooldown_elapsed:
                    send_system_alert(
                        f"The bot is failing to fetch tweets and may not be catching "
                        f"real incidents right now.\n\n<b>Error:</b> {html.escape(error)}\n\n"
                        f"Consecutive failures: {consecutive_failures}."
                    )
                    last_health_alert_at = datetime.now(timezone.utc)
            else:
                if consecutive_failures > 0:
                    # We just recovered — let the user know it's back.
                    send_system_alert("Bot has recovered and is fetching tweets normally again.")
                consecutive_failures = 0

        except Exception as e:
            # Never let a single bad poll kill the 24/7 process.
            print(f"Unexpected error during poll: {e}", file=sys.stderr)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
