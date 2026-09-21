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
import re
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

# AI scoring uses Claude as the primary provider, with automatic failover to
# Grok if Claude is unreachable/erroring — you only get paged on Telegram if
# BOTH fail. Set whichever key(s) you have; at least one is required.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")  # primary provider (Claude)
XAI_API_KEY = os.environ.get("XAI_API_KEY")  # fallback provider (Grok)
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
GROK_MODEL = os.environ.get("GROK_MODEL", "grok-4.3")

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
DEDUPE_MAX_ENTRIES = int(os.environ.get("DEDUPE_MAX_ENTRIES", "10"))  # cap memory size regardless of window

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


def _call_claude(system_prompt: str, user_message: str, max_tokens: int) -> str:
    """Calls Anthropic's Claude API. Raises on any failure — caller handles fallback."""
    resp = requests.post(
        "https://api.anthropic.com/v1/messages",
        headers={
            "x-api-key": ANTHROPIC_API_KEY,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        },
        json={
            "model": CLAUDE_MODEL,
            "max_tokens": max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["content"][0]["text"].strip()


def _call_grok(system_prompt: str, user_message: str, max_tokens: int) -> str:
    """Calls xAI's Grok API. Raises on any failure — caller handles fallback."""
    resp = requests.post(
        "https://api.x.ai/v1/chat/completions",
        headers={
            "Authorization": f"Bearer {XAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": GROK_MODEL,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        },
        timeout=20,
    )
    resp.raise_for_status()
    data = resp.json()
    return data["choices"][0]["message"]["content"].strip()


def call_ai(system_prompt: str, user_message: str, max_tokens: int = 500):
    """
    Calls the configured AI provider(s) with automatic failover: tries
    Claude first (primary) if ANTHROPIC_API_KEY is set, and only falls back
    to Grok if Claude errors or isn't configured. Returns (text,
    provider_name) on success, or (None, None) if every configured
    provider failed. There is no keyword-based fallback — callers should
    treat (None, None) as "AI unreachable": skip the tweet/case and page on
    Telegram (see note_ai_failure_and_maybe_alert()).
    """
    if ANTHROPIC_API_KEY:
        try:
            return _call_claude(system_prompt, user_message, max_tokens), "claude"
        except Exception as e:
            print(f"Claude API call failed, trying Grok fallback: {e}", file=sys.stderr)

    if XAI_API_KEY:
        try:
            return _call_grok(system_prompt, user_message, max_tokens), "grok"
        except Exception as e:
            print(f"Grok API call failed: {e}", file=sys.stderr)

    return None, None


# Common false-positive phrases that share words with our incident terms
# but are almost never real crypto security incidents (growth hacking,
# hackathons, unrelated giveaway/airdrop spam). Excluded directly in the
# X query to cut billed noise.
NOISE_EXCLUSIONS = ["hackathon", "giveaway", "airdrop"]

# Hard cap on how many tweets we pull per poll — mainly a safety ceiling for
# traffic bursts, since since_id tracking already prevents re-reads.
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "10"))

# If a single poll finds more new matching tweets than MAX_RESULTS, this
# caps how many additional pages we'll fetch to catch the rest — without
# this, anything beyond the first page would be silently and permanently
# skipped once since_id advances past it. Each extra page = one more
# billed batch of reads, so this bounds worst-case cost per poll.
PAGINATION_MAX_PAGES = int(os.environ.get("PAGINATION_MAX_PAGES", "3"))

# Only alert if the computed risk score is at least this high (0-100).
MIN_RISK_SCORE_TO_ALERT = int(os.environ.get("MIN_RISK_SCORE_TO_ALERT", "25"))

# ---------------------------------------------------------------------------
# Keyword / query strategy
# ---------------------------------------------------------------------------

# We run TWO separate X searches every poll instead of one. Query A covers
# hard, unambiguous attack vocabulary ("exploit", "hacked", ...). Query B
# covers the softer, "official statement" vocabulary that real incidents
# often surface with FIRST — before anyone has confirmed it's an exploit
# (e.g. "network paused", "under investigation") — which was the exact
# pattern that caused earlier misses (MultiversX, Ofero Network). Running
# both costs roughly 2x the reads of a single query, which the user has
# explicitly said is an acceptable tradeoff for earlier/broader coverage.

INCIDENT_TERMS_A = [
    "exploit", "hacked", "breach", "drained", "compromised",
    "rugpull", "reentrancy", "private key leaked", "wallet drained",
    "bridge exploit",
    # Post-hack fund movement / threat-actor tracking — distinct from an
    # active fresh exploit, but valuable for spotting stolen funds heading
    # toward an exchange. See the AI prompt's scoring guidance for how
    # these are weighted differently from a fresh exploit.
    "laundering", "launder", "lazarus",
    # Broader attack-vector and disclosure vocabulary — added once AI
    # scoring was trusted to filter the resulting noise.
    "access control", "unauthorized", "flash loan",
    "oracle manipulation", "stolen", "phishing",
]

# Context (crypto-relevance) terms ANDed against INCIDENT_TERMS_A.
CONTEXT_A = [
    "crypto", "bitcoin", "ethereum", "solana", "defi", "web3",
    "exchange", "dex", "bsc", "bnb", "polygon", "arbitrum", "avalanche",
    "eth", "btc",  # common cashtag tickers, not just full chain names
    "blockchain", "mainnet",
]

# Query B: softer/operational-disclosure vocabulary — official-sounding
# statements that often appear before "exploit"/"hacked" is ever used.
INCIDENT_TERMS_B = [
    "halted", "suspended", "paused", "frozen", "vulnerability",
    "incident", "security incident", "under investigation",
    "security investigation", "potential issue", "validators paused",
    "network paused", "temporarily unavailable",
]

# Context terms ANDed against INCIDENT_TERMS_B. Broader than CONTEXT_A
# (adds "network"/"validators") since query B's incident terms are vaguer
# on their own and need the extra context words to stay on-topic.
CONTEXT_B = [
    "crypto", "bitcoin", "ethereum", "solana", "defi", "web3",
    "exchange", "dex", "bsc", "bnb", "polygon", "arbitrum", "avalanche",
    "eth", "btc", "blockchain", "mainnet", "network", "validators",
]

# Accounts whose reporting is generally high-signal for security incidents.
# Boosts risk score and helps filter noise. Edit freely.
TRUSTED_ACCOUNTS = {
    "zachxbt", "peckshieldalert", "peckshield", "officer_cia",
    "certikalert", "certik", "slowmist_team", "cyversealerts",
    "bitcoin_infoBTC", "whale_alert", "exvulsec",
}


def _build_one_query(incident_terms: list[str], context_terms: list[str]) -> str:
    incident_clause = " OR ".join(f'"{t}"' if " " in t else t for t in incident_terms)
    context_clause = " OR ".join(context_terms)
    exclusions = " ".join(
        f'-"{t}"' if " " in t else f"-{t}" for t in NOISE_EXCLUSIONS
    )
    # Broad search across all of Twitter (not source-restricted) — trades
    # lower cost for wider coverage. The AI classification step is what
    # keeps this usable: it judges source credibility and current/active
    # status per-tweet instead of relying on a pre-vetted account list.
    return f"({incident_clause}) ({context_clause}) {exclusions} -is:retweet -is:quote lang:en"


def build_queries() -> list[str]:
    """Returns the two X search query strings run every poll (A: hard attack
    vocabulary, B: soft/operational-disclosure vocabulary)."""
    return [
        _build_one_query(INCIDENT_TERMS_A, CONTEXT_A),
        _build_one_query(INCIDENT_TERMS_B, CONTEXT_B),
    ]


def _search_one_query(query: str, since_id: str | None):
    """
    Runs a single X search query (with pagination). Returns
    (tweets, newest_id, error_message) — same contract as
    search_recent_tweets(), but for one query string only.
    """
    def fetch_page(pagination_token=None):
        params = {
            "query": query,
            "max_results": max(10, min(MAX_RESULTS, 100)),  # API requires 10-100
            "tweet.fields": "created_at,public_metrics,author_id,text",
            "expansions": "author_id",
            "user.fields": "username,name,verified",
        }
        if since_id:
            params["since_id"] = since_id
        else:
            lookback_seconds = max(INITIAL_LOOKBACK_MINUTES * 60, 60) + 30
            start_time = (
                datetime.now(timezone.utc) - timedelta(seconds=lookback_seconds)
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            params["start_time"] = start_time
        if pagination_token:
            params["pagination_token"] = pagination_token
        return requests.get(url, headers=headers, params=params, timeout=30)

    url = "https://api.twitter.com/2/tweets/search/recent"
    headers = {"Authorization": f"Bearer {X_BEARER_TOKEN}"}

    resp = fetch_page()

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
    all_raw_tweets = list(data.get("data", []))
    all_users = {u["id"]: u for u in data.get("includes", {}).get("users", [])}

    # newest_id must come from the FIRST page only — that's the true most
    # recent tweet, used as next poll's since_id. Subsequent pages go
    # backward in time from there.
    newest_id = data.get("meta", {}).get("newest_id", since_id)

    # If there were MORE new matches than fit on one page, keep paging —
    # otherwise anything beyond the first page's cap would be silently and
    # permanently skipped once since_id advances past it.
    next_token = data.get("meta", {}).get("next_token")
    pages_fetched = 1
    while next_token and pages_fetched < PAGINATION_MAX_PAGES:
        page_resp = fetch_page(pagination_token=next_token)
        if page_resp.status_code != 200:
            print(f"Pagination request failed ({page_resp.status_code}), "
                  f"stopping early with what we have.", file=sys.stderr)
            break
        page_data = page_resp.json()
        all_raw_tweets.extend(page_data.get("data", []))
        all_users.update({u["id"]: u for u in page_data.get("includes", {}).get("users", [])})
        next_token = page_data.get("meta", {}).get("next_token")
        pages_fetched += 1

    if next_token:
        print(f"NOTE: more new tweets exist beyond PAGINATION_MAX_PAGES="
              f"{PAGINATION_MAX_PAGES} ({pages_fetched} pages fetched) for "
              f"this query — some may be missed this poll. Consider raising "
              f"it if this happens often.", file=sys.stderr)

    results = []
    for t in all_raw_tweets:
        author = all_users.get(t.get("author_id"), {})
        results.append({
            "id": t["id"],
            "text": t["text"],
            "created_at": t.get("created_at"),
            "metrics": t.get("public_metrics", {}),
            "username": author.get("username", "unknown"),
            "name": author.get("name", ""),
            "verified": bool(author.get("verified", False)),
        })

    return results, newest_id, None


def search_recent_tweets(since_id: str | None):
    """
    Runs BOTH X search queries (build_queries()) every poll, merges and
    dedupes the results by tweet ID, and reconciles a single since_id for
    the next poll. Tweet IDs are Twitter Snowflake IDs, which are globally
    time-ordered across all of Twitter regardless of which query matched —
    so it's safe (and simplest) to use one shared since_id watermark, taken
    as the max newest_id seen across both queries, for both queries on the
    next poll.

    Returns (tweets, newest_id, error_message) — same contract as before.
    error_message is None on success (even with zero matches — that's a
    normal quiet period). If EITHER query errors, that error is reported,
    but results from the other query (if it succeeded) are still returned
    and used, so one query having trouble doesn't blind the whole poll.
    """
    if not X_BEARER_TOKEN:
        print("ERROR: X_BEARER_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)

    queries = build_queries()
    combined_by_id: dict[str, dict] = {}
    newest_id = since_id
    errors = []

    for i, query in enumerate(queries, start=1):
        tweets, q_newest_id, error = _search_one_query(query, since_id)
        if error:
            print(f"Query {i} of {len(queries)} failed: {error}", file=sys.stderr)
            errors.append(error)
        for t in tweets:
            combined_by_id[t["id"]] = t  # dedupe by tweet ID
        # Numeric comparison — Snowflake IDs are time-ordered but can exceed
        # 64-bit-safe float precision, so compare as int, not string/lexical.
        if q_newest_id and (newest_id is None or int(q_newest_id) > int(newest_id)):
            newest_id = q_newest_id

    # Only treat this as a hard failure if EVERY query failed with no
    # results at all — a partial failure still yields usable tweets.
    error_message = None
    if errors and not combined_by_id:
        error_message = errors[0]

    return list(combined_by_id.values()), newest_id, error_message


def classify_with_ai(tweet: dict):
    """
    Asks the AI (Claude primary, Grok fallback — see call_ai()) to judge
    whether a tweet describes a real, currently-active crypto security
    incident and assign a risk score. Returns
    (score, label, summary, reasoning), or None if AI scoring isn't
    configured or every provider's call fails. There is no keyword-based
    fallback — scoring is AI-only, so callers should skip the tweet and
    page on Telegram when this returns None (see
    note_ai_failure_and_maybe_alert()).
    """
    if not ANTHROPIC_API_KEY and not XAI_API_KEY:
        return None

    username = tweet.get("username", "unknown")
    is_known_trusted = username.lower() in TRUSTED_ACCOUNTS
    trusted_list = ", ".join(sorted(TRUSTED_ACCOUNTS))

    system_prompt = (
        "You are risk management staff at a crypto exchange. Your job is to "
        "monitor X/Twitter around the clock for a NEW, CURRENTLY-HAPPENING "
        "security incident (a protocol being actively drained, a token "
        "being minted far beyond its supply, a bridge or contract being "
        "exploited right now, or even just an early, low-detail mention "
        "that some project 'is being exploited') so the exchange can "
        "immediately pause deposits/withdrawals/trading for the affected "
        "coin as a first response. Speed is everything: project teams are "
        "typically SLOW to confirm what's happening, so the earliest signal "
        "is often a vague, unconfirmed tweet, not an official statement. "
        "You would rather act on an early, still-uncertain report of an "
        "active exploit than wait for a confirmed post-mortem — by the time "
        "a project publishes a full writeup, the window to protect the "
        "exchange has usually already closed.\n\n"
        "This search is NOT restricted to pre-vetted accounts — you will "
        "see tweets from anyone, including random or unverified accounts "
        "making claims. Judge source credibility, but do NOT require "
        "concrete proof (contract address, tx hash, exact dollar amount) "
        "before treating a LIVE-sounding incident as worth flagging — a "
        "brief, detail-light 'X protocol is being exploited right now' "
        "from an unverified account is still actionable and should NOT be "
        "scored low just for lacking specifics. Reserve low scores for "
        "tweets with no incident signal at all (pure speculation, jokes, "
        "unrelated content), not for real-sounding but sparse reports. "
        f"Known reputable security researchers/firms include: {trusted_list} "
        "— a tweet from one of these is automatically credible, but their "
        "absence should never be the reason to downgrade an otherwise "
        "live-sounding incident.\n\n"
        "You'll be told the tweet's author username and whether X has "
        "verified that account. A verified account (especially a project's "
        "own official account) is a meaningful credibility signal on its "
        "own — weigh it alongside the tweet's content, even if the account "
        "isn't on the named trusted-researcher list.\n\n"
        "Respond with ONLY a JSON object, no other text, no markdown fences. "
        "CRITICAL: the JSON must be valid — any line break inside a string "
        "value must be written as the two characters backslash-n (\\n), "
        "NEVER as an actual line break, or the JSON will fail to parse.\n"
        '{"is_real_incident": true or false, "risk_score": <integer 0-100>, '
        '"summary": "<HARD LIMIT: 140 characters, no exceptions — this is '
        "read on a phone alert, not a report. ONE compact sentence in the "
        "shape '<Project/token name, or \\'Unknown\\'>: <what's happening>' "
        "— e.g. 'Liquid Network: bridge contract actively being drained, "
        "~$3M out so far.' Plain, non-technical language a risk officer "
        "can act on instantly. Cut every word that isn't essential; drop "
        'the loss figure/detail entirely rather than exceed 140 chars>", '
        '"reasoning": "<one short sentence on why this score, including '
        'your source-credibility judgment>"}\n\n'
        "Set is_real_incident TRUE for anything suggesting an incident is "
        "NEW or CURRENTLY UNFOLDING — active draining, an exploit in "
        "progress, abnormal/excessive token minting, funds actively moving "
        "out, or even a brief unconfirmed mention that a project is being "
        "exploited right now. Set it FALSE for: general commentary or "
        "educational threads about attack techniques in the abstract; "
        "retrospectives or anniversaries of old hacks ('2 years ago "
        "today...'); and — importantly — POST-MORTEMS or official updates "
        "published AFTER the fact (root-cause writeups, 'here's what "
        "happened and what we're doing', law-enforcement/recovery updates) "
        "about an incident that is already stabilized or contained. Those "
        "come too late to inform a first response and are low priority "
        "here, UNLESS they reveal the incident is actually STILL ongoing or "
        "unresolved (attacker still has access, funds still moving, "
        "exploit not yet patched) — in that case set it TRUE, since that's "
        "still actionable.\n\n"
        "SPECIAL CASE — known threat actor fund movement: some tweets "
        "report a known threat actor (e.g. Lazarus Group) moving, "
        "laundering, or cashing out PREVIOUSLY stolen funds, rather than a "
        "fresh exploit. Still set is_real_incident TRUE for these — this is "
        "valuable, actionable intel for an exchange risk officer, since "
        "incoming funds from a known attacker can be flagged before they "
        "land. Score these moderately (typically 30-50) UNLESS the funds "
        "are explicitly moving toward a specific exchange or CEX deposit "
        "address, in which case score higher (60+) since that's directly "
        "actionable. Note in the summary which threat actor and where "
        "funds are headed if stated.\n\n"
        "SPECIAL CASE — security-awareness / PSA posts: some tweets "
        "reference a real (sometimes days-old) incident mainly as a "
        "springboard for general security advice, not to report current "
        "developments. Hallmarks: imperative instructions ('Stop.', "
        "'Verify independently', 'Trust the evidence, not appearance'), a "
        "bulleted/numbered list of things to never share (seed phrase, "
        "private key, recovery phrase), or closing 'lesson'/'reminder' "
        "framing. If a meaningful portion of the tweet is generic advice "
        "rather than describing what's currently happening or new about "
        "THIS incident, treat it as educational/PSA content — set "
        "is_real_incident FALSE and score LOW (10-20) — regardless of how "
        "detailed or alarming the incident recap itself is, and even if "
        "you haven't seen this specific incident mentioned before.\n\n"
        "SPECIAL CASE — official first-party operational disclosure: some "
        "tweets are an official project/platform account announcing that "
        "operations are disrupted by a halt, pause, or security "
        "investigation. This covers TWO situations, treated the same way: "
        "(a) the account's OWN network/protocol has halted, paused "
        "validation, or is under investigation (e.g. 'mainnet validation is "
        "temporarily paused during a security investigation'), OR (b) the "
        "account runs a platform/service BUILT ON another chain or "
        "protocol, and is telling its users that ITS service (transfers, "
        "withdrawals, cashbacks, deposits, etc.) is disrupted because that "
        "underlying chain/protocol is paused or under a security "
        "investigation, even if the underlying network isn't the account's "
        "own. Both are inherently credible even though it's not on the "
        "trusted researcher list and no third party has confirmed it — an "
        "official channel does not tell its own users their funds/transfers "
        "are affected unless something real is happening. Do NOT downgrade "
        "for lacking outside confirmation or a stated loss figure, and do "
        "NOT downgrade case (b) just because the halted network belongs to "
        "a different project than the tweeting account — the disruption to "
        "the tweeting account's own users is what matters. Set "
        "is_real_incident TRUE and score at least 65-80 by default. Score "
        "at the HIGH end of that range (75+) when the account is VERIFIED, "
        "when user funds/withdrawals/transfers/deposits are explicitly "
        "affected, or both — this combination should essentially always "
        "clear 70. This is a materially different situation from an "
        "unverified rando making claims — an official channel disclosing "
        "impact to its own users is itself the actionable signal, so don't "
        "undersell it while waiting for more details.\n\n"
        "Scoring guide — weight CURRENT/ACTIVE status above all else; "
        "source credibility adjusts within that, it doesn't override it: "
        "0-24 = no real incident signal, pure speculation/noise, or a "
        "POST-MORTEM/update about an incident that's already stabilized "
        "with nothing new actionable. 25-44 = plausible but light on "
        "detail — a brief/early live-sounding report from an unverified "
        "source, or routine threat-actor fund movement with no exchange "
        "destination stated. 45-69 = credible and actively unfolding right "
        "now (draining, exploit in progress, abnormal minting), even if "
        "details are still thin — this band is where most fresh incident "
        "chatter should land. 70-100 = confirmed MAJOR incident that is "
        "currently active, from a credible source or with strong "
        "supporting evidence, or an official first-party disclosure of "
        "disrupted operations — large funds at risk/lost, attacker still "
        "moving funds, or critical infrastructure compromised.\n\n"
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

    verified_note = "verified" if tweet.get("verified") else "not verified"
    user_message = (
        f"Tweet author: @{username} ({verified_note} account)\n"
        f"Tweet text: {tweet['text']}"
    )

    text, provider = call_ai(system_prompt, user_message, max_tokens=500)
    if not text:
        print("AI classification failed: both Claude and Grok were "
              "unreachable/erroring.", file=sys.stderr)
        return None

    try:
        text = text.replace("```json", "").replace("```", "").strip()

        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            # Common failure mode: the model put a literal line break inside
            # a string value instead of escaping it as \n. Try a repair
            # pass — escape any raw newlines inside quoted strings — before
            # giving up and treating this as a failed classification.
            repaired = re.sub(
                r'"((?:[^"\\]|\\.)*)"',
                lambda m: '"' + m.group(1).replace("\n", "\\n") + '"',
                text,
                flags=re.DOTALL,
            )
            parsed = json.loads(repaired)  # let this raise if still broken

        score = max(0, min(100, int(parsed.get("risk_score", 0))))
        is_real = bool(parsed.get("is_real_incident", False))
        summary = parsed.get("summary", "").strip()
        if len(summary) > 140:
            # Safety net in case the AI overshoots the 140-char instruction —
            # trim on a word boundary rather than mid-word.
            summary = summary[:140].rsplit(" ", 1)[0].rstrip(",.;:") + "…"
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
        print(f"AI response from {provider} couldn't be parsed: {e}\n"
              f"  Raw response was: {text!r}", file=sys.stderr)
        return None


# Maps how X writes chain names in "chain:0xaddress" references to the
# platform ID CoinGecko's API expects.
CHAIN_TO_COINGECKO_PLATFORM = {
    "ethereum": "ethereum",
    "bsc": "binance-smart-chain",
    "polygon": "polygon-pos",
    "arbitrum": "arbitrum-one",
    "avalanche": "avalanche",
}

_token_symbol_cache: dict[str, str] = {}  # address -> symbol, avoids repeat lookups


def resolve_token_symbols(text: str) -> str:
    """
    X's raw tweet text sometimes contains 'chain:0xaddress' references
    where the tweet visually shows a token symbol like '$XPR' on x.com
    (a display-only "smart tag" X adds — not present in the actual API
    data). This looks up the real symbol via CoinGecko's free API and
    substitutes it in as '$SYMBOL (0xaddr...)' so alerts are readable.
    Best-effort: leaves text unchanged for anything that fails to resolve.
    """
    pattern = re.compile(r'\b(' + '|'.join(CHAIN_TO_COINGECKO_PLATFORM) + r'):(0x[a-fA-F0-9]{40})\b')

    def replace_match(m):
        chain, address = m.group(1), m.group(2)
        cache_key = f"{chain}:{address.lower()}"
        if cache_key in _token_symbol_cache:
            symbol = _token_symbol_cache[cache_key]
        else:
            platform = CHAIN_TO_COINGECKO_PLATFORM[chain]
            try:
                resp = requests.get(
                    f"https://api.coingecko.com/api/v3/coins/{platform}/contract/{address}",
                    timeout=10,
                )
                if resp.status_code == 200:
                    symbol = resp.json().get("symbol", "").upper()
                else:
                    symbol = ""
            except Exception as e:
                print(f"Token symbol lookup failed for {cache_key}: {e}", file=sys.stderr)
                symbol = ""
            _token_symbol_cache[cache_key] = symbol

        short_addr = f"{address[:6]}...{address[-4:]}"
        if symbol:
            return f"${symbol} ({short_addr})"
        return m.group(0)  # couldn't resolve — leave the original text as-is

    return pattern.sub(replace_match, text)


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
    Sends one clearly-labeled TEST alert through the full pipeline
    (AI scoring, translation, Telegram formatting) so you can verify
    everything is wired correctly, or check what score a specific real
    tweet would get, without waiting for it to appear via X search.
    Triggered by setting SELF_TEST_ON_START=true.

    By default, scores a built-in fake example. To test a real tweet
    instead, also set:
      TEST_TWEET_TEXT     = the tweet's full text (required)
      TEST_TWEET_USERNAME = the author's handle, no @ (optional)
    """
    print("Running self-test: sending a sample alert through the full pipeline...")

    custom_text = os.environ.get("TEST_TWEET_TEXT")
    if custom_text:
        test_tweet = {
            "id": "0000000000000000000",
            "text": custom_text,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {"like_count": 0, "retweet_count": 0},
            "username": os.environ.get("TEST_TWEET_USERNAME", "unknown"),
            "name": "",
        }
        print(f"Using custom TEST_TWEET_TEXT (author: @{test_tweet['username']})")
    else:
        test_tweet = {
            "id": "0000000000000000000",
            "text": "TEST ALERT: This is a sample tweet simulating a wallet drained "
                    "in a DeFi exploit, used only to verify your bot setup.",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "metrics": {"like_count": 123, "retweet_count": 45},
            "username": "test_account",
            "name": "Self-Test",
        }

    test_tweet["text"] = resolve_token_symbols(test_tweet["text"])

    ai_result = classify_with_ai(test_tweet)
    if not ai_result:
        print("AI classification failed — both Claude and Grok were unreachable/"
              "erroring, or neither is configured. Scoring is AI-only now, so no "
              "alert can be sent. Check ANTHROPIC_API_KEY / XAI_API_KEY.",
              file=sys.stderr)
        send_system_alert(
            "Self-test: AI classification failed on both Claude and Grok. "
            "Scoring is AI-only — check ANTHROPIC_API_KEY / XAI_API_KEY."
        )
        return

    score, label, summary, reasoning = ai_result
    print(f"Scored via AI: {label} {score}/100 — {reasoning}")

    zh_text = translate_to_chinese(test_tweet["text"])
    message = "🧪 <b>SELF-TEST — not a real incident</b>\n\n" + format_alert(
        test_tweet, score, label, zh_text, summary
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


# Scoring is AI-only — no keyword-based fallback. classify_with_ai()
# already tries Claude, then Grok, before giving up (see call_ai()); this
# only fires once BOTH have failed. Tweets during that window are skipped
# (not silently keyword-scored) and you're paged on Telegram instead,
# cooldown-guarded so a stuck outage doesn't spam you once per tweet.
_last_ai_failure_alert_at = None
AI_FAILURE_ALERT_COOLDOWN_SECONDS = 1800  # 30 min


def note_ai_failure_and_maybe_alert():
    global _last_ai_failure_alert_at
    now = datetime.now(timezone.utc)
    cooldown_elapsed = (
        _last_ai_failure_alert_at is None
        or (now - _last_ai_failure_alert_at).total_seconds() > AI_FAILURE_ALERT_COOLDOWN_SECONDS
    )
    if cooldown_elapsed:
        send_system_alert(
            "AI classification is unreachable or failing on BOTH Claude and "
            "Grok (or neither is configured). Scoring is AI-only — tweets "
            "are being SKIPPED (not keyword-scored) until this recovers, so "
            "you may be missing real incidents right now. Check "
            "ANTHROPIC_API_KEY / XAI_API_KEY."
        )
        _last_ai_failure_alert_at = now


def run_once(since_id):
    tweets, newest_id, error = search_recent_tweets(since_id)
    if tweets:
        print(f"[{datetime.now(timezone.utc).isoformat()}] {len(tweets)} new candidate tweet(s).")

    for tweet in tweets:
        metrics = tweet.get("metrics", {})
        likes = metrics.get("like_count", 0)

        # Resolve any 'chain:0xaddress' references to readable token
        # symbols before this text is used anywhere downstream.
        tweet["text"] = resolve_token_symbols(tweet["text"])

        preview = tweet["text"][:80].replace("\n", " ")

        ai_result = classify_with_ai(tweet)
        if not ai_result:
            print(f"  [SKIPPED — AI unreachable] {likes} likes @{tweet['username']}: {preview}",
                  file=sys.stderr)
            note_ai_failure_and_maybe_alert()
            continue

        score, label, summary, reasoning = ai_result

        # Always log the score, even for tweets that won't alert — this is
        # what you want to watch to calibrate MIN_RISK_SCORE_TO_ALERT and
        # MIN_ENGAGEMENT_FILTER against real traffic.
        print(f"  [{label} {score}/100] {likes} likes @{tweet['username']}: {preview}")
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
    for i, q in enumerate(build_queries(), start=1):
        print(f"Search query {i}: {q}")

    if not X_BEARER_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: Missing one or more required env vars: X_BEARER_TOKEN, "
              "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID.", file=sys.stderr)
        sys.exit(1)

    if not ANTHROPIC_API_KEY and not XAI_API_KEY:
        print("ERROR: Neither ANTHROPIC_API_KEY nor XAI_API_KEY is set. "
              "Scoring is AI-only — the bot cannot classify any tweets "
              "without at least one of these configured.", file=sys.stderr)
        sys.exit(1)

    print(
        "AI provider(s): "
        + (f"Claude ({CLAUDE_MODEL}) primary" if ANTHROPIC_API_KEY else "Claude NOT configured")
        + ", "
        + (f"Grok ({GROK_MODEL}) fallback" if XAI_API_KEY else "Grok NOT configured")
    )

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
