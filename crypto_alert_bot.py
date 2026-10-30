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

try:
    import redis as redis_lib
except ImportError:
    redis_lib = None

# ---------------------------------------------------------------------------
# Configuration (all pulled from environment variables / GitHub Secrets)
# ---------------------------------------------------------------------------

X_BEARER_TOKEN = os.environ.get("X_BEARER_TOKEN")
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")
DEEPL_API_KEY = os.environ.get("DEEPL_API_KEY")  # optional but strongly recommended

# --- Which AI scores the tweets (change these in Railway variables) ---------
#   AI_PROVIDER           "grok" (default) or "deepseek"
#   AI_FALLBACK_PROVIDER  optional: the other one, tried only if the main AI
#                         fails completely. Leave empty for none.
# Each provider needs its own key: XAI_API_KEY for Grok, DEEPSEEK_API_KEY for
# DeepSeek (only the ones you actually use).
AI_PROVIDER = os.environ.get("AI_PROVIDER", "grok").strip().lower()
AI_FALLBACK_PROVIDER = os.environ.get("AI_FALLBACK_PROVIDER", "").strip().lower()

XAI_API_KEY = os.environ.get("XAI_API_KEY")
GROK_MODEL = os.environ.get("GROK_MODEL", "grok-4.3")
# Optional second Grok model, used only when GROK_MODEL is overloaded ("at
# capacity", 5xx, timeouts). Leave unset to disable.
GROK_FALLBACK_MODEL = os.environ.get("GROK_FALLBACK_MODEL", "")

DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY")
# Check the current model name on platform.deepseek.com (names change).
DEEPSEEK_MODEL = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
DEEPSEEK_FALLBACK_MODEL = os.environ.get("DEEPSEEK_FALLBACK_MODEL", "")
DEEPSEEK_BASE_URL = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
# Ask DeepSeek to return strict JSON. Set to 0 if it ever rejects the request.
DEEPSEEK_JSON_MODE = os.environ.get("DEEPSEEK_JSON_MODE", "1") != "0"
# DeepSeek's newer models "think" first, and that hidden thinking eats the
# max_tokens budget (empty or cut-off JSON replies). We turn thinking off, and
# give DeepSeek a roomier token limit as a safety margin (you pay only for
# tokens actually produced). Set DEEPSEEK_THINKING= (empty) to not send the
# switch at all.
DEEPSEEK_THINKING = os.environ.get("DEEPSEEK_THINKING", "disabled").strip().lower()
DEEPSEEK_MAX_TOKENS = int(os.environ.get("DEEPSEEK_MAX_TOKENS", "1500"))

AI_PROVIDERS = {
    "grok": {
        "name": "Grok", "key": lambda: XAI_API_KEY, "model": lambda: GROK_MODEL,
        "fallback_model": lambda: GROK_FALLBACK_MODEL,
        "url": "https://api.x.ai/v1/chat/completions", "json_mode": False,
    },
    "deepseek": {
        "name": "DeepSeek", "key": lambda: DEEPSEEK_API_KEY, "model": lambda: DEEPSEEK_MODEL,
        "fallback_model": lambda: DEEPSEEK_FALLBACK_MODEL,
        "url": DEEPSEEK_BASE_URL.rstrip("/") + "/chat/completions",
        "json_mode": DEEPSEEK_JSON_MODE,
        "extra": ({"thinking": {"type": DEEPSEEK_THINKING}} if DEEPSEEK_THINKING else {}),
        "max_tokens": DEEPSEEK_MAX_TOKENS,
    },
}


def _ai_attempts():
    """Ordered list of (provider, model) to try for each tweet: the main
    provider's model, its optional backup model, then the fallback provider."""
    out = []
    for prov in [AI_PROVIDER, AI_FALLBACK_PROVIDER]:
        cfg = AI_PROVIDERS.get(prov)
        if not cfg or not cfg["key"]() or any(a[0] == prov for a in out):
            continue
        out.append((prov, cfg["model"]()))
        if cfg["fallback_model"]():
            out.append((prov, cfg["fallback_model"]()))
    return out

# Sent as its own Telegram message right after every NEW-case alert.
# Override with the NEW_CASE_REMINDER env var; set it empty to turn it off.
NEW_CASE_REMINDER = os.environ.get(
    "NEW_CASE_REMINDER",
    "Don't forget to close deposit/withdrawal, and deposit not credited, also inform MM",
)
GROK_TIMEOUT_SECONDS = int(os.environ.get("GROK_TIMEOUT_SECONDS", "40"))   # per request
GROK_TOTAL_BUDGET_SECONDS = int(os.environ.get("GROK_TOTAL_BUDGET_SECONDS", "75"))  # per tweet, all retries
GROK_MIN_INTERVAL_SECONDS = float(os.environ.get("GROK_MIN_INTERVAL_SECONDS", "1.0"))  # between calls

# How often to poll, in seconds. 30-60s gives near-real-time alerts without
# hammering X's rate limit (450 search requests / 15 min per app).
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "45"))

# On first startup only (no since_id yet), how far back to look so we don't
# miss anything but also don't backfill hours of history.
INITIAL_LOOKBACK_MINUTES = int(os.environ.get("INITIAL_LOOKBACK_MINUTES", "5"))

# Minimum likes a tweet needs to trigger an alert. Applied client-side
# after fetching — X's pay-per-use tier doesn't support engagement-based
# query operators (min_faves), so this reduces alert noise, not read cost.
MIN_ENGAGEMENT_FILTER = int(os.environ.get("MIN_ENGAGEMENT_FILTER", "0"))

# ---------------------------------------------------------------------------
# Persistent case store (Redis) — one structured record per incident,
# keyed by a short "case_key" made of up to 3 distinctive keywords (e.g.
# "ledger_cryptobilis_asia"). It survives restarts/redeploys and has no fixed
# retention window, so "have we already told the risk officer about this
# incident" can be answered days or weeks later.
#
# Only active when REDIS_URL is set (a free Railway Redis add-on works
# fine). Without it, the bot still runs exactly as before — no case
# tracking, no dedup-by-case, no on-demand case reports — it just can't
# remember incidents across restarts.
# ---------------------------------------------------------------------------

REDIS_URL = os.environ.get("REDIS_URL")
CASE_KEY_PREFIX = "crypto_alert_bot:case:"
CASE_INDEX_KEY = "crypto_alert_bot:case_index"  # a Redis SET of every known case_key
CASE_MAX_UPDATES_STORED = 40  # cap per-case update history so records can't grow unbounded

_redis_client = None
_redis_unavailable_warned = False


def get_redis():
    """
    Returns a connected Redis client, or None if REDIS_URL isn't set or the
    library/connection isn't available. Callers should treat None as "case
    tracking is off" and degrade gracefully (skip persistence, don't crash).
    """
    global _redis_client, _redis_unavailable_warned
    if not REDIS_URL:
        return None
    if redis_lib is None:
        if not _redis_unavailable_warned:
            print("REDIS_URL is set but the 'redis' package isn't installed — "
                  "case tracking is disabled. Check requirements.txt.", file=sys.stderr)
            _redis_unavailable_warned = True
        return None
    if _redis_client is None:
        try:
            _redis_client = redis_lib.from_url(REDIS_URL, decode_responses=True, socket_timeout=5)
            _redis_client.ping()
        except Exception as e:
            if not _redis_unavailable_warned:
                print(f"Could not connect to Redis (case tracking disabled): {e}", file=sys.stderr)
                _redis_unavailable_warned = True
            _redis_client = None
    return _redis_client


def get_case(case_key: str):
    """Returns the stored case dict for case_key, or None if it doesn't exist / Redis is off."""
    r = get_redis()
    if not r or not case_key:
        return None
    raw = r.get(CASE_KEY_PREFIX + case_key)
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def save_case(case_key: str, case: dict):
    """Persists a case dict and registers it in the searchable index."""
    r = get_redis()
    if not r or not case_key:
        return
    r.set(CASE_KEY_PREFIX + case_key, json.dumps(case))
    r.sadd(CASE_INDEX_KEY, case_key)


def list_case_keys() -> list[str]:
    """Returns every known case_key (used by case_report.py to search)."""
    r = get_redis()
    if not r:
        return []
    return sorted(r.smembers(CASE_INDEX_KEY))


# The AI is shown the keys of recently-active cases so it can reuse one for a
# tweet about the same incident. Keys only (no field dump) keeps this cheap.
OPEN_CASES_CONTEXT_LIMIT = int(os.environ.get("OPEN_CASES_CONTEXT_LIMIT", "10"))
OPEN_CASES_CONTEXT_HOURS = int(os.environ.get("OPEN_CASES_CONTEXT_HOURS", "24"))


def get_open_cases_context() -> str:
    """Comma-separated case_keys of cases active in the last
    OPEN_CASES_CONTEXT_HOURS (max OPEN_CASES_CONTEXT_LIMIT), newest first,
    fed to the classifier so it can reuse a key. "(none yet)" if empty."""
    r = get_redis()
    if not r:
        return "(none yet)"
    case_keys = list_case_keys()
    if not case_keys:
        return "(none yet)"

    cases = [c for c in (get_case(k) for k in case_keys) if c]
    cases.sort(key=lambda c: c.get("last_seen", ""), reverse=True)

    # Keys only (no field dump) and only cases active recently: the AI just
    # needs the names to reuse one. Everything else is handled in code.
    now = datetime.now(timezone.utc)
    keys = []
    for c in cases:
        try:
            age_hours = (now - datetime.fromisoformat(c.get("last_seen", ""))).total_seconds() / 3600
        except ValueError:
            continue
        if age_hours <= OPEN_CASES_CONTEXT_HOURS:
            keys.append(c["case_key"])
        if len(keys) >= OPEN_CASES_CONTEXT_LIMIT:
            break
    return ", ".join(keys) if keys else "(none yet)"


# Fields we track structured facts in, beyond the free-text summary — these
# are what get diffed to decide whether a repeat mention of a known case
# counts as "new information" worth alerting on again.
CASE_TRACKED_FIELDS = [
    "tokens_affected", "estimated_loss_usd", "latest_official_response",
    "hacker_addresses", "asset_movement", "status",
]

# Of CASE_TRACKED_FIELDS, only these re-trigger a Telegram alert when they
# change on a case you already know about (the FIRST alert for a new case
# always fires regardless). Rationale: once an incident is known, a rising
# loss estimate or reworded official statement isn't actionable — what's
# actionable is where the stolen funds are moving and who holds them now,
# or the incident wrapping up (funds recovered/attacker caught). Edit this
# set if you want more/less re-alerting on updates.
ALERT_WORTHY_UPDATE_FIELDS = {
    "asset_movement", "hacker_addresses", "status", "latest_official_response",
}

# Placeholder values the AI might legitimately return that should NOT count
# as real information when diffing (so they don't falsely trigger "this is
# new" the first time a field goes from empty to "unknown").
_CASE_FIELD_EMPTY_VALUES = {"", "unknown", "not stated", "n/a", "none", "not specified"}


def _normalize_case_field(value: str) -> str:
    return (value or "").strip().lower()


# tokens_affected/hacker_addresses are comma-separated lists — the AI can
# reorder or reformat them tweet to tweet without meaning anything changed,
# so these are compared as sets (and only "changed" if the new set adds
# something not already known), not as exact strings.
_CASE_FIELD_LIST_TYPE = {"tokens_affected", "hacker_addresses"}

# A new loss estimate only counts as "changed" once it moves more than this
# fraction away from the old one — small re-estimates ($19.8M -> $20.1M)
# are noise, not new information.
_CASE_FIELD_USD_TOLERANCE = 0.25

_USD_AMOUNT_RE = re.compile(r"\$?\s*([\d.]+)\s*(k|m|b|thousand|million|billion)?")
_USD_UNIT_MULTIPLIERS = {
    "k": 1e3, "thousand": 1e3,
    "m": 1e6, "million": 1e6,
    "b": 1e9, "billion": 1e9,
}


def _extract_usd_amount(text: str) -> float | None:
    """Pulls a rough USD figure out of strings like '~$20M', '$109K', or
    '$3.2 million' (already-lowercased text). None if no number is found."""
    match = _USD_AMOUNT_RE.search(text.replace(",", ""))
    if not match:
        return None
    try:
        amount = float(match.group(1))
    except ValueError:
        return None
    return amount * _USD_UNIT_MULTIPLIERS.get(match.group(2) or "", 1)


# Common English filler words stripped before comparing narrative fields —
# without this, two rewordings of the same fact ("paused... investigating"
# vs "remains paused while the investigation continues") can share so few
# CONTENT words that overlap looks artificially low.
_ENGLISH_STOPWORDS = {
    "and", "the", "has", "is", "at", "while", "to", "a", "an", "of", "in",
    "on", "for", "with", "was", "were", "it", "its", "this", "that", "are",
    "been", "being", "from", "as", "by", "so", "far", "still", "now",
}


def _word_set(text: str) -> set[str]:
    return {
        w for w in re.findall(r"[a-z0-9']+", text)
        if len(w) > 2 and w not in _ENGLISH_STOPWORDS
    }


def _case_field_changed(field: str, old_val: str, new_val: str) -> bool:
    """For the fields not handled by the fact / status rules in
    diff_case_fields(): list fields change when an item is added; the loss
    estimate changes when it moves more than 25%. Both values are already
    lowercased/stripped."""
    if field in _CASE_FIELD_LIST_TYPE:
        old_set = {v.strip() for v in old_val.split(",") if v.strip()}
        new_set = {v.strip() for v in new_val.split(",") if v.strip()}
        return not new_set.issubset(old_set)

    if field == "estimated_loss_usd":
        old_amount = _extract_usd_amount(old_val)
        new_amount = _extract_usd_amount(new_val)
        if old_amount and new_amount:
            return abs(new_amount - old_amount) / old_amount > _CASE_FIELD_USD_TOLERANCE
        return False  # can't compare; loss revisions aren't news anyway

    return new_val != old_val


# Wallet / tx-hash looking strings (0x..., bc1.../1.../3... BTC, long base58
# like Solana) — pulled out of text so "new address" can be detected
# objectively instead of by comparing the AI's wording.
_ADDR_RE = re.compile(
    r"0x[a-f0-9]{6,}"
    r"|\b(?:bc1|[13])[a-z0-9]{25,60}\b"
    r"|\b(?=[a-z0-9]*\d)(?=[a-z0-9]*[a-z])[a-z0-9]{32,}\b"
)
_AMOUNT_RE = re.compile(
    r"(\$)?\s?(\d+(?:\.\d+)?)\s?(k|m|b|thousand|million|billion)?\s?"
    r"(eth|btc|usdt|usdc|sol|bnb|trx|dai|usd|weth|wbtc|steth)?\b"
)


def _extract_facts(text: str) -> set[str]:
    """Objective facts in a piece of text: wallet/tx strings and money
    amounts (rounded to 2 significant digits, so '$20.1M' == '$20M').
    Used to decide whether a reworded field carries anything NEW."""
    t = (text or "").lower().replace(",", "")
    facts = {m.group(0) for m in _ADDR_RE.finditer(t)}
    t_no_addr = _ADDR_RE.sub(" ", t)
    for m in _AMOUNT_RE.finditer(t_no_addr):
        dollar, num, unit, sym = m.groups()
        if not (dollar or unit or sym):
            continue  # bare number, not money
        try:
            v = float(num) * _USD_UNIT_MULTIPLIERS.get(unit or "", 1)
        except ValueError:
            continue
        if v > 0:
            facts.add("amt:%.1e" % v)
    return facts


_STATUS_RANK = {"ongoing": 1, "active": 1, "contained": 2, "resolved": 3}


def _status_rank(value: str) -> int:
    v = (value or "").strip().lower()
    for k, r in _STATUS_RANK.items():
        if v.startswith(k):
            return r
    return 0


# Narrative fields where a reworded repeat must NOT count as news.
_CASE_FIELD_FACT_TYPE = {"asset_movement", "latest_official_response"}
# Below this word-overlap with EVERY previously seen version, a fact-less
# narrative is treated as a genuinely different statement.
_CASE_FIELD_HISTORY_OVERLAP_THRESHOLD = 0.15


def diff_case_fields(old_case: dict, new_fields: dict) -> list[str]:
    """
    Returns which tracked fields carry genuinely NEW information versus
    everything already known for this case. Objective rules, not wording:
      - status: only when it moves FORWARD (ongoing -> contained -> resolved).
      - hacker_addresses / tokens_affected: only when a new item appears.
      - asset_movement / latest_official_response: only when the text holds
        a wallet/tx string or money amount not already seen in this case;
        if it holds none, only when it is very different from every
        earlier version. Rewording alone never counts.
      - estimated_loss_usd: big (25%+) moves only (not alert-worthy anyway).
    The baseline is the case's whole history (known_facts), not just the
    last stored value, so wording that flips back and forth can't re-fire.
    """
    changed = []
    known = set(old_case.get("known_facts", []))
    history = old_case.get("history", {})
    for field in CASE_TRACKED_FIELDS:
        new_val = _normalize_case_field(new_fields.get(field, ""))
        old_val = _normalize_case_field(old_case.get(field, ""))
        if new_val in _CASE_FIELD_EMPTY_VALUES:
            continue
        if field == "status":
            if _status_rank(new_val) > _status_rank(old_val):
                changed.append(field)
            continue
        if old_val in _CASE_FIELD_EMPTY_VALUES:
            changed.append(field)  # first time we learn this field
            continue
        if field in _CASE_FIELD_FACT_TYPE:
            new_facts = _extract_facts(new_val)
            if new_facts:
                if new_facts - known:
                    changed.append(field)
                continue
            versions = [old_val] + [_normalize_case_field(v) for v in history.get(field, [])]
            if all(_case_overlap(v, new_val) < _CASE_FIELD_HISTORY_OVERLAP_THRESHOLD
                   for v in versions):
                changed.append(field)
            continue
        if _case_field_changed(field, old_val, new_val):
            changed.append(field)
    return changed


def _case_overlap(a: str, b: str) -> float:
    # 5-letter prefixes so spelling/tense variants match (unauthorized /
    # unauthorised, confirmed / confirms).
    wa = {w[:5] for w in _word_set(a)}
    wb = {w[:5] for w in _word_set(b)}
    if not wa or not wb:
        return 0.0 if a != b else 1.0
    return len(wa & wb) / len(wa | wb)


# Words that can never be a case's identity: incident-report boilerplate and
# very common asset/market words. A case_key is built from the OTHER words —
# the project, company, attacker, victim or place — and two keys describe the
# same incident when they share one of those.
_GENERIC_WORDS = {
    # incident boilerplate
    "exploit", "exploited", "hack", "hacked", "hacker", "hackers", "incident",
    "attack", "attacked", "attacker", "attackers", "breach", "breached",
    "halt", "halted", "halting", "suspended", "paused", "frozen",
    "vulnerability", "governance", "validators", "validator", "network",
    "chain", "protocol", "unknown", "token", "tokens", "security", "issue",
    "supply", "stolen", "drained", "compromised", "phishing", "scam",
    "breaking", "update", "alert", "report", "reports", "reported",
    "confirmed", "confirms", "official", "urgent", "just", "today", "now",
    "according", "sources", "amid", "major", "massive", "huge", "new",
    "another", "latest", "multiple", "several", "users", "wallet", "wallets",
    "funds", "million", "billion", "this", "that", "with", "from", "warning",
    "caution", "news", "investigating", "investigation", "unauthorized", "peg", "withdrawals", "withdrawal", "deposits", "bridge",
    "unauthorised", "implant", "backend", "spoofing", "the", "and", "for",
    # very common market words
    "crypto", "bitcoin", "ethereum", "solana", "btc", "eth", "sol", "usdt",
    "usdc", "defi", "web3", "exchange", "blockchain", "mainnet", "dex",
    "bnb", "bsc", "nft", "dao",
}

CASE_KEY_MAX_WORDS = 3

# How far back to look for a case to fold a new tweet into. Long enough to
# catch an incident re-reported over several days, short enough not to merge
# into long-resolved cases that merely share a project name.
CASE_MERGE_LOOKBACK_HOURS = 24 * 7


def _key_words(case_key: str) -> list[str]:
    """Distinctive words of a case_key, in order, without repeats."""
    seen, out = set(), []
    for w in (case_key or "").lower().split("_"):
        if w in seen or w in _GENERIC_WORDS or w.isdigit() or len(w) < 3:
            continue
        seen.add(w)
        out.append(w)
    return out


def _words_from_text(tweet_text: str) -> list[str]:
    """Last-resort key words taken from the tweet itself: its capitalised
    names and $TICKERS that aren't generic, first CASE_KEY_MAX_WORDS."""
    out = []
    for m in re.findall(r"\$?\b[A-Za-z][A-Za-z0-9]{2,}\b", tweet_text):
        if not (m[0].isupper() or m[0] == "$"):
            continue
        w = m.lstrip("$").lower()
        if w in _GENERIC_WORDS or w in out or w.isdigit():
            continue
        out.append(w)
        if len(out) >= CASE_KEY_MAX_WORDS:
            break
    return out


def resolve_case_key(candidate_key: str, tweet_text: str = "", tweet_id: str = "") -> str:
    """
    Turns the AI's proposed case_key into the key this tweet is filed under.

    1. If it is an existing case and the tweet mentions one of its keywords,
       use it as is. (An existing key whose keywords the tweet never mentions
       is a wrong reuse — it is rejected.)
    2. Otherwise keep only the proposed keywords that literally appear in the
       tweet (max 3) — this drops invented or generic words. If none are
       left, take names from the tweet text instead.
    3. If any of those words is shared with a case active in the last 7
       days, file the tweet under that case (earliest one wins) — this joins
       the Ledger tweets that say "ledger" with those that say "ledger
       cryptobilis".
    4. Otherwise it is a new case keyed by those words.
    """
    r = get_redis()
    text_lower = (tweet_text or "").lower()
    existing_keys = set(list_case_keys()) if r else set()

    if candidate_key in existing_keys:
        words = _key_words(candidate_key)
        if not tweet_text or not words or any(w in text_lower for w in words):
            return candidate_key
        print(f"    -> case_key sanity check failed: AI proposed reusing "
              f"'{candidate_key}' but the tweet mentions none of its keywords "
              f"({', '.join(words)}) — treating it as a different incident.",
              file=sys.stderr)

    words = _key_words(candidate_key)
    if tweet_text:
        words = [w for w in words if w in text_lower]
        if not words:
            words = _words_from_text(tweet_text)
    words = words[:CASE_KEY_MAX_WORDS]

    if r and words:
        now = datetime.now(timezone.utc)
        best = None  # (first_seen_iso, case_key)
        for key in existing_keys:
            if not set(words) & set(_key_words(key)):
                continue
            case = get_case(key)
            if not case:
                continue
            try:
                age_h = (now - datetime.fromisoformat(case.get("last_seen", ""))).total_seconds() / 3600
            except ValueError:
                continue
            if age_h > CASE_MERGE_LOOKBACK_HOURS:
                continue
            first = case.get("first_seen") or case.get("last_seen", "")
            if best is None or first < best[0]:
                best = (first, key)
        if best:
            return best[1]

    key = "_".join(words) if words else f"unknown_{(tweet_id or 'x')[-6:]}"
    base, n = key, 2
    while key in existing_keys:  # only reachable for a rejected reuse
        key = f"{base}_{n}"
        n += 1
    return key


def _set_case_flag(case_key: str, flag: str, value) -> None:
    case = get_case(case_key)
    if case is not None:
        case[flag] = value
        save_case(case_key, case)


def upsert_case(case_key: str, tweet: dict, score: int, label: str, summary: str,
                 fields: dict) -> tuple[bool, list[str]]:
    """
    Creates or updates the persistent record for case_key with this tweet's
    info. Returns (is_new_case, changed_fields) — is_new_case is True the
    very first time this case_key is seen; changed_fields lists which
    tracked fields (see CASE_TRACKED_FIELDS) actually carried new
    information versus what was already stored. Callers use this to decide
    whether to alert (new case, or changed_fields non-empty) or suppress
    (existing case, nothing new) while still recording the update either way.
    """
    now_iso = datetime.now(timezone.utc).isoformat()
    existing = get_case(case_key)
    is_new = existing is None

    if is_new:
        changed_fields = [f for f in CASE_TRACKED_FIELDS
                           if _normalize_case_field(fields.get(f, "")) not in _CASE_FIELD_EMPTY_VALUES]
        case = {
            "case_key": case_key,
            "display_name": case_key.replace("_", " ").title(),
            "first_seen": now_iso,
            "last_seen": now_iso,
            "updates": [],
        }
        for f in CASE_TRACKED_FIELDS:
            case[f] = fields.get(f, "") or ""
    else:
        changed_fields = diff_case_fields(existing, fields)
        case = existing
        case["last_seen"] = now_iso
        hist = case.setdefault("history", {})
        for f in changed_fields:
            if case.get(f):
                hist.setdefault(f, []).append(case[f])
                hist[f] = hist[f][-5:]
            case[f] = fields.get(f, "") or ""

    # Remember every concrete fact (wallet/tx strings, amounts) ever seen
    # for this case — from the AI's fields AND the raw tweet text — so the
    # same fact reworded later is never treated as news again.
    known = set(case.get("known_facts", []))
    for f in ("asset_movement", "latest_official_response", "hacker_addresses"):
        known |= _extract_facts(fields.get(f, ""))
    known |= {x for x in _extract_facts(tweet.get("text", "")) if not x.startswith("amt:")}
    case["known_facts"] = sorted(known)[-300:]

    case["updates"].append({
        "time": now_iso,
        "username": tweet.get("username", "unknown"),
        "tweet_id": tweet.get("id", ""),
        "score": score,
        "label": label,
        "summary": summary,
    })
    case["updates"] = case["updates"][-CASE_MAX_UPDATES_STORED:]

    save_case(case_key, case)
    return is_new, changed_fields


_last_grok_call_at = 0.0


def _call_grok(system_prompt: str, user_message: str, max_tokens: int,
               model: str | None = None, fast_fail: bool = False,
               provider: str = "grok") -> str:
    """Calls the chosen AI's chat API (Grok or DeepSeek, same request
    format; the name is historical). Calls are spaced at least GROK_MIN_INTERVAL_SECONDS
    apart (a batch of tweets would otherwise burst into xAI's rate limit).
    Retries on rate limits (429), server errors (5xx), timeouts and dropped
    connections, but gives up after GROK_TOTAL_BUDGET_SECONDS in total so one
    bad moment at xAI can't freeze the poll loop. With fast_fail, an
    "at capacity" 429 raises at once so the caller can switch models.
    Raises on failure."""
    global _last_grok_call_at
    cfg = AI_PROVIDERS[provider]
    pname = cfg["name"]
    payload = {
        "model": model or cfg["model"](),
        "max_tokens": max(max_tokens, cfg.get("max_tokens", 0)),
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message},
        ],
    }
    if cfg["json_mode"]:
        payload["response_format"] = {"type": "json_object"}
    payload.update(cfg.get("extra", {}))
    headers = {
        "Authorization": f"Bearer {cfg['key']()}",
        "Content-Type": "application/json",
    }
    deadline = time.time() + GROK_TOTAL_BUDGET_SECONDS
    last_error = "unknown"
    for attempt in range(4):
        gap = GROK_MIN_INTERVAL_SECONDS - (time.time() - _last_grok_call_at)
        if gap > 0:
            time.sleep(gap)
        _last_grok_call_at = time.time()
        wait = 2 ** (attempt + 1)  # 2s, 4s, 8s
        try:
            resp = requests.post(cfg["url"], headers=headers,
                                 json=payload, timeout=GROK_TIMEOUT_SECONDS)
        except (requests.Timeout, requests.ConnectionError) as e:
            last_error = type(e).__name__
        else:
            if resp.ok:
                data = resp.json()
                choice = data["choices"][0]
                content = (choice["message"].get("content") or "").strip()
                if content and choice.get("finish_reason") != "length":
                    return content
                last_error = (f"{'cut-off' if content else 'empty'} reply from {pname} "
                              f"(finish_reason={choice.get('finish_reason')}, "
                              f"usage={data.get('usage')})")
                resp = None
            # Include the provider's own explanation (spend limit, blocked key,
            # content filter...) — the bare status code hides it.
            if resp is not None:
                last_error = f"{resp.status_code} from {pname}: {resp.text[:300]}"
                if resp.status_code != 429 and resp.status_code < 500:
                    raise RuntimeError(last_error)  # not worth retrying
                if fast_fail and "capacity" in resp.text.lower():
                    raise RuntimeError(last_error)  # overloaded model: switch instead of waiting
                try:
                    wait = float(resp.headers.get("Retry-After", ""))
                except ValueError:
                    pass
        wait = min(max(wait, 1), 15)
        if attempt == 3 or time.time() + wait > deadline:
            break
        print(f"{pname} {last_error[:60]} — retrying in {wait:.0f}s ({attempt + 1}/3)...", file=sys.stderr)
        time.sleep(wait)
    raise RuntimeError(f"gave up after retries: {last_error}")



# Common false-positive phrases that share words with our incident terms
# but are almost never real crypto security incidents (growth hacking,
# hackathons, unrelated giveaway/airdrop spam). Excluded directly in the
# X query to cut billed noise.
NOISE_EXCLUSIONS = ["giveaway", "airdrop"]

# Hard cap on how many tweets we pull per poll — mainly a safety ceiling for
# traffic bursts, since since_id tracking already prevents re-reads.
MAX_RESULTS = int(os.environ.get("MAX_RESULTS", "10"))

# If a single poll finds more new matching tweets than MAX_RESULTS, this
# caps how many additional pages we'll fetch to catch the rest — without
# this, anything beyond the first page would be silently and permanently
# skipped once since_id advances past it. Each extra page = one more
# billed batch of reads, so this bounds worst-case cost per poll.
PAGINATION_MAX_PAGES = int(os.environ.get("PAGINATION_MAX_PAGES", "3"))

# Only alert (send to Telegram) if the computed risk score is at least
# this high (0-100).
MIN_RISK_SCORE_TO_ALERT = int(os.environ.get("MIN_RISK_SCORE_TO_ALERT", "25"))

# Only PERSIST a case to Redis if the score is at least this high — lower
# than MIN_RISK_SCORE_TO_ALERT on purpose. A tweet can be too weak/unclear
# on its own to page you about, but still worth quietly recording, so that
# if a LATER tweet firms it up into something alert-worthy, the case
# already has this earlier context (first_seen, an early field value,
# etc.) instead of starting from nothing. Defaults to MIN_RISK_SCORE_TO_ALERT
# minus 15 (floored at 0) if not set, so out of the box tracking is a bit
# more permissive than alerting without needing extra configuration.
MIN_RISK_SCORE_TO_TRACK = int(os.environ.get(
    "MIN_RISK_SCORE_TO_TRACK", str(max(0, MIN_RISK_SCORE_TO_ALERT - 15))
))

# ---------------------------------------------------------------------------
# Keyword / query strategy
# ---------------------------------------------------------------------------

# One X search per poll: (any INCIDENT_TERMS) AND (any CONTEXT_TERMS), minus
# NOISE_EXCLUSIONS. X caps the query string at 512 characters — check
# len(build_queries()[0]) after editing these lists (currently ~464).

INCIDENT_TERMS = [
    "exploit", "hacked", "breach", "drained", "compromised",
    "laundering", "launder", "unauthorized", "flash loan",
    "oracle manipulation", "stolen", "phishing",
    # Softer/operational-disclosure vocabulary — real incidents often
    # surface with these FIRST, before anyone says "exploit"/"hacked".
    "halted", "suspended", "paused", "frozen", "vulnerability",
    "incident", "under investigation",
]

# Context (crypto-relevance) terms ANDed against INCIDENT_TERMS.
CONTEXT_TERMS = [
    "crypto", "bitcoin", "ethereum", "solana", "defi",
    "exchange", "dex", "bsc", "bnb", "eth", "btc",
    "blockchain", "mainnet", "chain", "validators", "governance",
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
    """Returns the X search query string(s) run every poll — currently one."""
    return [_build_one_query(INCIDENT_TERMS, CONTEXT_TERMS)]


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
    """Runs the single X search query. Returns (tweets, newest_id,
    error_message); error_message is None on success (even with zero
    matches — a quiet period is normal)."""
    if not X_BEARER_TOKEN:
        print("ERROR: X_BEARER_TOKEN is not set.", file=sys.stderr)
        sys.exit(1)
    return _search_one_query(build_queries()[0], since_id)


def _build_classification_prompt(trusted_list: str) -> str:
    return (
        "Is this tweet reporting that a crypto attack, hack, exploit or "
        "security incident is happening RIGHT NOW? Tweets from trusted "
        f"accounts score higher. Trusted: {trusted_list}.\n\n"
        "Respond with ONLY valid JSON (no markdown):\n"
        '{"is_real_incident": true/false, "risk_score": 0-100 (0-24 not an '
        "incident, 25-44 plausible, 45-69 credible and unfolding, 70-100 "
        'major and active), "case_key": "if this is about a case in Known '
        "open cases, copy its key EXACTLY; otherwise up to 3 distinctive "
        "lowercase words from the tweet joined by _ (project/company, plus "
        "attacker, victim or place if named; never generic words like hack, "
        'exploit, incident, supply, wallet, crypto, and no dates)", '
        '"tokens_affected": "symbols or \'unknown\'", '
        '"estimated_loss_usd": "e.g. \'~$3M\' or \'unknown\'", '
        '"latest_official_response": "what the project/exchange said or '
        'did, or \'unknown\'", "hacker_addresses": "addresses or '
        '\'unknown\'", "asset_movement": "where stolen funds are moving, '
        'or \'unknown\'", "status": "ongoing | contained | resolved | '
        'unknown", "summary": "max 140 chars: \'<Project>: <what\'s '
        'happening>\'"}'
    )


def _parse_classification_json(text: str, provider: str):
    """
    Shared JSON parsing/repair for classify_with_ai()'s response, used by
    every provider attempt. Returns a dict with keys: score, label,
    summary, case_key, fields (a dict of
    CASE_TRACKED_FIELDS values) — or None if the response couldn't be
    parsed into a usable classification.
    """
    try:
        text = text.replace("```json", "").replace("```", "").strip()

        # Models sometimes add stray characters around the JSON (a trailing
        # backtick, "Here is the JSON:" ...). Read just the first {...} object.
        start = text.find("{")
        if start > 0:
            text = text[start:]
        try:
            parsed, _end = json.JSONDecoder().raw_decode(text)
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
            parsed, _end = json.JSONDecoder().raw_decode(repaired)  # raises if still broken

        score = max(0, min(100, int(parsed.get("risk_score", 0))))
        is_real = bool(parsed.get("is_real_incident", False))
        summary = parsed.get("summary", "").strip()
        if len(summary) > 140:
            # Safety net in case the AI overshoots the 140-char instruction —
            # trim on a word boundary rather than mid-word.
            summary = summary[:140].rsplit(" ", 1)[0].rstrip(",.;:") + "…"
        case_key = (parsed.get("case_key", "") or "").strip().lower().replace(" ", "_") or "unknown_incident"
        fields = {f: (parsed.get(f, "") or "").strip() for f in CASE_TRACKED_FIELDS}
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
        return {
            "score": score, "label": label, "summary": summary,
            "case_key": case_key, "fields": fields,
        }

    except Exception as e:
        print(f"AI response from {provider} couldn't be parsed: {e}\n"
              f"  Raw response was: {text!r}", file=sys.stderr)
        return None


_last_ai_error = ""  # newest Grok failure text, shown in the Telegram health alert


def classify_with_ai(tweet: dict):
    """
    Asks Grok whether a tweet reports a real, currently-active crypto
    security incident and assigns a risk score (see
    _parse_classification_json() for the returned dict). Returns None if
    XAI_API_KEY is missing or the call fails — scoring is AI-only, so the
    caller skips the tweet and pages on Telegram (see
    note_ai_failure_and_maybe_alert()).
    """
    attempts = _ai_attempts()
    if not attempts:
        return None

    username = tweet.get("username", "unknown")
    trusted_list = ", ".join(sorted(TRUSTED_ACCOUNTS))
    verified_note = "verified" if tweet.get("verified") else "not verified"
    open_cases = get_open_cases_context()
    user_message = (
        f"Tweet author: @{username} ({verified_note} account)\n"
        f"Tweet text: {tweet['text']}\n\n"
        f"Known open cases (reuse a case_key from here if this tweet is "
        f"about one of these — see case_key instructions):\n{open_cases}"
    )

    system_prompt = _build_classification_prompt(trusted_list)

    for i, (prov, model) in enumerate(attempts):
        pname = AI_PROVIDERS[prov]["name"]
        try:
            text = _call_grok(system_prompt, user_message, max_tokens=400, model=model,
                              fast_fail=(i < len(attempts) - 1), provider=prov)
            result = _parse_classification_json(text, f"{pname} ({model})")
            if result:
                return result
            raise RuntimeError(f"unreadable reply from {pname}: {text[:200]!r}")
        except Exception as e:
            global _last_ai_error
            _last_ai_error = str(e)
            print(f"{pname} ({model}) classification failed: {e}", file=sys.stderr)
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


def format_case_update_alert(tweet: dict, score: int, label: str, case_key: str,
                              changed_fields: list[str], fields: dict) -> str:
    """
    Compact alert for an UPDATE to an already-alerted case. Deliberately
    does NOT re-send the full original tweet or a fresh "what happened"
    recap the way format_alert() does — you already got the full picture
    on this case's first alert. This shows ONLY the fields that actually
    changed (see ALERT_WORTHY_UPDATE_FIELDS), in English and Chinese, plus
    a link to verify, so a case that keeps accumulating forensic detail
    throughout the day reads as a short delta each time, not a repeat of
    the whole incident. Chinese translation is via DeepL/free fallback
    (see translate_to_chinese()) — a separate, cheap service unrelated to
    the AI classification cost, so there's no reason to skip it here.
    """
    url = f"https://x.com/{tweet['username']}/status/{tweet['id']}"
    icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪"}[label]
    display_name = case_key.replace("_", " ").title()

    en_values = [
        (f, (fields.get(f, "") or "").strip())
        for f in changed_fields if (fields.get(f, "") or "").strip()
    ]
    en_lines = [
        f"• <b>{f.replace('_', ' ').title()}:</b> {html.escape(v)}" for f, v in en_values
    ]
    en_details = "\n".join(en_lines) if en_lines else "(see tweet)"

    if en_values:
        zh_lines = [
            f"• <b>{f.replace('_', ' ').title()}:</b> {html.escape(translate_to_chinese(v))}"
            for f, v in en_values
        ]
        zh_details = "\n".join(zh_lines)
    else:
        zh_details = "(见推文)"

    return (
        f"🔄 <b>CASE UPDATE — {html.escape(display_name)}</b>\n"
        f"{icon} Risk: {label} ({score}/100)\n\n"
        f"{en_details}\n\n"
        f"{zh_details}\n\n"
        f"🔗 {url}"
    )


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
        print("AI classification failed — Grok was unreachable/erroring or "
              "isn't configured. Check AI_PROVIDER and its API key.", file=sys.stderr)
        send_system_alert("Self-test: AI classification failed. Check AI_PROVIDER and its API key.")
        return

    score = ai_result["score"]
    label = ai_result["label"]
    summary = ai_result["summary"]
    print(f"Scored via AI: {label} {score}/100 (case: {ai_result['case_key']})")

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


# Scoring is AI-only — no keyword-based fallback. When Grok (and the optional
# fallback model) fail, you're paged on Telegram with xAI's own error message
# (in English and Chinese), cooldown-guarded so a stuck outage doesn't spam
# you once per tweet.
_last_ai_failure_alert_at = None
AI_FAILURE_ALERT_COOLDOWN_SECONDS = 1800  # 30 min


def _readable_ai_error(raw: str) -> str:
    """xAI's own message out of a raw error string like
    'gave up after retries: 429 from xAI: {"code":"...","error":"The model..."}'."""
    m = re.search(r"\{.*\}", raw or "", flags=re.DOTALL)
    if m:
        try:
            data = json.loads(m.group(0))
            msg = data.get("error") or data.get("message")
            if isinstance(msg, dict):
                msg = msg.get("message")
            if msg:
                return str(msg).strip()
        except Exception:
            pass
    return (raw or "unknown error").strip()[:300]


def note_ai_failure_and_maybe_alert():
    global _last_ai_failure_alert_at
    now = datetime.now(timezone.utc)
    cooldown_elapsed = (
        _last_ai_failure_alert_at is None
        or (now - _last_ai_failure_alert_at).total_seconds() > AI_FAILURE_ALERT_COOLDOWN_SECONDS
    )
    if cooldown_elapsed:
        reason = _readable_ai_error(_last_ai_error)
        send_system_alert(
            f"{AI_PROVIDERS.get(AI_PROVIDER, AI_PROVIDERS['grok'])['name']} classification is failing. Tweets are queued and retried "
            f"for about {AI_MAX_ATTEMPTS_PER_TWEET} polls, then dropped, so you "
            "may miss incidents until this recovers.\n\n"
            f"<b>AI says:</b> {html.escape(reason)}\n\n"
            f"<b>AI 提示：</b> {html.escape(translate_to_chinese(reason))}"
        )
        _last_ai_failure_alert_at = now


# ---------------------------------------------------------------------------
# Telegram "dampener" — temporarily hard-mute a word from your Telegram chat:
#   /dampen pyr 6h        mute "pyr" for 6 hours (m / h / d; default 6h)
#   /dampen "ledger implant" 2d   (quote a phrase)
#   /undampen pyr         cancel early
#   /dampened             list active mutes
# A tweet containing a muted word (whole word, case-insensitive; "$PYR" counts)
# is skipped BEFORE the Grok call, so it costs nothing. Only messages from
# TELEGRAM_CHAT_ID are obeyed. Mutes live in Redis with an expiry (lost on
# restart if Redis is off). Commands are read once per poll (~45s).
# ---------------------------------------------------------------------------

MUTE_MAX_SECONDS = 7 * 24 * 3600
MUTE_DEFAULT_SECONDS = 6 * 3600
MUTE_KEY_PREFIX = "crypto_alert_bot:mute:"
TG_OFFSET_KEY = "crypto_alert_bot:tg_offset"
BOT_TIMEZONE = os.environ.get("BOT_TIMEZONE", "Asia/Jakarta")

_mutes_local: dict[str, datetime] = {}  # word -> expiry (used when Redis is off)
_tg_offset = None  # next Telegram update id to read
_tg_started = False  # True once the first getUpdates call has completed
_tg_warned = False


def _fmt_local(dt: datetime) -> str:
    try:
        from zoneinfo import ZoneInfo
        return dt.astimezone(ZoneInfo(BOT_TIMEZONE)).strftime("%d %b %H:%M") + f" {BOT_TIMEZONE}"
    except Exception:
        return dt.strftime("%d %b %H:%M") + " UTC"


def _fmt_remaining(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds >= 86400:
        return f"{seconds // 86400}d {(seconds % 86400) // 3600}h"
    if seconds >= 3600:
        return f"{seconds // 3600}h {(seconds % 3600) // 60}m"
    return f"{max(1, seconds // 60)}m"


def add_mute(word: str, seconds: int) -> datetime:
    expiry = datetime.now(timezone.utc) + timedelta(seconds=seconds)
    _mutes_local[word] = expiry
    r = get_redis()
    if r:
        try:
            r.set(MUTE_KEY_PREFIX + word, expiry.isoformat(), ex=seconds)
        except Exception as e:
            print(f"Could not save mute to Redis: {e}", file=sys.stderr)
    return expiry


def remove_mute(word: str) -> bool:
    existed = word in {w for w, _ in list_mutes()}
    _mutes_local.pop(word, None)
    r = get_redis()
    if r:
        try:
            r.delete(MUTE_KEY_PREFIX + word)
        except Exception:
            pass
    return existed


def list_mutes() -> list[tuple[str, datetime]]:
    """Active (word, expiry) pairs, soonest-expiring first."""
    now = datetime.now(timezone.utc)
    found = {w: e for w, e in _mutes_local.items() if e > now}
    r = get_redis()
    if r:
        try:
            for key in r.scan_iter(MUTE_KEY_PREFIX + "*"):
                raw = r.get(key)
                if raw:
                    exp = datetime.fromisoformat(raw)
                    if exp > now:
                        found[key[len(MUTE_KEY_PREFIX):]] = exp
        except Exception:
            pass
    for w in [w for w, e in _mutes_local.items() if e <= now]:
        _mutes_local.pop(w, None)
    return sorted(found.items(), key=lambda x: x[1])


def muted_word(text: str) -> str | None:
    """The first active muted word found in text (whole word), else None."""
    low = (text or "").lower()
    for word, _ in list_mutes():
        if re.search(r"(?<![a-z0-9])" + re.escape(word) + r"(?![a-z0-9])", low):
            return word
    return None


_DURATION_RE = re.compile(r"^(\d+)\s*([mhd])$", re.IGNORECASE)


def _handle_command(text: str) -> str | None:
    """Runs one /dampen-style command; returns the reply text (HTML) or None
    if it isn't one of ours."""
    m = re.match(r"^/(undampen|dampened|dampen)(?![a-z])(?:@\w+)?\s*(.*)$", text.strip(), re.IGNORECASE | re.DOTALL)
    if not m:
        return None
    cmd, rest = m.group(1).lower(), m.group(2).strip()

    if cmd == "dampened":
        mutes = list_mutes()
        if not mutes:
            return "No active dampeners."
        now = datetime.now(timezone.utc)
        return "<b>Active dampeners</b>\n" + "\n".join(
            f"• {html.escape(w)} — {_fmt_remaining((e - now).total_seconds())} left (until {_fmt_local(e)})"
            for w, e in mutes
        )

    wm = re.match(r'^(?:"([^"]+)"|(\S+))\s*(.*)$', rest)
    if not wm:
        return ("Usage: <code>/dampen pyr 6h</code> · <code>/undampen pyr</code> · "
                "<code>/dampened</code>")
    word = (wm.group(1) or wm.group(2)).lower().lstrip("$").strip()
    dur = wm.group(3).strip()
    if len(word) < 2:
        return "That word is too short to dampen."

    if cmd == "undampen":
        return (f"Removed dampener for <b>{html.escape(word)}</b>." if remove_mute(word)
                else f"No active dampener for <b>{html.escape(word)}</b>.")

    seconds = MUTE_DEFAULT_SECONDS
    if dur:
        dm = _DURATION_RE.match(dur)
        if not dm:
            return "Duration should look like <code>30m</code>, <code>6h</code> or <code>2d</code>."
        seconds = int(dm.group(1)) * {"m": 60, "h": 3600, "d": 86400}[dm.group(2).lower()]
    seconds = max(60, min(seconds, MUTE_MAX_SECONDS))
    expiry = add_mute(word, seconds)
    return (f"Dampened <b>{html.escape(word)}</b> for {_fmt_remaining(seconds)} "
            f"(until {_fmt_local(expiry)}). Tweets containing it are skipped.")


def process_telegram_commands():
    """Reads new messages sent to the bot and runs any dampener commands.
    Never raises — a Telegram hiccup must not stop tweet processing."""
    global _tg_offset, _tg_warned, _tg_started
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        r = get_redis()
        first_run = not _tg_started
        if first_run and r:
            saved = r.get(TG_OFFSET_KEY)
            if saved:
                _tg_offset = int(saved)
        params = {"timeout": 0, "allowed_updates": '["message","channel_post"]'}
        if _tg_offset is not None:
            params["offset"] = _tg_offset
        resp = requests.get(f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getUpdates",
                            params=params, timeout=15)
        if resp.status_code != 200:
            if not _tg_warned:
                print(f"Telegram getUpdates failed ({resp.status_code}): {resp.text[:200]} — "
                      f"dampener commands won't work (409 = a webhook is set on this bot, or "
                      f"another copy of the bot is running with the same Telegram token).",
                      file=sys.stderr)
                _tg_warned = True
            return
        _tg_warned = False
        updates = resp.json().get("result", [])
        _tg_started = True
        now_ts = time.time()
        for u in updates:
            _tg_offset = u["update_id"] + 1
            msg = u.get("message") or u.get("channel_post") or {}
            text = msg.get("text", "") or ""
            chat_id = str(msg.get("chat", {}).get("id"))
            if not text.strip().startswith("/"):
                continue
            if chat_id != str(TELEGRAM_CHAT_ID):
                print(f"Telegram command {text[:40]!r} ignored: it came from chat "
                      f"{chat_id}, but TELEGRAM_CHAT_ID is {TELEGRAM_CHAT_ID}. Send "
                      f"commands in the same chat the alerts arrive in.", file=sys.stderr)
                continue
            # Old backlog (e.g. sent long before a restart) is not replayed,
            # but a command from the last 15 minutes still counts.
            if now_ts - msg.get("date", now_ts) > 900:
                print(f"Telegram command {text[:40]!r} ignored: older than 15 minutes.")
                continue
            reply = _handle_command(text)
            if not reply:
                print(f"Telegram: unknown command {text[:40]!r} (try /dampen, /undampen, /dampened)")
            if reply:
                print(f"Telegram command: {msg.get('text', '')[:60]!r}")
                send_telegram_alert(reply)
        if updates and r:
            r.set(TG_OFFSET_KEY, str(_tg_offset))
    except Exception as e:
        print(f"Telegram command check failed: {e}", file=sys.stderr)


_seen_local: set[str] = set()  # fallback when Redis is off / briefly down
AI_MAX_ATTEMPTS_PER_TWEET = int(os.environ.get("AI_MAX_ATTEMPTS_PER_TWEET", "6"))  # polls, not calls
_ai_fail_counts: dict[str, int] = {}


def tweet_already_processed(tweet_id: str) -> bool:
    if tweet_id in _seen_local:
        return True
    r = get_redis()
    if not r:
        return False
    try:
        return bool(r.exists(f"crypto_alert_bot:seen:{tweet_id}"))
    except Exception:
        return False


def mark_tweet_processed(tweet_id: str):
    if len(_seen_local) > 5000:
        _seen_local.clear()
    _seen_local.add(tweet_id)
    r = get_redis()
    if not r:
        return
    try:
        r.set(f"crypto_alert_bot:seen:{tweet_id}", "1", ex=3 * 24 * 3600)
    except Exception:
        pass


def _process_tweet(tweet: dict) -> bool:
    """Handles one tweet. Returns True only if the AI call failed and the
    tweet should be retried on a later poll."""
    metrics = tweet.get("metrics", {})
    likes = metrics.get("like_count", 0)

    # Resolve any 'chain:0xaddress' references to readable token
    # symbols before this text is used anywhere downstream.
    tweet["text"] = resolve_token_symbols(tweet["text"])

    preview = tweet["text"][:80].replace("\n", " ")

    hit = muted_word(tweet["text"])
    if hit:
        print(f"  [muted: {hit}] @{tweet['username']}: {preview}")
        return False

    # Cheap check FIRST so low-engagement tweets never cost an AI call.
    if likes < MIN_ENGAGEMENT_FILTER:
        print(f"  [not classified] {likes} likes @{tweet['username']}: {preview} "
              f"-> skipped (below MIN_ENGAGEMENT_FILTER={MIN_ENGAGEMENT_FILTER})")
        return

    if tweet_already_processed(tweet["id"]):
        return  # already classified earlier (e.g. batch re-fetched after an error)

    ai_result = classify_with_ai(tweet)
    if not ai_result:
        n = _ai_fail_counts.get(tweet["id"], 0) + 1
        _ai_fail_counts[tweet["id"]] = n
        note_ai_failure_and_maybe_alert()
        if n >= AI_MAX_ATTEMPTS_PER_TWEET:
            print(f"  [GAVE UP after {n} failed AI attempts] {likes} likes "
                  f"@{tweet['username']}: {preview}", file=sys.stderr)
            mark_tweet_processed(tweet["id"])
            return False
        print(f"  [AI failed, will retry next poll ({n}/{AI_MAX_ATTEMPTS_PER_TWEET})] "
              f"{likes} likes @{tweet['username']}: {preview}", file=sys.stderr)
        return True  # retry later

    mark_tweet_processed(tweet["id"])

    score = ai_result["score"]
    label = ai_result["label"]
    summary = ai_result["summary"]
    case_key = ai_result["case_key"]
    fields = ai_result["fields"]

    # Always log the score, even for tweets that won't alert — this is
    # what you want to watch to calibrate MIN_RISK_SCORE_TO_ALERT and
    # MIN_ENGAGEMENT_FILTER against real traffic.
    print(f"  [{label} {score}/100] {likes} likes @{tweet['username']}: {preview}")

    if score < MIN_RISK_SCORE_TO_TRACK:
        print(f"    -> skipped (below MIN_RISK_SCORE_TO_TRACK={MIN_RISK_SCORE_TO_TRACK})")
        return

    # File the tweet under the right case (see resolve_case_key()): reuse an
    # existing case that shares a distinctive keyword, else a new keyword key.
    resolved_key = resolve_case_key(case_key, tweet["text"], tweet["id"])
    note = f" (AI proposed '{case_key}')" if resolved_key != case_key else ""
    print(f"    case: {resolved_key}{note}")
    case_key = resolved_key

    # Persistent case tracking: has this exact incident (by case_key)
    # been recorded before, and if so, did THIS tweet add anything we
    # didn't already know? This runs for anything clearing
    # MIN_RISK_SCORE_TO_TRACK, which is lower than the alert bar — so a
    # weak/early tweet still gets recorded even when it won't page you,
    # giving a later tweet about the same case earlier context to
    # build on. Always updates the case record either way; only the
    # alert itself is gated further below.
    is_new_case, changed_fields = upsert_case(
        case_key, tweet, score, label, summary, fields
    )
    if not is_new_case and not changed_fields:
        print(f"    -> skipped (case '{case_key}' already known, no new "
              f"information in this tweet — recorded to case history anyway)")
        return

    # For an UPDATE to a known case (not its first alert), only re-alert
    # if something in ALERT_WORTHY_UPDATE_FIELDS changed. A rising loss
    # estimate or a reworded status on an incident you already know
    # about isn't worth another Telegram ping — what actually matters
    # for an already-known hack is where the funds are moving and who's
    # holding them, so those are what re-trigger an alert. Anything
    # else that changed is still saved to the case record (for
    # case_report.py) — it just doesn't page you again.
    if not is_new_case:
        alert_worthy_changes = [f for f in changed_fields if f in ALERT_WORTHY_UPDATE_FIELDS]
        if not alert_worthy_changes:
            print(f"    -> tracked but not re-alerted (case '{case_key}' updated "
                  f"in {', '.join(changed_fields)}, none of which are in "
                  f"ALERT_WORTHY_UPDATE_FIELDS={sorted(ALERT_WORTHY_UPDATE_FIELDS)})")
            return
        changed_fields = alert_worthy_changes

    if score < MIN_RISK_SCORE_TO_ALERT:
        print(f"    -> tracked but not alerted (below MIN_RISK_SCORE_TO_ALERT="
              f"{MIN_RISK_SCORE_TO_ALERT}) — case '{case_key}' updated silently")
        if is_new_case:
            _set_case_flag(case_key, "alerted", False)  # not paged yet
        return

    if is_new_case:
        zh_text = translate_to_chinese(tweet["text"])
        message = format_alert(tweet, score, label, zh_text, summary)
    else:
        pretty_fields = ", ".join(f.replace("_", " ") for f in changed_fields)
        print(f"    -> case update: new info in {pretty_fields}")
        message = format_case_update_alert(tweet, score, label, case_key, changed_fields, fields)

    send_telegram_alert(message)
    # The reminder goes out with the FIRST alert for a case — a brand-new
    # case, or one that was tracked silently earlier (flag alerted=False) and
    # has only now crossed the alert threshold. Cases saved before this
    # feature have no flag and are treated as already alerted.
    existing = get_case(case_key) or {}
    first_alert = is_new_case or existing.get("alerted") is False
    if first_alert:
        _set_case_flag(case_key, "alerted", True)
        if NEW_CASE_REMINDER:
            send_telegram_alert(NEW_CASE_REMINDER)  # separate chat bubble
    print(f"    -> ALERT SENT")
    time.sleep(1)  # be gentle with Telegram's rate limits


def run_once(since_id):
    process_telegram_commands()
    tweets, newest_id, error = search_recent_tweets(since_id)
    if tweets:
        print(f"[{datetime.now(timezone.utc).isoformat()}] {len(tweets)} new candidate tweet(s).")

    retry_needed = False
    consecutive_ai_failures = 0
    for tweet in tweets:
        if consecutive_ai_failures >= 2:
            # xAI is clearly struggling — stop hammering it this poll; the
            # untouched tweets are picked up again next poll.
            retry_needed = True
            break
        try:
            failed = _process_tweet(tweet)
        except Exception as e:
            # One bad tweet must not abort the batch.
            print(f"Error processing tweet {tweet.get('id')}: {e}", file=sys.stderr)
            failed = False
        if failed:
            retry_needed = True
            consecutive_ai_failures += 1
        else:
            consecutive_ai_failures = 0

    if retry_needed:
        # Don't advance past tweets we couldn't classify: next poll re-fetches
        # them. Tweets already classified are skipped for free (seen-ID check),
        # and a tweet is abandoned after AI_MAX_ATTEMPTS_PER_TWEET failures.
        return since_id, error

    return newest_id, error


def main():
    print(f"[{datetime.now(timezone.utc).isoformat()}] Crypto incident monitor starting up.")
    print(f"Polling every {POLL_INTERVAL_SECONDS}s. Alert threshold: {MIN_RISK_SCORE_TO_ALERT}. "
          f"Track threshold: {MIN_RISK_SCORE_TO_TRACK}. "
          f"Min engagement filter: {MIN_ENGAGEMENT_FILTER} likes.")
    for i, q in enumerate(build_queries(), start=1):
        print(f"Search query {i}: {q}")

    if not X_BEARER_TOKEN or not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        print("ERROR: Missing one or more required env vars: X_BEARER_TOKEN, "
              "TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID.", file=sys.stderr)
        sys.exit(1)

    if AI_PROVIDER not in AI_PROVIDERS:
        print(f"ERROR: AI_PROVIDER={AI_PROVIDER!r} is not valid. Use 'grok' or "
              "'deepseek'.", file=sys.stderr)
        sys.exit(1)
    if AI_FALLBACK_PROVIDER and AI_FALLBACK_PROVIDER not in AI_PROVIDERS:
        print(f"ERROR: AI_FALLBACK_PROVIDER={AI_FALLBACK_PROVIDER!r} is not valid. "
              "Use 'grok', 'deepseek' or leave it empty.", file=sys.stderr)
        sys.exit(1)
    attempts = _ai_attempts()
    if not attempts or attempts[0][0] != AI_PROVIDER:
        need = "XAI_API_KEY" if AI_PROVIDER == "grok" else "DEEPSEEK_API_KEY"
        print(f"ERROR: AI_PROVIDER is '{AI_PROVIDER}' but {need} is not set. "
              "Scoring is AI-only — the bot cannot classify tweets without it.",
              file=sys.stderr)
        sys.exit(1)
    print("AI order: " + " -> ".join(f"{AI_PROVIDERS[p]['name']} ({m})" for p, m in attempts)
          + ". No live X search.")

    if REDIS_URL:
        if get_redis():
            known_cases = len(list_case_keys())
            print(f"Case tracking: ON (Redis connected) — {known_cases} known "
                  f"case(s) in the database. Repeat mentions of a known "
                  f"incident are suppressed unless they add new information "
                  f"(new loss figure, official response, attacker address, "
                  f"status change, etc.); the case record is updated either way.")
        else:
            print("Case tracking: REDIS_URL is set but Redis is unreachable right "
                  "now — case tracking is degraded to 'always treat as new' "
                  "until it reconnects.", file=sys.stderr)
    else:
        print("Case tracking: OFF (no REDIS_URL) — every alert-worthy tweet is "
              "treated as new; no persistent dedup-by-incident or on-demand "
              "case reports.")

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
