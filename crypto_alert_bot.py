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

# AI scoring uses Claude as the primary provider, with automatic failover to
# Grok if Claude is unreachable/erroring — you only get paged on Telegram if
# BOTH fail. Set whichever key(s) you have; at least one is required.
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")  # primary provider (Claude)
XAI_API_KEY = os.environ.get("XAI_API_KEY")  # fallback provider (Grok)
CLAUDE_MODEL = os.environ.get("CLAUDE_MODEL", "claude-haiku-4-5-20251001")
GROK_MODEL = os.environ.get("GROK_MODEL", "grok-4.3")

# Recency verification: before sending an alert, ask Grok's LIVE X search
# (real-time access to X/Twitter — something Claude doesn't have) whether
# this incident is genuinely new/ongoing, or was already circulating
# earlier (a stale/old incident being reported again). Requires
# XAI_API_KEY and a Grok model that supports the x_search tool (see
# GROK_LIVE_SEARCH_MODEL). Set to "false" to disable and skip this check.
LIVE_SEARCH_RECENCY_CHECK = os.environ.get("LIVE_SEARCH_RECENCY_CHECK", "true").lower() == "true"
GROK_LIVE_SEARCH_MODEL = os.environ.get("GROK_LIVE_SEARCH_MODEL", GROK_MODEL)

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


# ---------------------------------------------------------------------------
# Persistent case store (Redis) — one structured record per incident,
# keyed by the AI's own "case_key" (e.g. "egld_multiversx_exploit"). Unlike
# recent_alerts above (short-term, in-memory, resets on restart), this is
# meant to last: it survives restarts/redeploys and has no fixed retention
# window, so "have we already told the risk officer about this incident"
# can be answered days or weeks later, not just within a few hours.
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


# How many of the most-recently-updated cases to show the AI as candidates
# for case_key reuse (see get_open_cases_context() below). Kept small so it
# doesn't blow up the prompt, but wide enough to cover "this got tweeted
# about by 10 different accounts within an hour" bursts.
OPEN_CASES_CONTEXT_LIMIT = 20

# Of those, only cases updated within this many hours get the FULL per-
# field fact dump (needed for the "copy forward, don't restate" check —
# see get_open_cases_context()). Older cases are very unlikely to get a
# genuine repeat tweet, so they only need their case_key + status shown
# (still enough for case_key-reuse matching) rather than all 6 tracked
# fields — this is what keeps prompt size (and therefore per-call cost)
# from scaling with total cases ever tracked instead of just active ones.
OPEN_CASES_FULL_DETAIL_HOURS = 48


def get_open_cases_context() -> str:
    """
    Returns a compact, per-case text block describing the most-recently-
    updated known cases — fed to the AI classifier for TWO purposes:

    1. So it can REUSE an existing case_key for a tweet about an incident
       it already knows, instead of inventing a new one blind. Without
       this, every call is stateless and the AI has no way to know what
       an incident was already named, which is what caused the same
       real-world incident to fragment into many different case_keys
       (e.g. "cosmos_hub_noble_exploit", "cosmos_hub_neutron_attack",
       "cosmos_hub_governance_exploit", ...). Every case in the list gets
       at least this — a one-line case_key/display_name/status entry.

    2. So it can tell whether THIS tweet actually adds a new fact versus
       just rewording something already on file — but only for cases
       updated in the last OPEN_CASES_FULL_DETAIL_HOURS, which get their
       CURRENT tracked field values shown in full so the AI can compare
       the tweet's content against them directly and copy a value
       forward unchanged when nothing substantive has changed (see the
       "COPY FORWARD, DON'T RESTATE" prompt instructions). A case that's
       gone quiet for days is very unlikely to get a genuine same-day
       repeat, so it doesn't need this — keeping the prompt from growing
       with your total case history instead of just what's currently hot.

    Returns "(none yet)" if case tracking is off or no cases exist yet.
    """
    r = get_redis()
    if not r:
        return "(none yet)"
    case_keys = list_case_keys()
    if not case_keys:
        return "(none yet)"

    cases = [c for c in (get_case(k) for k in case_keys) if c]
    cases.sort(key=lambda c: c.get("last_seen", ""), reverse=True)
    cases = cases[:OPEN_CASES_CONTEXT_LIMIT]

    now = datetime.now(timezone.utc)
    blocks = []
    for c in cases:
        header = f"- case_key=\"{c['case_key']}\" | {c.get('display_name', c['case_key'])}"
        try:
            age_hours = (now - datetime.fromisoformat(c.get("last_seen", ""))).total_seconds() / 3600
        except ValueError:
            age_hours = None

        if age_hours is not None and age_hours <= OPEN_CASES_FULL_DETAIL_HOURS:
            field_lines = "\n".join(
                f"    {f}: {c.get(f) or 'unknown'}" for f in CASE_TRACKED_FIELDS
            )
            blocks.append(f"{header}\n{field_lines}")
        else:
            blocks.append(f"{header} | status: {c.get('status') or 'unknown'} (older case — "
                           f"full details omitted, not expected to get same-day updates)")
    return "\n".join(blocks)


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

# estimated_loss_usd/latest_official_response/asset_movement are free-text
# narrative the AI writes fresh every call — the SAME fact routinely comes
# back reworded ("~$20M" vs "$20 million estimated", "paused, investigating"
# vs "investigation ongoing"), which exact-string comparison mistakes for
# new information, firing a repeat "CASE UPDATE" alert for nothing. These
# are compared by text similarity instead, and only count as changed once
# the wording diverges enough to plausibly be a different fact, not just a
# different phrasing of the same one.
_CASE_FIELD_FUZZY_TYPE = {
    "estimated_loss_usd", "latest_official_response", "asset_movement",
}
# Below this word-overlap ratio, two versions of a narrative field are
# treated as different facts rather than a reworded repeat of the same one.
_CASE_FIELD_WORD_OVERLAP_THRESHOLD = 0.3
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
    """True if new_val represents genuinely new information for `field`
    versus old_val (both already lowercased/stripped), using a comparison
    suited to that field's shape rather than blind exact-string equality
    (the AI reworks free-text fields every call, so exact matching treats
    a rephrasing of the same fact as new information)."""
    if field in _CASE_FIELD_LIST_TYPE:
        old_set = {v.strip() for v in old_val.split(",") if v.strip()}
        new_set = {v.strip() for v in new_val.split(",") if v.strip()}
        return not new_set.issubset(old_set)

    if field == "estimated_loss_usd":
        old_amount = _extract_usd_amount(old_val)
        new_amount = _extract_usd_amount(new_val)
        if old_amount and new_amount:
            return abs(new_amount - old_amount) / old_amount > _CASE_FIELD_USD_TOLERANCE
        # no parseable number on one side — fall through to word overlap

    if field in _CASE_FIELD_FUZZY_TYPE:
        old_words, new_words = _word_set(old_val), _word_set(new_val)
        if not old_words or not new_words:
            return new_val != old_val
        overlap = len(old_words & new_words) / len(old_words | new_words)
        return overlap < _CASE_FIELD_WORD_OVERLAP_THRESHOLD

    return new_val != old_val  # status and anything else: exact match is fine


def diff_case_fields(old_case: dict, new_fields: dict) -> list[str]:
    """
    Compares new_fields (freshly extracted by the AI for this tweet)
    against what's already stored for this case, and returns the list of
    tracked field names that changed meaningfully. An empty list means
    "nothing new" — the tweet is a repeat of what we already know.
    """
    changed = []
    for field in CASE_TRACKED_FIELDS:
        new_val = _normalize_case_field(new_fields.get(field, ""))
        old_val = _normalize_case_field(old_case.get(field, ""))
        if new_val in _CASE_FIELD_EMPTY_VALUES:
            continue  # the AI didn't learn anything new for this field this time
        if old_val in _CASE_FIELD_EMPTY_VALUES:
            changed.append(field)  # first time we've learned this field at all
            continue
        if _case_field_changed(field, old_val, new_val):
            changed.append(field)
    return changed


# Words too generic to prove two case_keys are about the SAME incident —
# stripped out before comparing, so "cosmos_hub_governance_exploit" and
# "cosmos_hub_validators_halt" are still recognized as sharing "cosmos"/
# "hub" even though neither incident-type word matches.
_CASE_KEY_STOPWORDS = {
    "exploit", "exploited", "hack", "hacked", "hacker", "incident",
    "attack", "attacked", "breach", "breached", "halt", "halted",
    "halting", "suspended", "paused", "frozen", "vulnerability",
    "governance", "validators", "validator", "network", "chain",
    "protocol", "unknown", "token", "tokens", "security", "issue",
}

# How far back (in hours) to look for a case to merge a near-duplicate
# case_key into. Long enough to catch an incident that keeps getting
# re-reported over a few days, short enough not to merge into stale,
# long-resolved cases that happen to share a project name.
CASE_MERGE_LOOKBACK_HOURS = 24 * 7


def _case_key_tokens(case_key: str) -> set[str]:
    """Distinctive (non-generic) tokens in a case_key, used to detect
    near-duplicate case_keys for the same real-world incident."""
    return {
        t for t in case_key.split("_")
        if t not in _CASE_KEY_STOPWORDS and not t.isdigit() and len(t) > 2
    }


# Words too generic/incident-y to serve as a case's own identity when
# minting a fallback case_key straight from tweet text (see
# _fallback_case_key_from_text()). Deliberately overlaps _CASE_KEY_STOPWORDS
# but includes plain-English words too, since this runs on raw tweet prose
# rather than an already-terse case_key.
_FALLBACK_NAME_IGNORE = _CASE_KEY_STOPWORDS | {
    "breaking", "update", "alert", "report", "reports", "reported",
    "confirmed", "official", "urgent", "just", "today", "now", "crypto",
    "the", "backend", "spoofing", "according", "sources", "amid",
}


def _fallback_case_key_from_text(tweet_text: str, existing_keys: set[str]) -> str:
    """
    Mints a brand-new case_key straight from a tweet's own text, used when
    the AI's proposed case_key turns out to belong to an unrelated case
    (see resolve_case_key()) and no better existing match was found. Picks
    the first capitalized word/phrase in the tweet that isn't generic
    incident-report boilerplate — usually the project/exchange name — e.g.
    "Bitget Breach: $387.5M Stolen..." -> "bitget_incident_2026_09".
    Falls back to "unknown_incident_<month>" if nothing usable is found,
    and disambiguates with a numeric suffix if that key is already taken.
    """
    base = None
    for m in re.findall(r"\b[A-Z][a-zA-Z0-9]{2,}(?:\s+[A-Z][a-zA-Z0-9]{2,}){0,2}\b", tweet_text):
        slug = "_".join(w.lower() for w in m.split())
        if slug in _FALLBACK_NAME_IGNORE:
            continue
        base = slug
        break
    base = base or "unknown"

    month_suffix = datetime.now(timezone.utc).strftime("%Y_%m")
    key = f"{base}_incident_{month_suffix}"
    n = 2
    while key in existing_keys:
        key = f"{base}_incident_{month_suffix}_{n}"
        n += 1
    return key


def resolve_case_key(candidate_key: str, tweet_text: str = "") -> str:
    """
    Safety net for case_key mistakes in both directions.

    1. FRAGMENTATION: the AI is shown a list of known open cases and told
       to copy a matching case_key exactly, but free-text generation means
       it sometimes drifts to a near-duplicate variant anyway — e.g. the
       same Cosmos Hub/Neutron incident got tagged 'cosmos_hub_noble_exploit',
       'cosmos_hub_neutron_attack', and 'cosmos_hub_governance_exploit'
       across different tweets. Distinctive-token overlap with a recently-
       active case collapses these into one canonical (earliest) case.

    2. WRONG MERGE (the more dangerous direction): the AI sometimes reuses
       an EXISTING case_key for a genuinely different incident — e.g. a
       tweet about a Bitget breach got filed under an existing
       'bybit_safe_delegatecall_exploit_2026_09' case just because both
       had a similar loss figure, silently corrupting the real Bybit case
       with unrelated Bitget data. To catch this, any reuse of an existing
       case_key (whether it's an exact match or a token-overlap merge) is
       only accepted if the tweet text actually mentions something
       distinctive about that case. If the AI's exact case_key fails this
       check and nothing else matches either, a fresh case_key is minted
       straight from the tweet's own text (see _fallback_case_key_from_text)
       instead of corrupting the wrong case.

    Only affects NEW classifications going forward — existing fragmented
    or wrongly-merged case records are left as-is (not fixed retroactively).
    """
    r = get_redis()
    if not r:
        return candidate_key

    text_lower = tweet_text.lower()

    def _mentions(key: str) -> bool:
        tokens = _case_key_tokens(key)
        return not tokens or any(t in text_lower for t in tokens)

    existing_keys = set(list_case_keys())
    existing = get_case(candidate_key)
    if existing:
        if not tweet_text or _mentions(candidate_key):
            return candidate_key  # exact match, and the tweet backs it up
        print(f"    -> case_key sanity check failed: AI proposed reusing "
              f"'{candidate_key}' but this tweet doesn't mention any of its "
              f"distinctive terms — likely a different incident (e.g. a "
              f"similarly-named project or a coincidentally matching loss "
              f"figure). Looking for the real match instead.", file=sys.stderr)

    candidate_tokens = _case_key_tokens(candidate_key)
    now = datetime.now(timezone.utc)
    best_match = None  # (first_seen_iso, case_key)
    for key in existing_keys:
        if key == candidate_key:
            continue
        case = get_case(key)
        if not case:
            continue
        try:
            age_hours = (now - datetime.fromisoformat(case.get("last_seen", ""))).total_seconds() / 3600
        except ValueError:
            continue
        if age_hours > CASE_MERGE_LOOKBACK_HOURS:
            continue
        if not (candidate_tokens & _case_key_tokens(key)):
            continue
        # Token overlap with the candidate alone isn't enough evidence on
        # its own (the candidate could itself be the wrong case) — the
        # tweet has to actually back up THIS case too.
        if tweet_text and not _mentions(key):
            continue
        first_seen = case.get("first_seen") or case.get("last_seen", "")
        if best_match is None or first_seen < best_match[0]:
            best_match = (first_seen, key)

    if best_match:
        return best_match[1]

    if existing:
        # candidate_key belongs to a different, unrelated case (sanity
        # check above failed) and nothing else matched either — don't
        # corrupt that case; give this tweet its own fresh identity.
        return _fallback_case_key_from_text(tweet_text, existing_keys)

    return candidate_key


def upsert_case(case_key: str, tweet: dict, score: int, label: str, summary: str,
                 fields: dict, first_seen_estimate: str) -> tuple[bool, list[str]]:
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
        for f in changed_fields:
            case[f] = fields.get(f, "") or ""

    case["updates"].append({
        "time": now_iso,
        "username": tweet.get("username", "unknown"),
        "tweet_id": tweet.get("id", ""),
        "score": score,
        "label": label,
        "summary": summary,
        "first_seen_estimate": first_seen_estimate,
    })
    case["updates"] = case["updates"][-CASE_MAX_UPDATES_STORED:]

    save_case(case_key, case)
    return is_new, changed_fields


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



def _call_grok_responses_with_search(system_prompt: str, user_message: str, max_tokens: int) -> str:
    """
    Calls xAI's /v1/responses endpoint with the x_search tool enabled —
    Grok's LIVE X search, real-time access to X that Claude does not have.
    Raises on any failure (caller handles fallback). Note: this endpoint
    bills x_search usage per post/profile fetched, separate from and in
    addition to normal chat tokens.
    """
    resp = requests.post(
        "https://api.x.ai/v1/responses",
        headers={
            "Authorization": f"Bearer {XAI_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "model": GROK_LIVE_SEARCH_MODEL,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
            "tools": [{"type": "x_search"}],
            "max_output_tokens": max_tokens,
        },
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()

    # The /v1/responses "output" array can contain more than just the
    # final message — when tools are used (like x_search here), earlier
    # items are often tool-call/reasoning entries with no "content" field,
    # so output[0] isn't reliably the message. Scan for the first item
    # that actually has text content instead of assuming a fixed position.
    text = None
    for item in data.get("output", []):
        for block in item.get("content", []) or []:
            if isinstance(block, dict) and block.get("text"):
                text = block["text"]
                break
        if text:
            break
    if not text:
        # Fallback for APIs that also expose a flat convenience field.
        text = data.get("output_text")
    if not text:
        raise ValueError(f"No text content found in response: {data!r}")
    return text.strip()


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
    "exchange", "dex", "bsc", "bnb",
    "eth", "btc",  # common cashtag tickers, not just full chain names
    "blockchain", "mainnet", "chain",
    # "validators"/"governance" are safe to add HERE (but not to CONTEXT_B —
    # see the note below) because query A's incident terms are already hard,
    # unambiguous attack vocabulary ("exploit", "hacked", "rugpull", ...),
    # so an unrelated tweet pairing one of those with "validators" or
    # "governance" is very unlikely. Added after missing a real incident
    # (Cosmos Hub/Neutron, Sep 2026) whose tweet said "governance exploit"
    # and "validators" but never used a generic crypto word like "eth"/"btc".
    "validators", "governance",
    # "polygon"/"arbitrum"/"avalanche" were dropped to make room for the
    # above — X's query parameter has a hard 512-char cap, and this query
    # was going over it (542 chars). The generic "chain"/"blockchain"/
    # "defi" terms already added above still catch tweets about those
    # chains as long as the tweet also uses one of those broader words.
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
    "eth", "btc", "blockchain", "mainnet", "chain",
    # NOTE: standalone "network"/"validators" were removed from here — they
    # made this query match non-crypto outage tweets (e.g. an ISP's own
    # network disruption notice) whenever they also contained "under
    # investigation" or similar. INCIDENT_TERMS_B already has "network
    # paused" and "validators paused" as their own specific phrase terms,
    # so that coverage isn't lost — this just drops the overly generic
    # standalone versions.
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


def _build_classification_prompt(trusted_list: str, has_live_search: bool) -> str:
    if has_live_search:
        recency_instructions = (
            "RECENCY VIA LIVE SEARCH — you have LIVE X SEARCH for this "
            "call. Find the EARLIEST credible mention of this same "
            "incident/project being exploited and compare to now. Fold "
            "this DIRECTLY into risk_score: started within roughly the "
            "last few hours (or no earlier mention found — this tweet may "
            "be the earliest signal) scores toward the HIGH end of its "
            "band. Already reported significantly earlier (yesterday+) "
            "with no sign it's still unfolding scores LOW (0-24) "
            "regardless of severity — stale, the response window has "
            "likely passed. first_seen_estimate: e.g. 'within the last "
            "hour', '~18 hours ago', 'yesterday', '2+ days ago', or 'no "
            "earlier mention found'."
        )
    else:
        recency_instructions = (
            "RECENCY — no live search this call; reason only from the "
            "tweet's own wording/timing cues, don't claim to have checked "
            "X. first_seen_estimate: 'not verified (no live search)'."
        )

    return (
        "You are risk-management staff at a crypto exchange, watching "
        "X/Twitter for a NEW, CURRENTLY-HAPPENING security incident (active "
        "draining, abnormal minting, a bridge/contract exploited right now, "
        "or even a vague 'X is being exploited' mention) so the exchange "
        "can pause deposits/withdrawals for the affected coin. Speed "
        "matters most: teams are usually SLOW to confirm, so the earliest "
        "signal is a vague, unconfirmed tweet, not an official statement — "
        "act on that rather than wait for a post-mortem, since by then the "
        "window to protect the exchange has usually closed.\n\n"
        "CRYPTO GATE (apply FIRST, overrides everything below, including "
        "the official-disclosure special case): confirm this is actually "
        "about crypto/blockchain/DeFi/Web3 (token, protocol, smart "
        "contract, exchange, wallet, chain, bridge). This search is "
        "keyword-based, not crypto-restricted, so it also surfaces ISPs, "
        "telecoms, banks etc. using similar words ('outage', 'breach', "
        "'under investigation', 'paused'). If NOT plausibly crypto-"
        "related, set is_real_incident FALSE and risk_score below 10, no "
        "matter how closely the wording matches a pattern below.\n\n"
        "SOURCE CREDIBILITY: not restricted to vetted accounts — judge "
        "credibility, but don't require proof (address, tx hash, exact $) "
        "before flagging a live-sounding incident; a brief, detail-light "
        "report from an unverified account is still actionable, not "
        f"low-scored just for lacking specifics. Trusted: {trusted_list} "
        "(auto-credible; their absence never downgrades an otherwise "
        "live-sounding incident). You'll see the author's username and "
        "X-verified status — verified (esp. an official project account) "
        "is a meaningful signal too. Reserve low scores for tweets with NO "
        "incident signal (speculation, jokes, unrelated), not for "
        "sparse-but-real reports.\n\n"
        "Respond with ONLY a JSON object, no other text, no markdown "
        "fences. CRITICAL: valid JSON only — line breaks inside a string "
        "value must be \\n, never a literal line break.\n"
        '{"is_real_incident": true or false, "risk_score": <integer 0-100>, '
        '"first_seen_estimate": "<see RECENCY below>", '
        '"case_key": "<short STABLE lowercase_underscore id for this '
        "SPECIFIC incident, e.g. 'liquid_network_exploit'. CHECK 'Known "
        "open cases' in the user message FIRST — if this tweet is "
        "plausibly the SAME incident as one listed (same project/"
        "protocol/chain, even a different affected app/wording/angle), "
        "COPY that case_key EXACTLY — reusing correctly matters more than "
        "an elegant new key, so when in doubt, reuse. Only mint a new one "
        "if nothing listed genuinely matches; use 'unknown_' + a few "
        "words if no project name is identifiable. Fill this even if "
        'is_real_incident is false (used for dedup)>", '
        '"tokens_affected": "<comma-separated symbols/names, or '
        '\'unknown\'>", '
        '"estimated_loss_usd": "<best estimate e.g. \'~$3M\', \'$109K\', or '
        '\'unknown\'>", '
        '"latest_official_response": "<what the project/exchange has said/'
        "done (paused, investigating, reimbursing, silent), or "
        '\'unknown\'>", '
        '"hacker_addresses": "<attacker/contract/destination addresses, '
        'comma-separated, or \'unknown\'>", '
        '"asset_movement": "<where stolen funds are moving, e.g. \'bridged '
        'to Ethereum, partially swapped to ETH\', or \'unknown\'>", '
        '"status": "<ongoing (unfolding/unresolved), contained (halted/'
        "paused not resolved), resolved (recovered/caught/closed), or "
        'unknown>", '
        '"summary": "<HARD LIMIT 140 chars — a phone alert, not a report. '
        "ONE sentence: '<Project name, or 'Unknown'>: <what's happening>' "
        "e.g. 'Liquid Network: bridge actively being drained, ~$3M out so "
        "far.' Plain, non-technical, instantly actionable; drop the loss "
        'figure rather than exceed 140 chars>", '
        '"reasoning": "<one short sentence: why this score, incl. source-'
        'credibility AND recency judgment>"}\n\n'
        f"{recency_instructions}\n\n"
        "CASE TRACKING: case_key + the 6 tracked fields (tokens_affected, "
        "estimated_loss_usd, latest_official_response, hacker_addresses, "
        "asset_movement, status) feed a persistent database keyed by "
        "case_key — every tweet with the SAME case_key updates the SAME "
        "record. Fill in every field you can from THIS tweet; don't leave "
        "one 'unknown' if the tweet states it. case_key CONSISTENCY "
        "matters more than anything else here — always check 'Known open "
        "cases' first and copy an existing key exactly whenever this "
        "tweet is plausibly the same incident, even from a different "
        "angle.\n\n"
        "COPY FORWARD, DON'T RESTATE (most important rule here — getting "
        "it wrong spams the same incident repeatedly in one day): 'Known "
        "open cases' shows each case's CURRENT value per field. Compare "
        "this tweet against those fact-by-fact, not just for incident "
        "keywords. If this tweet's version of a fact is the SAME as "
        "what's listed — same address even reformatted, same claim/"
        "statement reworded, just a refined loss figure — copy the "
        "EXISTING value forward EXACTLY. Only write a NEW value when the "
        "fact is genuinely absent or different in substance: a DIFFERENT "
        "address, funds moving somewhere new, a materially different loss "
        "figure, or a real status transition (ongoing -> contained -> "
        "resolved). A tweet repeating known facts should return every "
        "field as an exact copy of the case's current value, so the "
        "system knows nothing changed and won't re-alert. When unsure, "
        "copy forward — under-alerting on a borderline repeat costs "
        "nothing (still logged to case history); over-alerting pages the "
        "user for no reason.\n\n"
        "Set is_real_incident TRUE for anything suggesting an incident is "
        "NEW or CURRENTLY UNFOLDING — active draining, an exploit in "
        "progress, abnormal minting, funds moving, or even a brief "
        "unconfirmed 'being exploited right now' mention. Set it FALSE "
        "for: general/educational commentary on attack techniques; "
        "retrospectives of old hacks; and POST-MORTEMS published AFTER "
        "the fact about an incident already stabilized — those come too "
        "late for a first response, UNLESS they reveal it's actually "
        "STILL ongoing (attacker still has access, funds still moving, "
        "not yet patched), then TRUE.\n\n"
        "SPECIAL CASE — known threat-actor fund movement: a tweet on a "
        "known actor (e.g. Lazarus) moving/laundering PREVIOUSLY stolen "
        "funds (not a fresh exploit) is still TRUE — actionable, since "
        "incoming funds from a known attacker can be flagged before they "
        "land. Score 30-50, or 60+ if funds are explicitly moving toward "
        "a specific exchange/CEX deposit address. Note the actor and "
        "destination in the summary if stated.\n\n"
        "SPECIAL CASE — security-awareness/PSA posts: a tweet using a "
        "real (maybe days-old) incident mainly as a springboard for "
        "generic security advice, not current developments — hallmarks: "
        "imperative instructions ('Stop.', 'Verify independently'), a "
        "list of things to never share (seed phrase, private key), or "
        "closing 'lesson' framing. If a meaningful portion is generic "
        "advice rather than what's new about THIS incident: FALSE, score "
        "LOW (10-20), regardless of recap detail or prior familiarity.\n\n"
        "SPECIAL CASE — official first-party disclosure (CRYPTO ONLY — "
        "GATE above still applies; not an ISP/telecom outage phrased "
        "identically): an official crypto project/platform account "
        "announcing a halt/pause/security investigation — either (a) its "
        "OWN network/protocol, or (b) its service built on another chain "
        "is disrupted because THAT chain is paused, even if not the "
        "account's own. Both are inherently credible without outside "
        "confirmation — an official channel doesn't tell users their "
        "funds are affected unless something real is happening. Don't "
        "downgrade for lacking a stated loss figure. Set TRUE, score "
        "65-80 by default, 75+ when VERIFIED and/or user funds/"
        "withdrawals are explicitly affected — that combination should "
        "essentially always clear 70.\n\n"
        "SCORING GUIDE — weight CURRENT/ACTIVE status above all else, "
        "RECENCY (above) as the strongest modifier within a band; source "
        "credibility adjusts within that, doesn't override either. 0-24: "
        "no real incident signal, pure noise, a stabilized post-mortem "
        "with nothing new, or live-search-confirmed stale news. 25-44: "
        "plausible but light — a brief/early unverified report, or "
        "routine threat-actor movement with no exchange destination. "
        "45-69: credible and actively unfolding now even if thin — where "
        "most fresh chatter lands; push toward 69 the more recent live "
        "search confirms it. 70-100: confirmed MAJOR incident, currently "
        "active — fresh (last few hours, or no earlier mention found) "
        "from a credible source, or an official first-party disruption "
        "disclosure — large funds at risk, attacker still moving funds, "
        "or critical infrastructure compromised.\n\n"
        "DUPLICATE CHECK — incidents already alerted on recently (last "
        f"{DEDUPE_WINDOW_HOURS:.0f}h):\n{recent_alerts_context()}\n\n"
        "If this tweet reports the SAME underlying incident as one listed "
        "above — even a different account/wording — set is_real_incident "
        "FALSE, score low, note it's a duplicate. EXCEPTION (same bar as "
        "COPY FORWARD above): a genuinely NEW fact — a named wallet/"
        "destination funds are moving to, or an official response/status "
        "change — still gets reported even if the rest repeats; score "
        "45-69 (70+ if funds are moving to a specific exchange, or the "
        "official news is major like funds recovered/attacker caught). A "
        "modestly revised loss estimate or a repeat with no new address/"
        "official word does NOT meet this bar.\n\n"
        "FIRST-MENTION PRIORITY — being the earliest signal of a brand-new "
        "incident is this system's single most valuable output. If this "
        "tweet matches NO case in 'Known open cases' AND recency judgment "
        "says it's fresh ('within the last hour' or 'no earlier mention "
        "found'), score at the TOP of whatever band it otherwise falls "
        "in, even thin or unverified — vague-but-first beats detailed-"
        "but-late."
    )


def _parse_classification_json(text: str, provider: str):
    """
    Shared JSON parsing/repair for classify_with_ai()'s response, used by
    every provider attempt. Returns a dict with keys: score, label,
    summary, reasoning, first_seen, case_key, fields (a dict of
    CASE_TRACKED_FIELDS values) — or None if the response couldn't be
    parsed into a usable classification.
    """
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
        first_seen = parsed.get("first_seen_estimate", "unknown").strip()
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
            "reasoning": reasoning, "first_seen": first_seen,
            "case_key": case_key, "fields": fields,
        }

    except Exception as e:
        print(f"AI response from {provider} couldn't be parsed: {e}\n"
              f"  Raw response was: {text!r}", file=sys.stderr)
        return None


def classify_with_ai(tweet: dict):
    """
    Asks the AI to judge whether a tweet describes a real, currently-active
    crypto security incident, assign a risk score, and — when using Grok
    with live X search — verify how recently the incident actually started,
    folding that directly into the score (fresher = higher, stale = lower).
    This replaces the old two-step design (a separate scoring call, then a
    separate pre-alert live-search recency check): now the SAME AI call
    does both, as requested.

    Provider priority (first that succeeds wins):
      1. Grok WITH live X search — best: classification + real recency
         verification in one call. Used when XAI_API_KEY is set and
         LIVE_SEARCH_RECENCY_CHECK is enabled (the default).
      2. Claude — classification only, no live search (can't verify
         recency, so it's told to not claim to).
      3. Grok WITHOUT live search — last resort if the live-search call
         itself failed (e.g. bad response shape) but the key is still
         presumably valid for plain chat completions.

    Returns a dict (see _parse_classification_json() for the exact shape:
    score, label, summary, reasoning, first_seen, case_key, fields), or
    None if AI scoring isn't configured or every provider's call fails.
    There is no keyword-based fallback — scoring is AI-only, so callers
    should skip the tweet and page on Telegram when this returns None (see
    note_ai_failure_and_maybe_alert()).
    """
    if not ANTHROPIC_API_KEY and not XAI_API_KEY:
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

    # 1. Grok + live X search (best — merged classification + recency).
    if XAI_API_KEY and LIVE_SEARCH_RECENCY_CHECK:
        system_prompt = _build_classification_prompt(trusted_list, has_live_search=True)
        try:
            text = _call_grok_responses_with_search(system_prompt, user_message, max_tokens=800)
            result = _parse_classification_json(text, "grok (live search)")
            if result:
                return result
        except Exception as e:
            print(f"Grok live-search classification failed, trying next "
                  f"provider: {e}", file=sys.stderr)

    # 2. Claude — classification only, no live search.
    if ANTHROPIC_API_KEY:
        system_prompt = _build_classification_prompt(trusted_list, has_live_search=False)
        try:
            text = _call_claude(system_prompt, user_message, max_tokens=700)
            result = _parse_classification_json(text, "claude")
            if result:
                return result
        except Exception as e:
            print(f"Claude classification failed, trying next provider: {e}",
                  file=sys.stderr)

    # 3. Grok without live search — last resort.
    if XAI_API_KEY:
        system_prompt = _build_classification_prompt(trusted_list, has_live_search=False)
        try:
            text = _call_grok(system_prompt, user_message, max_tokens=700)
            result = _parse_classification_json(text, "grok (no search)")
            if result:
                return result
        except Exception as e:
            print(f"Grok (no search) classification failed: {e}", file=sys.stderr)

    print("AI classification failed: every configured provider was "
          "unreachable/erroring.", file=sys.stderr)
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
        print("AI classification failed — both Claude and Grok were unreachable/"
              "erroring, or neither is configured. Scoring is AI-only now, so no "
              "alert can be sent. Check ANTHROPIC_API_KEY / XAI_API_KEY.",
              file=sys.stderr)
        send_system_alert(
            "Self-test: AI classification failed on both Claude and Grok. "
            "Scoring is AI-only — check ANTHROPIC_API_KEY / XAI_API_KEY."
        )
        return

    score = ai_result["score"]
    label = ai_result["label"]
    summary = ai_result["summary"]
    reasoning = ai_result["reasoning"]
    print(f"Scored via AI: {label} {score}/100 — {reasoning} "
          f"(first seen: {ai_result['first_seen']}, case: {ai_result['case_key']})")

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
# already tries every configured provider in priority order before giving
# up; this only fires once ALL of them have failed. Tweets during that
# window are skipped (not silently keyword-scored) and you're paged on
# Telegram instead, cooldown-guarded so a stuck outage doesn't spam you
# once per tweet.
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

        score = ai_result["score"]
        label = ai_result["label"]
        summary = ai_result["summary"]
        reasoning = ai_result["reasoning"]
        first_seen = ai_result["first_seen"]
        case_key = ai_result["case_key"]
        fields = ai_result["fields"]

        # Always log the score, even for tweets that won't alert — this is
        # what you want to watch to calibrate MIN_RISK_SCORE_TO_ALERT and
        # MIN_ENGAGEMENT_FILTER against real traffic.
        print(f"  [{label} {score}/100] {likes} likes @{tweet['username']}: {preview}")
        if reasoning:
            print(f"    reasoning: {reasoning}")
        print(f"    first seen: {first_seen} | case: {case_key}")

        if likes < MIN_ENGAGEMENT_FILTER:
            print(f"    -> skipped (below MIN_ENGAGEMENT_FILTER={MIN_ENGAGEMENT_FILTER})")
            continue
        if score < MIN_RISK_SCORE_TO_TRACK:
            print(f"    -> skipped (below MIN_RISK_SCORE_TO_TRACK={MIN_RISK_SCORE_TO_TRACK})")
            continue

        # Safety net: collapse near-duplicate case_keys (see
        # resolve_case_key()) before persisting, in case the AI drifted to
        # a variant of an existing case instead of reusing it exactly.
        resolved_key = resolve_case_key(case_key, tweet["text"])
        if resolved_key != case_key:
            print(f"    -> merged into existing case '{resolved_key}' "
                  f"(AI proposed '{case_key}')")
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
            case_key, tweet, score, label, summary, fields, first_seen
        )
        if not is_new_case and not changed_fields:
            print(f"    -> skipped (case '{case_key}' already known, no new "
                  f"information in this tweet — recorded to case history anyway)")
            continue

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
                continue
            changed_fields = alert_worthy_changes

        if score < MIN_RISK_SCORE_TO_ALERT:
            print(f"    -> tracked but not alerted (below MIN_RISK_SCORE_TO_ALERT="
                  f"{MIN_RISK_SCORE_TO_ALERT}) — case '{case_key}' updated silently")
            continue

        if is_new_case:
            zh_text = translate_to_chinese(tweet["text"])
            message = format_alert(tweet, score, label, zh_text, summary)
        else:
            pretty_fields = ", ".join(f.replace("_", " ") for f in changed_fields)
            print(f"    -> case update: new info in {pretty_fields}")
            message = format_case_update_alert(tweet, score, label, case_key, changed_fields, fields)

        send_telegram_alert(message)
        if summary:
            remember_alert(summary)  # so future duplicates of this get suppressed
        print(f"    -> ALERT SENT")
        time.sleep(1)  # be gentle with Telegram's rate limits

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

    if not ANTHROPIC_API_KEY and not XAI_API_KEY:
        print("ERROR: Neither ANTHROPIC_API_KEY nor XAI_API_KEY is set. "
              "Scoring is AI-only — the bot cannot classify any tweets "
              "without at least one of these configured.", file=sys.stderr)
        sys.exit(1)

    if LIVE_SEARCH_RECENCY_CHECK and XAI_API_KEY:
        print(f"AI provider priority: 1) Grok ({GROK_LIVE_SEARCH_MODEL}) WITH live X "
              f"search — classifies AND verifies recency in one call, folding "
              f"how fresh the incident is directly into the risk score; "
              + (f"2) Claude ({CLAUDE_MODEL}) as fallback (no live search); "
                 if ANTHROPIC_API_KEY else "2) Claude NOT configured; ")
              + f"3) Grok without search as last resort. Live search bills "
              f"per post/profile fetched, separate from chat tokens, and "
              f"only runs on candidate tweets your two search queries "
              f"already pulled — not every tweet on X. Set "
              f"LIVE_SEARCH_RECENCY_CHECK=false to disable it and always "
              f"use plain classification instead.")
    else:
        print(
            "AI provider priority: "
            + (f"1) Claude ({CLAUDE_MODEL}); " if ANTHROPIC_API_KEY else "Claude NOT configured; ")
            + (f"2) Grok ({GROK_MODEL}), no live search."
               if XAI_API_KEY else "Grok NOT configured.")
            + (" Live-search recency check is OFF." if not XAI_API_KEY
               else " Live-search recency check is disabled (LIVE_SEARCH_RECENCY_CHECK=false).")
        )

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
