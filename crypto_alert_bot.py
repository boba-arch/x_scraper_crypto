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

# AI scoring uses Grok as the primary provider, with automatic failover to
# Claude if Grok is unreachable/erroring — you only get paged on Telegram if
# BOTH fail. Set whichever key(s) you have; at least one is required.
XAI_API_KEY = os.environ.get("XAI_API_KEY")  # primary provider (Grok)
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")  # fallback provider (Claude)
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
MIN_ENGAGEMENT_FILTER = int(os.environ.get("MIN_ENGAGEMENT_FILTER", "0"))

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
    """
    Runs the X search query (build_queries()) every poll and returns
    (tweets, newest_id, error_message). error_message is None on success
    (even with zero matches — that's a normal quiet period).
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


def _build_classification_prompt(trusted_list: str) -> str:
    return (
        "Is this tweet reporting that a crypto attack, hack, exploit or "
        "security incident is happening RIGHT NOW? Tweets from trusted "
        f"accounts score higher. Trusted: {trusted_list}.\n\n"
        "Respond with ONLY valid JSON (no markdown):\n"
        '{"is_real_incident": true/false, "risk_score": 0-100 (0-24 not an '
        "incident, 25-44 plausible, 45-69 credible and unfolding, 70-100 "
        'major and active), "case_key": "short_lowercase_underscore id of '
        "the incident; if it matches one in 'Known open cases', copy that "
        'key EXACTLY", "tokens_affected": "symbols or \'unknown\'", '
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
    crypto security incident and assign a risk score. No live X search is
    used (it was removed to cut cost), so there is no recency verification.

    Provider priority (first that succeeds wins):
      1. Grok — plain chat completion.
      2. Claude — fallback if Grok is unconfigured or fails.

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

    system_prompt = _build_classification_prompt(trusted_list)

    # 1. Grok (primary).
    if XAI_API_KEY:
        try:
            text = _call_grok(system_prompt, user_message, max_tokens=700)
            result = _parse_classification_json(text, "grok")
            if result:
                return result
        except Exception as e:
            print(f"Grok classification failed, trying next provider: {e}",
                  file=sys.stderr)

    # 2. Claude (fallback).
    if ANTHROPIC_API_KEY:
        try:
            text = _call_claude(system_prompt, user_message, max_tokens=700)
            result = _parse_classification_json(text, "claude")
            if result:
                return result
        except Exception as e:
            print(f"Claude classification failed: {e}", file=sys.stderr)

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
          f"(case: {ai_result['case_key']})")

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

        # Cheap check FIRST so low-engagement tweets never cost an AI call.
        if likes < MIN_ENGAGEMENT_FILTER:
            print(f"  [not classified] {likes} likes @{tweet['username']}: {preview} "
                  f"-> skipped (below MIN_ENGAGEMENT_FILTER={MIN_ENGAGEMENT_FILTER})")
            continue

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

        if score < MIN_RISK_SCORE_TO_TRACK:
            print(f"    -> skipped (below MIN_RISK_SCORE_TO_TRACK={MIN_RISK_SCORE_TO_TRACK})")
            continue
        print(f"    case: {case_key}")

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

    print(
        "AI provider priority: "
        + (f"1) Grok ({GROK_MODEL}); " if XAI_API_KEY else "Grok NOT configured; ")
        + (f"2) Claude ({CLAUDE_MODEL}) as fallback." if ANTHROPIC_API_KEY else "Claude NOT configured.")
        + " Live X search is removed."
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
