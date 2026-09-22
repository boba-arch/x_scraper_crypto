"""
On-demand case report — run this locally via the Railway CLI to pull the
full picture on a tracked incident and have it sent to your Telegram chat.

This does NOT run as part of the deployed bot (it's not in the Procfile).
It's meant to be run from your own PC, from inside this project folder,
using `railway run`, which injects the same environment variables
(REDIS_URL, TELEGRAM_BOT_TOKEN, etc.) that the deployed bot uses — so it
reads the SAME persistent case database and can post to the SAME Telegram
chat, without needing any new bot feature or two-way Telegram support.

USAGE (from your PC, after `railway login` and `railway link` once):
    railway run python case_report.py egld
    railway run python case_report.py                     (lists all known cases)

The search term matches against the case_key and its display name
(case-insensitive, partial match is fine — you don't need the exact key).
If it matches more than one case, or none, you get a list back on Telegram
instead of a report, so you can re-run with a more specific term.

See SETUP_GUIDE.md for one-time setup steps (installing the Railway CLI,
logging in, linking this folder to your project).
"""

import sys
from datetime import datetime, timezone

import crypto_alert_bot as bot


def safe_send_telegram(message: str):
    """Sends to Telegram, but never lets a network hiccup crash this
    one-off script with a raw traceback — the report still printed to the
    console above is the fallback."""
    try:
        bot.send_telegram_alert(message)
        print("\nSent to Telegram.")
    except Exception as e:
        print(f"\nCouldn't send to Telegram ({e}) — but the report above is "
              f"still complete, just read it here instead.", file=sys.stderr)


def find_matching_cases(query: str) -> list[dict]:
    """Returns full case dicts whose case_key or display_name contains query
    (case-insensitive). Empty query matches everything."""
    query = query.strip().lower()
    matches = []
    for case_key in bot.list_case_keys():
        case = bot.get_case(case_key)
        if not case:
            continue
        haystack = f"{case_key} {case.get('display_name', '')}".lower()
        if query in haystack:
            matches.append(case)
    return matches


def format_case_list(cases: list[dict]) -> str:
    lines = []
    for c in sorted(cases, key=lambda c: c.get("last_seen", ""), reverse=True):
        lines.append(
            f"• <b>{c.get('display_name', c['case_key'])}</b>  "
            f"[{c.get('status', 'unknown')}]  "
            f"last seen: {c.get('last_seen', 'unknown')[:16].replace('T', ' ')}"
        )
    return "\n".join(lines)


def generate_full_report(case: dict) -> str:
    """
    Asks the AI (Claude primary, Grok fallback — same providers as the main
    bot) to synthesize this case's full structured record + update history
    into a readable status report. Returns the AI's text, or a plain
    fallback dump of the raw data if both providers fail.
    """
    updates_text = "\n".join(
        f"[{u['time'][:16].replace('T', ' ')} UTC] (@{u['username']}, "
        f"{u['label']} {u['score']}) {u['summary']}"
        + (f" (first seen: {u['first_seen_estimate']})" if u.get("first_seen_estimate") else "")
        for u in case.get("updates", [])
    )
    fields_text = "\n".join(
        f"{f.replace('_', ' ').title()}: {case.get(f, 'unknown') or 'unknown'}"
        for f in bot.CASE_TRACKED_FIELDS
    )

    system_prompt = (
        "You are a crypto security analyst writing a full status report for "
        "a risk officer at an exchange, on ONE specific tracked incident. "
        "You're given the incident's current structured facts and its full "
        "chronological update history (each entry is a separate tweet that "
        "was judged to add something new).\n\n"
        "Write a clear report covering: (1) what happened and to which "
        "project/protocol/token(s), (2) a brief timeline of how it "
        "developed, (3) current status, (4) explicitly: has the attacker "
        "been identified or caught? (say 'not stated' if unclear), (5) "
        "explicitly: have funds been frozen or recovered? (say 'not stated' "
        "if unclear), (6) total estimated financial impact if known, (7) "
        "known attacker/destination addresses if any. Be direct and "
        "factual — say 'not stated' rather than guessing at anything the "
        "data doesn't actually cover. Plain text, no JSON, no markdown "
        "headers, just the report itself. Keep it tight — this is read on "
        "a phone."
    )
    user_message = (
        f"Case: {case.get('display_name', case['case_key'])}\n"
        f"First seen: {case.get('first_seen', 'unknown')}\n"
        f"Last seen: {case.get('last_seen', 'unknown')}\n\n"
        f"Current known facts:\n{fields_text}\n\n"
        f"Update history ({len(case.get('updates', []))} entries):\n{updates_text}"
    )

    if bot.ANTHROPIC_API_KEY:
        try:
            return bot._call_claude(system_prompt, user_message, max_tokens=700)
        except Exception as e:
            print(f"Claude report generation failed, trying Grok: {e}", file=sys.stderr)
    if bot.XAI_API_KEY:
        try:
            return bot._call_grok(system_prompt, user_message, max_tokens=700)
        except Exception as e:
            print(f"Grok report generation failed: {e}", file=sys.stderr)

    # Both failed (or neither configured) — fall back to the raw data
    # rather than sending nothing.
    return (
        "(AI report generation unavailable — showing raw data instead)\n\n"
        f"{fields_text}\n\nUpdate history:\n{updates_text}"
    )


def main():
    if not bot.get_redis():
        print("ERROR: Can't connect to Redis (REDIS_URL missing or unreachable). "
              "Make sure you're running this via `railway run` from inside "
              "the linked project folder.", file=sys.stderr)
        sys.exit(1)

    query = " ".join(sys.argv[1:]).strip()
    matches = find_matching_cases(query)

    if not matches:
        all_cases = find_matching_cases("")
        if all_cases:
            message = (
                f"🔍 No case matched \"{query}\".\n\nKnown cases:\n"
                + format_case_list(all_cases)
            )
        else:
            message = "🔍 No cases tracked yet — the database is empty."
        print(message)
        safe_send_telegram(message)
        return

    if len(matches) > 1:
        message = (
            f"🔍 \"{query}\" matched {len(matches)} cases — be more specific:\n\n"
            + format_case_list(matches)
        )
        print(message)
        safe_send_telegram(message)
        return

    case = matches[0]
    print(f"Generating full report for: {case.get('display_name', case['case_key'])}...")
    report_text = generate_full_report(case)

    header = (
        f"📋 <b>{case.get('display_name', case['case_key'])}</b>\n"
        f"<i>Status: {case.get('status', 'unknown')} | "
        f"{len(case.get('updates', []))} update(s) | "
        f"first seen: {case.get('first_seen', 'unknown')[:16].replace('T', ' ')}</i>\n\n"
    )
    message = header + report_text

    print(message)
    safe_send_telegram(message)


if __name__ == "__main__":
    main()
