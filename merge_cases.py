"""
On-demand case merge — run this locally via the Railway CLI to fold several
fragmented case records (the same real-world incident that got split into
multiple case_keys, e.g. because the AI invented a new key each time) into
one, and post a confirmation to your Telegram chat.

This does NOT run as part of the deployed bot (it's not in the Procfile).
Like case_report.py, it's meant to be run from your own PC, from inside
this project folder, using `railway run`, which injects the same REDIS_URL
the deployed bot uses — so it edits the SAME persistent case database.

USAGE (from your PC, after the one-time `railway login` / `railway link`
setup described in SETUP_GUIDE.md):

    # Step 1 — find the exact case_keys you want to merge (partial,
    # case-insensitive search, same as case_report.py):
    railway run python merge_cases.py list cosmos

    # Step 2 — merge them. The FIRST case_key you list is the one that
    # survives (the "keep" key) — all the others are folded into it and
    # then deleted. All of the survivors' + absorbed cases' update history
    # is combined and sorted by time; first_seen becomes the EARLIEST of
    # all of them, last_seen the LATEST, and each tracked fact field
    # (tokens_affected, estimated_loss_usd, latest_official_response,
    # hacker_addresses, asset_movement, status) takes the most recently
    # updated non-unknown value across all the merged cases:
    railway run python merge_cases.py merge cosmos_hub_noble_exploit cosmos_hub_halting cosmos_hub_noble_incident cosmos_hub_governance_exploit neutron_cosmos_hub_exploit cosmos_hub_neutron_exploit cosmos_hub_neutron_attack cosmos_hub_validators_halt

    # Add --dry-run to preview the merge (prints what WOULD happen) without
    # writing/deleting anything:
    railway run python merge_cases.py merge cosmos_hub_noble_exploit cosmos_hub_halting --dry-run

This only fixes cases that already exist. It doesn't change how NEW tweets
get classified going forward — that's the "Known open cases" context now
passed to the AI classifier in crypto_alert_bot.py, which should keep this
kind of fragmentation from happening again.
"""

import sys
from datetime import datetime, timezone

import crypto_alert_bot as bot
from case_report import find_matching_cases, format_case_list, safe_send_telegram


def merge_cases(keep_key: str, absorb_keys: list[str], dry_run: bool = False):
    all_keys = [keep_key] + absorb_keys
    cases = {}
    missing = []
    for k in all_keys:
        c = bot.get_case(k)
        if c is None:
            missing.append(k)
        else:
            cases[k] = c

    if missing:
        print(f"ERROR: these case_key(s) don't exist, aborting: {', '.join(missing)}",
              file=sys.stderr)
        print("Run `railway run python merge_cases.py list <search term>` "
              "to find the exact keys.", file=sys.stderr)
        sys.exit(1)

    keep_case = cases[keep_key]
    absorb_cases = [cases[k] for k in absorb_keys]
    all_cases = [keep_case] + absorb_cases

    # Combine + dedupe update history (by tweet_id, falling back to the
    # (time, username, summary) tuple for updates with no tweet_id), then
    # sort chronologically.
    seen = set()
    combined_updates = []
    for c in all_cases:
        for u in c.get("updates", []):
            dedupe_key = u.get("tweet_id") or (u.get("time"), u.get("username"), u.get("summary"))
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            combined_updates.append(u)
    combined_updates.sort(key=lambda u: u.get("time", ""))
    combined_updates = combined_updates[-bot.CASE_MAX_UPDATES_STORED:]

    first_seen = min(c.get("first_seen", "") for c in all_cases if c.get("first_seen"))
    last_seen = max(c.get("last_seen", "") for c in all_cases if c.get("last_seen"))

    # For each tracked fact field, take the value from whichever merged
    # case was updated most recently and actually has a non-empty/non-
    # "unknown" value for it — falls back through older cases if the most
    # recent one didn't state it.
    cases_by_recency = sorted(all_cases, key=lambda c: c.get("last_seen", ""), reverse=True)
    merged_fields = {}
    for field in bot.CASE_TRACKED_FIELDS:
        value = ""
        for c in cases_by_recency:
            candidate = (c.get(field) or "").strip()
            if candidate and candidate.lower() not in bot._CASE_FIELD_EMPTY_VALUES:
                value = candidate
                break
        merged_fields[field] = value

    merged_case = {
        "case_key": keep_key,
        "display_name": keep_case.get("display_name", keep_key.replace("_", " ").title()),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "updates": combined_updates,
    }
    merged_case.update(merged_fields)

    print(f"Merging {len(absorb_keys)} case(s) into \"{keep_key}\":")
    for k in absorb_keys:
        print(f"  - {k} ({len(cases[k].get('updates', []))} update(s))")
    print(f"\nResult: {len(combined_updates)} combined update(s), "
          f"first_seen={first_seen}, last_seen={last_seen}")
    for field, value in merged_fields.items():
        print(f"  {field}: {value or '(unknown)'}")

    if dry_run:
        print("\n--dry-run set: nothing was written or deleted.")
        return None

    r = bot.get_redis()
    bot.save_case(keep_key, merged_case)
    for k in absorb_keys:
        r.delete(bot.CASE_KEY_PREFIX + k)
        r.srem(bot.CASE_INDEX_KEY, k)

    return merged_case


def main():
    if not bot.get_redis():
        print("ERROR: Can't connect to Redis (REDIS_URL missing or unreachable). "
              "Make sure you're running this via `railway run` from inside "
              "the linked project folder.", file=sys.stderr)
        sys.exit(1)

    args = sys.argv[1:]
    if not args or args[0] not in ("list", "merge"):
        print(__doc__)
        sys.exit(1)

    if args[0] == "list":
        query = " ".join(args[1:]).strip()
        matches = find_matching_cases(query)
        if not matches:
            print(f'No case matched "{query}".')
        else:
            print(format_case_list(matches).replace("<b>", "").replace("</b>", "")
                  .replace("<i>", "").replace("</i>", ""))
            print("\nRaw case_keys (use these with `merge`):")
            for c in sorted(matches, key=lambda c: c.get("last_seen", ""), reverse=True):
                print(f"  {c['case_key']}")
        return

    # merge
    dry_run = "--dry-run" in args
    keys = [a for a in args[1:] if a != "--dry-run"]
    if len(keys) < 2:
        print("ERROR: need at least 2 case_keys — the first is kept, the "
              "rest are merged into it and deleted.", file=sys.stderr)
        sys.exit(1)

    keep_key, absorb_keys = keys[0], keys[1:]
    merged = merge_cases(keep_key, absorb_keys, dry_run=dry_run)

    if merged is not None:
        message = (
            f"\U0001f501 Merged {len(absorb_keys)} duplicate case(s) into "
            f"<b>{merged.get('display_name', keep_key)}</b> (case_key: "
            f"{keep_key})\n\nAbsorbed: {', '.join(absorb_keys)}\n"
            f"Combined updates: {len(merged.get('updates', []))}"
        )
        print()
        safe_send_telegram(message)


if __name__ == "__main__":
    main()
