"""
Test how the bot would score a tweet — no Telegram message, nothing saved.

Run it from your PC inside this project folder (uses the same keys and Redis
as the deployed bot):

    railway run python test_tweet.py "Ledger confirms hardware implant in CryptoBilis reseller"

Or from the Railway shell (`railway ssh`):

    python test_tweet.py "tweet text here"

You can also pass a link to the tweet instead of its text (the bot fetches the
text and author from X; this costs one tweet read on your X API plan):

    railway run python test_tweet.py https://x.com/FuturesWire/status/1234567890

Optional: pretend the tweet came from a particular account:

    python test_tweet.py "tweet text here" --user peckshieldalert

It makes ONE Grok call and prints the score, the case key the bot would file
it under, the extracted fields, and whether it would be tracked / alerted
with your current thresholds.
"""

import re
import sys

import requests

import crypto_alert_bot as bot


def fetch_tweet(url: str):
    """Returns (text, username) for an x.com / twitter.com status link."""
    m = re.search(r"/status/(\d+)", url)
    if not m:
        print("ERROR: couldn't find a tweet ID in that link.", file=sys.stderr)
        sys.exit(1)
    if not bot.X_BEARER_TOKEN:
        print("ERROR: X_BEARER_TOKEN isn't set — run via `railway run`.", file=sys.stderr)
        sys.exit(1)
    resp = requests.get(
        f"https://api.twitter.com/2/tweets/{m.group(1)}",
        headers={"Authorization": f"Bearer {bot.X_BEARER_TOKEN}"},
        params={"tweet.fields": "text,note_tweet,author_id",
                "expansions": "author_id", "user.fields": "username"},
        timeout=30,
    )
    if resp.status_code != 200:
        print(f"ERROR: X API returned {resp.status_code}: {resp.text[:200]}", file=sys.stderr)
        sys.exit(1)
    data = resp.json()
    if "data" not in data:
        print(f"ERROR: tweet not found or not visible: {str(data)[:200]}", file=sys.stderr)
        sys.exit(1)
    tw = data["data"]
    text = (tw.get("note_tweet") or {}).get("text") or tw["text"]  # note_tweet = full text of long posts
    users = data.get("includes", {}).get("users", [])
    return text, (users[0]["username"] if users else "unknown")


def main():
    args = sys.argv[1:]
    username = "test_account"
    if "--user" in args:
        i = args.index("--user")
        try:
            username = args[i + 1].lstrip("@")
        except IndexError:
            print("ERROR: --user needs a handle.", file=sys.stderr)
            sys.exit(1)
        del args[i:i + 2]
    text = " ".join(args).strip()
    if not text:
        print(__doc__)
        sys.exit(1)
    if re.match(r"https?://(www\.)?(x|twitter)\.com/", text):
        text, author = fetch_tweet(text)
        if username == "test_account":
            username = author
        print(f"Fetched tweet by @{author}:\n{text}\n")
    if not bot.XAI_API_KEY:
        print("ERROR: XAI_API_KEY isn't set — run this through `railway run` "
              "or `railway ssh`.", file=sys.stderr)
        sys.exit(1)

    tweet = {"id": "0000000000", "text": bot.resolve_token_symbols(text),
             "username": username, "verified": False}
    result = bot.classify_with_ai(tweet)
    if not result:
        print("Grok call failed — see the error above.")
        sys.exit(1)

    score = result["score"]
    key = bot.resolve_case_key(result["case_key"], tweet["text"], tweet["id"])
    existing = bot.get_case(key) is not None

    print(f"\nScore:      {result['label']} {score}/100")
    print(f"Summary:    {result['summary']}")
    print(f"AI key:     {result['case_key']}")
    print(f"Filed as:   {key}  ({'existing case' if existing else 'new case'})")
    for f in bot.CASE_TRACKED_FIELDS:
        print(f"  {f}: {result['fields'].get(f) or '-'}")

    print(f"\nTrack threshold {bot.MIN_RISK_SCORE_TO_TRACK}, alert threshold {bot.MIN_RISK_SCORE_TO_ALERT}:")
    if score < bot.MIN_RISK_SCORE_TO_TRACK:
        print("  -> would be SKIPPED (below track threshold)")
    elif existing:
        changed = bot.diff_case_fields(bot.get_case(key), result["fields"])
        worthy = [f for f in changed if f in bot.ALERT_WORTHY_UPDATE_FIELDS]
        if worthy and score >= bot.MIN_RISK_SCORE_TO_ALERT:
            print(f"  -> would send a CASE UPDATE alert (new: {', '.join(worthy)})")
        else:
            print("  -> would be recorded, no alert (nothing new)")
    elif score >= bot.MIN_RISK_SCORE_TO_ALERT:
        print("  -> would send a NEW CASE alert")
    else:
        print("  -> would be recorded silently (below alert threshold)")


if __name__ == "__main__":
    main()
