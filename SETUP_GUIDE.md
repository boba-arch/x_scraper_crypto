## How "real-time" this actually is

X's true instant-push tool (filtered stream) now sits at Enterprise pricing
— guides put it around $42,000+/month since the mid-tier plan that used to
include it closed to new signups. That's not realistic for this use case.

Instead, this bot runs **continuously** and checks for new tweets every
30–60 seconds, remembering exactly where it left off (via each tweet's ID)
so it never re-reads or re-pays for the same tweet twice. In practice
that's a ~30–60 second delay from tweet to Telegram alert — not literally
instant, but close, and dramatically cheaper.

## Cost reality check

X moved to pay-per-use pricing in Feb 2026: reading a tweet costs $0.005.
Because this bot only reads *new* tweets (not the same batch repeatedly),
your cost tracks actual incident volume, not how often it polls — **but
that volume depends heavily on how broad your keyword query is.** Generic
words like "hack" or "token" alone match huge amounts of unrelated
crypto-Twitter noise. The default query here adds `min_faves:5` (a
minimum-engagement filter applied by X itself, before you're billed) plus
exclusions for common false-positive phrases, specifically to keep this
under control. If you widen the keyword lists later, watch your usage
dashboard for a few hours afterward to catch any cost spike early.

**Hosting**: for a lightweight always-on bot like this, Railway is the
simplest option — connect your GitHub repo, it deploys automatically as a
background worker, and typical cost lands around **$5–10/month** for this
scale of workload. Render is a steadier flat-rate alternative at about
**$7/month**. Both are described below; pick either, Railway is the easier
first setup.

**If you'd rather not run 24/7 paid infrastructure at all:** the free
route is joining human-curated Telegram channels directly (*Investigations
by ZachXBT*, *PeckShield*, *OfficerCIA*) — free, but you lose the custom
risk scoring and guaranteed keyword coverage. Just flagging it's there if
priorities shift.

---

## What you'll need

1. A free **GitHub** account (to host the code)
2. A free **Railway** or **Render** account (to run it 24/7)
3. An **X (Twitter) Developer** account with API access (paid, pay-per-use)
4. A free **Telegram bot** (takes 2 minutes)

---

## Step 1 — Get your X API key

1. Go to https://developer.x.com and sign up / log in.
2. Create a new **Project** and **App** (v2 access requires apps to live
   inside a Project).
3. Set up billing under pay-per-use.
4. Find your **Bearer Token** under the app's "Keys and Tokens" tab. Copy it
   somewhere safe.

## Step 2 — Create your Telegram bot

1. Open Telegram, search for **@BotFather**, start a chat with it.
2. Send `/newbot` and follow the prompts.
3. BotFather gives you a **bot token** — copy it.
4. Decide where alerts go: a private chat with yourself, or a dedicated
   group/channel for your risk team (recommended). Add your bot to that
   chat.
5. Get the **chat ID**:
   - Send any message in that chat.
   - Visit `https://api.telegram.org/bot<YOUR_BOT_TOKEN>/getUpdates` in a
     browser (replace `<YOUR_BOT_TOKEN>`).
   - Find `"chat":{"id": ...}` in the response — that number (possibly
     negative, for groups) is your chat ID.

## Step 2b — Get a free DeepL translation key (recommended)

The free public translate endpoints get rate-limited when called from
shared cloud IPs like Railway's — you may see "(translation unavailable)"
in alerts as a result. A free DeepL API key fixes this: 500,000
characters/month at no cost, authenticated to your own account so it
doesn't share a rate limit with anyone else.

1. Go to https://www.deepl.com/pro-api and sign up for **DeepL API Free**
   (a card is required to verify identity, but you won't be charged unless
   you explicitly upgrade).
2. Once signed up, find your **Authentication Key** under Account settings.
3. You'll add this as `DEEPL_API_KEY` in Step 4 below. If you skip this
   step, the bot still works — it falls back to the free public endpoints,
   just less reliably.

## Step 3 — Put this project on GitHub

1. Create a free account at https://github.com if needed.
2. Create a **new repository** (private is fine, recommended for a risk
   tool), e.g. `crypto-incident-monitor`.
3. Upload `crypto_alert_bot.py`, `requirements.txt`, and `Procfile` using
   GitHub's "Add file → Upload files" button.

## Step 4 — Deploy it to run 24/7 on Railway

1. Go to https://railway.app and sign up (you can sign up with your GitHub
   account, which makes this step faster).
2. Click **New Project → Deploy from GitHub repo**, and select the
   repository you just created.
3. Railway will detect the `Procfile` and set it up as a **worker**
   service automatically — no build configuration needed.
4. Go to the service's **Variables** tab and add:
   - `X_BEARER_TOKEN` → your token from Step 1
   - `TELEGRAM_BOT_TOKEN` → your token from Step 2
   - `TELEGRAM_CHAT_ID` → your chat ID from Step 2
   - `DEEPL_API_KEY` → your key from Step 2b (recommended, but the bot
     still runs without it)
5. Railway will deploy and start running the bot automatically. Check the
   **Deployments → Logs** tab — you should see:
   `Crypto incident monitor starting up.`
   If it's missing an env var, the log will say so plainly.
6. Add a payment method under **Settings → Billing** so it keeps running
   past the free trial credit.

That's it — it now runs continuously, and will keep running even if you
close your browser or turn off your computer.

### Alternative: Render instead of Railway
If you'd rather have flat, predictable billing:
1. Go to https://render.com, sign up, **New → Background Worker**, connect
   the same GitHub repo.
2. Render reads the `Procfile` automatically; start command is
   `python crypto_alert_bot.py`.
3. Add the same three environment variables under the service's
   **Environment** tab.
4. Choose the **Starter** plan (~$7/month) so it doesn't spin down.

---

## Testing before you rely on it

Real hack tweets don't happen on a schedule, so test the pipeline in
layers rather than just waiting and hoping. Do these in order — each one
catches a different type of mistake.

### Test 1 — Is your Telegram bot token/chat ID correct? (2 minutes, no bot needed)

Paste this into your **browser's address bar**, with your real values swapped in:

```
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/sendMessage?chat_id=<YOUR_CHAT_ID>&text=hello
```

If it's set up right, you'll immediately get a "hello" message in your
Telegram chat, and the browser will show `"ok":true`. If not, the browser
response will tell you what's wrong (wrong token, bot not in the chat,
wrong chat ID, etc.) — fix that before moving on.

### Test 2 — Is your X API bearer token valid? (2 minutes)

Open **Windows PowerShell** (search for it in the Start menu — you're just
pasting one line, not writing code) and run, with your token swapped in:

```powershell
Invoke-RestMethod -Uri "https://api.twitter.com/2/tweets/search/recent?query=bitcoin" -Headers @{Authorization="Bearer YOUR_X_BEARER_TOKEN"}
```

If it works, you'll see a block of tweet data print out. If your token or
billing setup is wrong, you'll get a clear error (401 = bad token, 403 =
billing/access issue) instead.

### Test 3 — Full pipeline test, using the bot itself (5 minutes)

I've built a self-test into the bot so you don't have to wait for a real
hack to confirm everything works end-to-end (search → scoring →
translation → Telegram formatting).

1. In Railway (or Render), add one more environment variable:
   `SELF_TEST_ON_START` = `true`
2. Redeploy / restart the service.
3. Check the logs — you should see `Running self-test...` then
   `Self-test message sent.`
4. Check your Telegram chat — you should receive a message starting with
   **"🧪 SELF-TEST — not a real incident"**, showing a sample risk score,
   English text, and Chinese translation. This confirms scoring,
   translation, and Telegram delivery all work correctly.
5. **Turn `SELF_TEST_ON_START` back to `false`** (or delete the variable)
   afterward — otherwise it'll send a test message every time the service
   restarts, which will clutter your real alerts.

### Test 4 — Confirm it catches real tweets (ongoing)

Once Tests 1–3 pass, the last thing to confirm is that it's actually
finding real matching tweets, not just capable of sending test ones.
Two ways to do this without waiting indefinitely:

- **Temporarily lower the bar**: set `MIN_RISK_SCORE_TO_ALERT` to `1` for
  15–20 minutes. Crypto Twitter is noisy enough that you'll likely see at
  least one real alert (even a low-severity one) come through, confirming
  the search itself works. Then set it back to your real threshold (e.g.
  25 or 45).
- **Check the logs directly**: Railway/Render logs will print a line like
  `3 new candidate tweet(s)` whenever the search finds anything, even if
  none of them score high enough to alert — so the logs alone tell you the
  search is actively working, independent of your alert threshold.

---

## Tuning it to your risk appetite

All of these are environment variables — edit them directly in Railway's
or Render's dashboard (no code, no redeploy hassle):

- `MIN_ENGAGEMENT_FILTER` (default 5) — minimum likes a tweet needs to
  even be returned by X's search. This is your **primary cost control** —
  raise it (e.g. to 20 or 50) to cut billed volume sharply if costs run
  high; lower it if you're missing low-engagement but real early signals.
- `MIN_RISK_SCORE_TO_ALERT` (default 25) — raise to e.g. 45 to only get
  High/Critical alerts; lower to catch more.
- `POLL_INTERVAL_SECONDS` (default 45) — how often it checks. Going lower
  than ~20s risks hitting X's rate limit (450 search calls/15 min).
- `MAX_RESULTS` (default 25) — safety cap per poll, mainly matters during
  traffic bursts.

You can also edit the keyword lists and `TRUSTED_ACCOUNTS` set directly in
`crypto_alert_bot.py` (editable right in GitHub's web UI, then Railway/
Render auto-redeploys) to tune which accounts get a risk-score boost, or
add specific chains/protocols you care about.

---

## Important caveats

- **Translation**: uses DeepL if you've added `DEEPL_API_KEY` (reliable,
  your own quota, 500K free chars/month) with two free keyless services
  (Google, then MyMemory) as fallback if DeepL isn't configured or has a
  brief outage. If you ever see "(translation unavailable — see logs)" in
  an alert, check the Railway/Render logs — they print the actual
  underlying error from each provider in the order they were tried.
- **Risk score is a triage heuristic, not a verified assessment.** Built
  from keyword severity, trusted-account matching, and engagement —
  useful for prioritization, not a substitute for your own verification
  (on-chain data, official project statements) before acting on an alert.
- **X-only coverage.** Pair this with the Telegram security channels
  mentioned above and on-chain monitors for fuller coverage.
- **If the process restarts** (deploys, host maintenance, etc.), it resets
  to "look back 5 minutes" rather than remembering history from before the
  restart — so a restart could very rarely cause a brief gap or a small
  amount of overlap. For a mission-critical setup, ask and I can add
  persistent state (e.g. a small Redis or database) so it survives
  restarts with zero gaps.
