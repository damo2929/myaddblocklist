# Adblock-listgen

A Pi-hole blocklist for **Ad-Shield**, the ad-recovery service that phoronix.com (and other
sites) use to serve ads to people who block them. Ad-Shield gets past DNS blocking by moving
to a new throwaway domain about once a week. This project reads the upcoming domains out of
Ad-Shield's own (obfuscated) script so they're blocked **before** they're used, and falls back
to spotting them in the Pi-hole's query log. New domains go into `blocklist.txt` automatically.

## Why this exists

Ad-Shield is a game of cat and mouse. Each time a blocklist catches up with it, it moves to
a fresh domain to push its ads, and with them the risk of malvertising, back onto our screens.
It also goes out of its way to dodge detection: encrypted strings, fallback CDN mirrors, a
WebSocket channel that delivers code as a last resort, and bot checks that stop automated
browsers from seeing what it does.

This project doesn't wait for the next domain to show up. It reads Ad-Shield's own playbook
(the rotation list inside its script) and blocks the domains it plans to use before it uses
them. The Pi-hole log scan is a backup for anything that gets through first. The aim is to
stay ahead in that race instead of reacting to each move after the ads have already loaded.

## Where the code runs: on the visitor's device, not the server

None of Ad-Shield's workaround happens on Phoronix's server. All of it is JavaScript sent
to the visitor's browser and run **on the visitor's own computer**:

- **Loader:** the obfuscated recovery script is inline in the page HTML. The browser runs
  it, and it removes its own `<script>` tag, then injects new script tags to fetch the
  next stage.
- **Stage-2 script:** about 180KB of obfuscated JavaScript fetched from public CDNs
  (`cdn.jsdelivr.net/gh/ad-shield/e/index.js` and mirrors) and run in the browser. This
  is where the rotation domains are tried and the ads are loaded.
- **Last-resort code delivery:** if every script URL is blocked, the loader opens a
  WebSocket to `wss://html-load.cc/ws`, takes whatever JavaScript comes back, puts it in a
  new `<script>` element and runs it. That code is never visible in the page source.
- **Blocker detection on the device:** it sends bait requests (`ad-delivery.net/px.gif`),
  loads FingerprintJS BotD (`m1.openfpcdn.io/botd`) to check for automated browsers, and
  writes what it found to the device's `localStorage`:

  | Key (stored base64-encoded as `<host>_fa_<key>`) | Example value |
  |---|---|
  | `cache_is_blocking_ads` | `true` |
  | `cache_request_filter_active` | `true` |
  | `cache_cosmetic_filter_active` | `false` |
  | `cache_is_blocking_acceptable_ads` | `true` |
  | `cache_adblock_circumvent_score` | `3` |
  | `blocked_script_cache` | base64 JSON list of scripts that were blocked |

**It's third-party code.** None of this comes from Phoronix itself. It's Ad-Shield's code,
served from Ad-Shield's GitHub repository (`github.com/ad-shield/e`, through public CDNs) and
from domains Ad-Shield controls (`html-load.cc` and the rotation domains). We have no
relationship with Ad-Shield and have **not consented** to it running code on our devices.
Blocking its domains with an ad blocker or DNS filter is an explicit refusal. Under the UK's
Privacy and Electronic Communications Regulations (PECR, regulation 6), storing or reading
information on a user's device needs consent obtained **in advance**: freely given,
specific, informed and given by a clear affirmative action. So the refusal is on top of
what the rules require, not something the user should have to give.

So code from a third party we haven't agreed to is delivered to, stored on and run on the
user's machine, specifically to get around that refusal.

**Evasion techniques.** Obfuscated JavaScript on its own is common on legitimate sites:
it's used to shrink code, protect a vendor's code from copying, and in bot-protection
scripts. What stands out here is the combination. Each technique below is one commonly
associated with malware, and here they're used to defeat the user's own security and
privacy controls:

| Ad-Shield does | Where this is usually seen |
|---|---|
| Encrypts its strings so domains and URLs don't appear in the source | Malware hiding its command-and-control servers from scanners |
| The loader deletes its own `<script>` tag after running | Malware removing its traces |
| Rotates throwaway domains to stay ahead of blocklists | Malware swapping domains to stay ahead of blocklists |
| Has fallback chains across several CDNs | Resilient malware infrastructure |
| Takes JavaScript sent over a WebSocket and runs it | Malware fetching instructions from its control server; the code never appears anywhere it can be checked |
| Exists to override a choice the user made on their own device | The opposite of what consent-based software does |

We haven't seen it steal data or damage the device, so this isn't a claim that it's malware.
It's a description of the techniques it uses and what they're for.

**A regulatory gap.** The UK Online Safety Act 2023's duties on fraudulent (scam) adverts
apply only to services Ofcom designates as Category 1 (the largest social media platforms)
or Category 2A (the largest search engines). Even for them, the codes are still in draft:
Ofcom's consultation closed on 2 October 2026, with final codes due by mid-2027. Ad-tech
intermediaries such as ad-recovery and ad-delivery networks aren't directly regulated by the
Act. Ofcom's draft reaches them only through the big platforms that use them, and
commentators have described third-party ad delivery as a gap in the framework. So nothing
currently requires these networks to vet what they push past a user's blocker onto their
screen, which is one more reason to block them yourself.
Sources: [Ofcom consultation](https://www.ofcom.org.uk/online-safety/online-fraud/consultation-fraudulent-advertising-code-of-practice),
[RPC](https://www.rpclegal.com/snapshots/advertising-and-marketing/autumn-2026/online-safety-act-ofcom-consults-on-fraudulent-advertising-codes/),
[Wiggin](https://wiggin.co.uk/insight/fraudulent-advertising-ofcom-consults-on-new-rules-under-online-safety-act/),
[University of Essex](https://repository.essex.ac.uk/42524/).

## Contents

| File | Purpose |
|---|---|
| `blocklist.txt` | The Pi-hole adlist (ABP-style `\|\|domain^` entries) |
| `detect_adshield.py` | Finds Ad-Shield domains (decoded script + Pi-hole query log) and appends new ones to the blocklist |
| `adshield.conf.example` | Template for alert settings (email, Telegram, Home Assistant); copy to `adshield.conf` |
| `deploy/run.sh` | Hourly wrapper: pulls the repo, runs the detector, reloads gravity/FTL when the list changes, commits and pushes new domains |
| `deploy/adshield.cron` | Cron entry installed as `/etc/cron.d/adshield` |

## How Phoronix serves ads past a blocker

Investigated on 2026-10-10 by decoding the page's inline loader and watching live traffic.

1. **Normal ads**: Freestar loads from `a.pub.network/phoronix-com/pubfig.min.js`.
2. **Recovery loader**: an obfuscated inline script (Ad-Shield, `data-sdk="e/1.0.8"`)
   tries a chain of script URLs, moving to the next whenever one fails:
   - `https://html-load.cc/script/<base64 of hostname>.js` (for Phoronix:
     `d3d3LnBob3Jvbml4LmNvbQ.js`)
   - `cdn.jsdelivr.net/gh/ad-shield/e/index.js`
   - `cdn.statically.io/{gh,gl,bb}/ad-shield/e/main/index.js`
   - `rawcdn.githack.com/ad-shield/e/...` and `bbcdn.githack.com/ad-shield/e/...`
   - if all of those fail: a WebSocket to `wss://html-load.cc/ws`, which sends back
     JavaScript to run
3. **Rotating domains**: the stage-2 script (from jsDelivr, version `e/1.0.13`) holds a
   list of four throwaway domains and tries the same `/script/<b64 host>.js` path on each in
   order. When one resolves, ads are proxied through numbered shards `0.<domain>` …
   `9.<domain>`. The list is encrypted in the script and moves forward over time:
   - GitHub / jsDelivr: `worstcommon → nicelyeven → tilljoyfully → betweenbrr`
   - githack mirrors: `nicelyeven → tilljoyfully → betweenbrr → reallywire`

   The script also loads FingerprintJS BotD (`m1.openfpcdn.io/botd`) to detect bots;
   that isn't an ad domain and isn't blocked.
4. **Detection cache**: Ad-Shield stores what it detected in the site's `localStorage`
   under `<host>_fa_<base64 key>` (`cache_is_blocking_ads`, `cache_request_filter_active`,
   `cache_cosmetic_filter_active`, `cache_adblock_circumvent_score`, …). It only switches
   domains on visits after the first one.

`ad-delivery.net/px.gif` is a bait request that Ad-Shield uses to detect ad blockers.

### Domains found so far (as of 2026-10-10)

| Domain | Seen | Source / notes |
|---|---|---|
| html-load.cc | until 26 Sep | primary loader, already blocked by public lists |
| abaftwetly.com | 13 Sep | Pi-hole log, got through |
| referwhen.com | 26–30 Sep | Pi-hole log, got through |
| exceptlone.com | 3–4 Oct | Pi-hole log, got through |
| worstcommon.com | 10 Oct | Pi-hole log + script; main domain blocked, numbered subdomains got through |
| nicelyeven.com | 10 Oct | Pi-hole log + script, got through |
| tilljoyfully.com | not yet used | script only, blocked in advance |
| betweenbrr.com | not yet used | script only, blocked in advance |
| reallywire.com | not yet used | script only (githack copy), blocked in advance |

The domains are random English word pairs on `.com`, and a new one appears roughly every week.

## Why `||domain^`

Plain domains in a Pi-hole adlist are **exact matches**. `worstcommon.com` was already
blocked, yet `0-9.worstcommon.com` still resolved. Pi-hole v6 reads ABP-style `||domain^`
lines in adlists as the domain **plus all its subdomains**, so one entry per rotation
domain covers every shard. Checked on the Pi-hole:

```
$ pihole -q zz-test.nicelyeven.com
  - file:///opt/adshield/blocklist.txt (block)
    - ||nicelyeven.com^
```

The shared CDNs (`cdn.jsdelivr.net`, `cdn.statically.io`, `*.githack.com`) are **not**
blocked: DNS blocking works on whole domains only, and blocking those would break many unrelated sites.
For per-browser coverage of the stage-2 script, add path rules such as
`||cdn.jsdelivr.net/gh/ad-shield/` to uBlock Origin.

## How detection works

`detect_adshield.py` has two sources. Both run by default.

### 1. The script (proactive)

1. Download every copy of the stage-2 script: `raw.githubusercontent.com/ad-shield/e`,
   jsDelivr, statically and both githack mirrors. The repo is force-pushed and the CDNs
   cache it for different lengths of time, so the copies carry different rotation windows;
   the results are merged. A copy that fails or arrives truncated (statically stalls at
   64 KiB) is skipped as a download failure and doesn't trigger a decoder alert. (statically's
   `/gl/` and `/bb/` paths are still in the loader but no longer work, so they're not fetched.)
2. Decode the obfuscated string table with a **pure-Python port** of obfuscator.io's
   decoder (custom base64 + RC4, plus the start-up array rotation). No Ad-Shield code is
   run: the only thing evaluated is the rotation checksum, after checking it contains
   nothing but numbers and arithmetic. The port was checked against the script's own
   decoder (run once in a Node sandbox): all 3,715 strings matched.
3. Put the decoded strings back into the source, join split pieces (`"https://nicelyeven.c"+'om'`),
   and collect every bare-origin `https://<name>.<tld>` URL. Those are the rotation domains.

### 2. The Pi-hole log (reactive backup)

Catches domains that reach browsers some other way (e.g. a newer copy of the script than
the mirrors serve):

1. Read the Pi-hole query log for the last `--hours` (default 24).
2. Flag any `name.tld` with three or more single-digit subdomains (`0.x.com`, `5.x.com`, …).
   Requiring exactly two labels in the base rules out legitimate sharded services such as
   `0.pool.ntp.org`. `gravatar.com` and `wp.com` are excluded explicitly, and you can add
   more with `--exclude`.
3. Report each domain: how many lookups, how many were answered (`GETTING THROUGH`) and
   whether it's already listed.

Each new domain from either source is appended as a `||domain^` line under a dated header
naming the source.

Exit codes: `0` nothing new, `2` new domains added (or found, with `--dry-run`), `1` error.

### Usage

```bash
# Script only: no Pi-hole needed, runs anywhere
./detect_adshield.py --no-log --dry-run

# On the Pi-hole host, reading the FTL database directly (no password needed)
python3 detect_adshield.py --db /etc/pihole/pihole-FTL.db --hours 720 --dry-run

# From another machine through the Pi-hole v6 API (use an app password)
PIHOLE_URL=http://192.168.5.253 PIHOLE_PASSWORD=... ./detect_adshield.py --dry-run
```

| Option | Default | Meaning |
|---|---|---|
| `--no-script` | | skip decoding the Ad-Shield script |
| `--script-url URL` | GitHub + mirrors | script copy to decode (repeatable) |
| `--no-log` | | skip the Pi-hole query log |
| `--db PATH` | API | read `pihole-FTL.db` instead of using the API |
| `--url URL` | `$PIHOLE_URL` or `http://pi.hole` | Pi-hole API base URL |
| `--hours N` | 24 | how far back to look in the log |
| `--min-shards N` | 3 | numbered subdomains needed to flag a domain |
| `--exclude DOMAIN` | | base domain to ignore (repeatable) |
| `--blocklist PATH` | `./blocklist.txt` | file to update |
| `--dry-run` | | report only; alerts are printed, not sent |
| `--config PATH` | `./adshield.conf` | alert settings |
| `--test-alert` | | send a test alert to every configured channel (and update the HA sensor), then exit |

Only Python 3.9+ standard library modules are used.

## Alerts: email, Telegram, Home Assistant

The decoder breaks if Ad-Shield changes its obfuscation (see [Limitations](#limitations)), so
the script reports it. When a copy of the script **downloads but can't be decoded**, an alert
goes to every channel configured in `adshield.conf`. Download failures and timeouts don't
trigger alerts, since mirrors are often flaky.

- **One alert per failure:** the same failure isn't re-sent until it changes or
  `REMIND_HOURS` (default 24) pass. State is kept in `.notify-state.json`.
- **Recovery:** one "working again" alert is sent once every downloaded copy decodes.
- **Early warning:** an alert fires as soon as *any* copy fails, so a format change shows up
  on the first mirror that serves it, while the others still provide the domain list.

| Channel | Settings | Notes |
|---|---|---|
| Email | `NOTIFY_TO`, `NOTIFY_FROM`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURITY` (`none`/`starttls`/`ssl`) | Through your SMTP relay; no SMTP login is supported. |
| Telegram | `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID` | Bot from @BotFather; chat id from `getUpdates`. |
| Home Assistant webhook | `HA_WEBHOOK_URL`, `HA_WEBHOOK_STATUS` (default `yes`) | POSTs `{event, title, message, host}` for alerts (`decoder_failed`, `decoder_recovered`, `test`). With `HA_WEBHOOK_STATUS=yes` it also POSTs `event: status` **every run** with `state` (`ok`/`decoder_failing`), `decoded_copies`, `decode_failures`, `rotation_domains`, `new_domains`, `listed`, `last_run`. No token needed. |
| Home Assistant REST sensor | `HA_URL`, `HA_TOKEN`, `HA_ENTITY` (default `sensor.adshield`) | Optional alternative for the status: sets the entity directly every run, but needs a long-lived token. A state set this way isn't kept across HA restarts. |

Setup on the Pi-hole:

```bash
cd /opt/adshield
cp adshield.conf.example adshield.conf && chmod 600 adshield.conf   # holds tokens
vi adshield.conf
python3 detect_adshield.py --test-alert
```

### Home Assistant setup (current)

Everything runs over the local-only webhook, so no token is involved:

- **Automation** "Ad-Shield blocklist alerts" (`automation.ad_shield_blocklist_alerts`), with a
  webhook trigger (random ID, `local_only`, POST only):
  - `event: status`: silently updates the helpers below.
  - anything else (`decoder_failed`, `decoder_recovered`, `test`): sends the title and message
    to `notify.mobile_app_cph2791` and a persistent notification (`notification_id: adshield`,
    so each alert replaces the last).
- **Helpers**, updated every hourly run and usable on dashboards or in automations:

  | Entity | Holds |
  |---|---|
  | `input_select.ad_shield_status` | `ok` / `decoder_failing` / `unknown` |
  | `input_text.ad_shield_decoded_copies` | e.g. `4/5` |
  | `input_text.ad_shield_rotation_domains` | domains decoded from the script |
  | `input_text.ad_shield_last_new_domains` | the last domains added (kept until the next addition) |
  | `input_number.ad_shield_listed_domains` | number of entries in the blocklist |
  | `input_datetime.ad_shield_last_run` | time of the last run, so a stalled cron shows up |

- **Dashboard**: an "Ad-Shield blocklist" section on the **Internet** dashboard, next to the
  Pi-hole card. It holds an entities card (status, copies decoded, last domains added, domains
  blocked, last run, link to this repo) and a markdown card listing the rotation domains one per
  line. All rows are read-only `simple-entity` rows, so the helpers can't be edited by accident.

  ```yaml
  type: grid
  cards:
    - type: entities
      title: Ad-Shield blocklist
      icon: mdi:shield-check
      state_color: true
      grid_options: {columns: full, rows: auto}
      entities:
        - {type: simple-entity, entity: input_select.ad_shield_status, name: Decoder status}
        - {type: simple-entity, entity: input_text.ad_shield_decoded_copies, name: Script copies decoded}
        - {type: simple-entity, entity: input_text.ad_shield_last_new_domains, name: Last domains added}
        - {type: simple-entity, entity: input_number.ad_shield_listed_domains, name: Domains blocked}
        - {type: simple-entity, entity: input_datetime.ad_shield_last_run, name: Last run (hourly)}
        - {type: weblink, name: Blocklist on GitHub, url: "https://github.com/damo2929/myaddblocklist", icon: "mdi:github"}
    - type: markdown
      grid_options: {columns: full, rows: auto}
      content: |-
        **Ad-Shield rotation domains** (decoded from its script, in order)
        {% set d = states('input_text.ad_shield_rotation_domains') %}{% if d in ['unknown','unavailable',''] %}
        _No data yet_{% else %}{% for x in d.split(', ') %}
        - `{{ x }}`{% endfor %}{% endif %}
  ```

A minimal webhook automation that only does the notification part:

```yaml
triggers:
  - trigger: webhook
    webhook_id: adshield-<random>     # HA_WEBHOOK_URL=http://HA:8123/api/webhook/adshield-<random>
    allowed_methods: [POST]
    local_only: true
conditions:
  - condition: template
    value_template: "{{ trigger.json.event != 'status' }}"
actions:
  - action: notify.notify
    data:
      title: "{{ trigger.json.title }}"
      message: "{{ trigger.json.message }}"
```

## Deployment (current setup)

Pi-hole host: `192.168.5.253` (CentOS Stream 9, Pi-hole v6.4.3), access by SSH key as root.
`/opt/adshield` on the Pi-hole is a **clone of this repository**, so the Pi-hole runs exactly
what's committed here and pushes its blocklist updates back.

| Item | Location |
|---|---|
| Repo clone (script, blocklist, wrapper) | `/opt/adshield/` |
| Adlist | `file:///opt/adshield/blocklist.txt` (gravity adlist id 81) |
| Cron | `/etc/cron.d/adshield` runs `/opt/adshield/deploy/run.sh` at :17 past every hour |
| Log | `/var/log/adshield.log` |
| GitHub deploy key (write, this repo only) | `/root/.ssh/adshield_deploy` |

Each hourly run of `deploy/run.sh`:

1. `git pull --rebase` so local commits apply cleanly. If `blocklist.txt` changed on GitHub,
   gravity is reloaded.
2. Runs `detect_adshield.py`. If it adds domains, it reloads gravity and commits
   `blocklist.txt` as `blocklist: add <domains>`.
3. Pushes any commits not yet on GitHub (failed pushes are retried next run). Without the
   deploy key it still updates the Pi-hole and keeps the commits locally.

`run.sh` runs `pihole reloadlists` after `pihole -g`: without it, FTL kept answering newly
listed domains until it was told to reload.

Because the Pi-hole pulls from GitHub every hour and runs the code as root, anything pushed
to `main` ends up running on the Pi-hole. Review changes before pushing.

### Install from scratch

```bash
# 1. Deploy key on the Pi-hole, added to the repo with write access
ssh root@PIHOLE 'ssh-keygen -t ed25519 -N "" -C pihole-adshield-deploy -f /root/.ssh/adshield_deploy && cat /root/.ssh/adshield_deploy.pub'
gh repo deploy-key add adshield_deploy.pub --repo damo2929/myaddblocklist --allow-write --title "pihole adshield auto-push"

# 2. Clone, schedule and register the adlist
ssh root@PIHOLE '
  GIT_SSH_COMMAND="ssh -i /root/.ssh/adshield_deploy -o IdentitiesOnly=yes" \
    git clone git@github.com:damo2929/myaddblocklist.git /opt/adshield
  git -C /opt/adshield config user.name "pihole-adshield"
  git -C /opt/adshield config user.email "pihole-adshield@users.noreply.github.com"
  cp /opt/adshield/deploy/adshield.cron /etc/cron.d/adshield && chmod 644 /etc/cron.d/adshield
  sqlite3 /etc/pihole/gravity.db "INSERT OR IGNORE INTO adlist (address, enabled, comment)
    VALUES (\"file:///opt/adshield/blocklist.txt\", 1, \"Ad-Shield rotating domains\");"
  pihole -g && pihole reloadlists'
```

To pick up the Pi-hole's latest commits locally, run `git pull`.

To check it's working:

```bash
dig @192.168.5.253 5.nicelyeven.com     # expect NXDOMAIN
ssh root@192.168.5.253 'pihole -q 5.nicelyeven.com; tail /var/log/adshield.log; git -C /opt/adshield log --oneline -3'
```

## Limitations

- **The script decoder depends on the obfuscation format.** If Ad-Shield changes its
  obfuscator settings (e.g. drops RC4, adds wrapper functions), every copy fails with
  "decoder not found" or "rotation checksum not found" and the exit code becomes 1. The
  log scan keeps working as a backup; `decode_strings()` then needs updating. This is
  reported through the [alerts](#alerts-email-telegram-home-assistant) as soon as any copy
  fails. It has happened once so far: on 2026-10-12 the layout changed (decoder function moved
  ahead of the rotation loop, checksum expression starting with a negative term) and only the
  checksum regex needed widening to accept a leading sign.
- **Log scan has a gap of up to an hour.** A domain that isn't in any script copy is only
  seen after a browser on the network has used it.
- **Headless Chrome didn't work:** Phoronix shows a Cloudflare bot check on the second page
  load, and Ad-Shield only switches domains on later visits, so a scripted browser can't
  trigger it. Getting past the bot check was not attempted.
- **Shard heuristic**: if Ad-Shield stops using `N.<domain>` shards, or uses a base domain
  with three or more labels, `SHARD_RE` in the script needs updating.
