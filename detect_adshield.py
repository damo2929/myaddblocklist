#!/usr/bin/env python3
"""Find Ad-Shield's rotating ad-proxy domains and add them to a Pi-hole blocklist.

Ad-Shield (used by phoronix.com and others) recovers ads by rotating through throwaway
domains. When one is not blocked, the page fetches <domain>/script/<b64 host>.js and then
proxies the ads through numbered shards: 0.<domain>, 1.<domain> ... 9.<domain>.

Two sources, both on by default:

  script  (proactive)  Download Ad-Shield's stage-2 script (cdn.jsdelivr.net/gh/ad-shield/e)
                       and decode its obfuscated string table to read the rotation list,
                       including domains not used yet. The decoding is a pure-Python
                       port of the obfuscator's base64+RC4 decoder: no Ad-Shield code is
                       executed.
  log     (reactive)   Read the Pi-hole query log and flag any registrable domain with
                       several single-digit subdomains (the shard pattern). Catches
                       domains that come from somewhere other than the script.
                       API (default): Pi-hole v6 REST API, password from $PIHOLE_PASSWORD
                       (use an app password). --db PATH: read pihole-FTL.db directly.

Each domain is written as one ABP-style "||domain^" line, which Pi-hole v6 treats as the
domain plus all of its subdomains, so the shards need no entries of their own.

Examples:
  ./detect_adshield.py --no-log --dry-run                 # script only, no Pi-hole needed
  sudo ./detect_adshield.py --db /etc/pihole/pihole-FTL.db
  PIHOLE_PASSWORD=... ./detect_adshield.py --hours 72

Alerts: if a copy of the script downloads but can no longer be decoded (Ad-Shield changed
its obfuscation), an alert goes to every channel configured in adshield.conf (see
adshield.conf.example): email via an SMTP relay, Telegram, and/or a Home Assistant webhook.
Repeats are suppressed until the failure changes or REMIND_HOURS pass, and a recovery alert
is sent once decoding works again. Optionally a Home Assistant sensor is updated every run.
--test-alert checks the setup.

Exit codes: 0 = nothing new, 2 = new domains found (added unless --dry-run), 1 = error.
"""

import argparse
import ast
import hashlib
import json
import math
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

# <digit>.<label>.<tld>: the base must be exactly two labels, which keeps out legit
# digit-sharded services such as 0.pool.ntp.org or 1.fedora.pool.ntp.org.
SHARD_RE = re.compile(r"^(\d)\.([a-z0-9-]+\.[a-z0-9-]+)$")

# Known legitimate two-label bases that also use digit shards.
DEFAULT_EXCLUDE = {"gravatar.com", "wp.com", "pool.ntp.org"}

# Pi-hole statuses meaning the query was answered (i.e. NOT blocked).
ALLOWED_API = {"FORWARDED", "CACHE", "RETRIED", "RETRIED_DNSSEC", "IN_PROGRESS", "CACHE_STALE"}
ALLOWED_DB = {2, 3, 12, 13, 14, 17}

# Ad-Shield's stage-2 script: the GitHub source plus the mirrors its loader falls back to.
# The repo is force-pushed and the CDNs cache it for different lengths of time, so the copies
# carry different rotation windows; all of them are decoded and the results merged.
SCRIPT_URLS = [
    "https://raw.githubusercontent.com/ad-shield/e/main/index.js",
    "https://cdn.jsdelivr.net/gh/ad-shield/e/index.js",
    "https://cdn.statically.io/gh/ad-shield/e/main/index.js",
    # statically.io /gl/ (403) and /bb/ (hangs) are also in the loader but no longer serve it.
    "https://rawcdn.githack.com/ad-shield/e/refs/heads/main/index.js",
    "https://bbcdn.githack.com/ad-shield/e/raw/main/index.js",
]

# Rotation domains appear in the decoded script as bare origins: "https://<sld>.<tld>".
ORIGIN_RE = re.compile(r"^https://([a-z0-9-]+\.[a-z]{2,})/?$")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"


@dataclass
class Base:
    shards: set = field(default_factory=set)
    queries: int = 0
    allowed: int = 0
    base_queried: bool = False
    first: float = float("inf")
    last: float = 0.0
    clients: set = field(default_factory=set)


# ---- script source: obfuscator.io string-array decoder (pure Python) -----------------

_B64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
_STR = r"\"(?:[^\"\\]|\\.)*\"|'(?:[^'\\]|\\.)*'"


def _b64(s):
    out, q, t = [], 0, 0
    for ch in s:
        h = _B64.find(ch)
        if h == -1:
            continue
        t = t * 64 + h if q % 4 else h
        q += 1
        if (q - 1) % 4:
            out.append(0xFF & (t >> (-2 * q & 6)))
    return bytes(out).decode("utf-8")


def _units(s):
    b = s.encode("utf-16-le", "surrogatepass")
    return [b[i] | b[i + 1] << 8 for i in range(0, len(b), 2)]


def _rc4(data, key):
    d, k = _units(_b64(data)), _units(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + k[i % len(k)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = []
    for c in d:
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) % 256])
    return b"".join(x.to_bytes(2, "little") for x in out).decode("utf-16-le", "surrogatepass")


def _parse_int(x):
    m = re.match(r"\s*([+-]?\d+)", x)
    return float(int(m.group(1))) if m else math.nan


def _match_brace(s, i):
    depth = 0
    while i < len(s):
        c = s[i]
        if c in "'\"`":
            q, i = c, i + 1
            while s[i] != q:
                i += 2 if s[i] == "\\" else 1
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise ValueError("unbalanced braces")


def _js_str(lit):
    return ast.literal_eval(lit)  # JS and Python single/double-quoted literals agree here


def decode_strings(src):
    """Return the script source with every obfuscated string call replaced by its value."""
    arr_m = re.search(r"function (\w+)\(\)\{var \w+=\[", src)
    if not arr_m:
        raise ValueError("string array not found")
    arr_name = arr_m.group(1)
    body = src[arr_m.start():_match_brace(src, src.find("{", arr_m.start())) + 1]
    arr = ast.literal_eval(body[body.find("["):body.rfind("]") + 1])
    dec_m = re.search(r"function (\w+)\(\w+,\w+\)\{var \w+=%s\(\);return \1=function\(\w+,\w+\)"
                      r"\{(\w+)=\2-(0x[0-9a-f]+);" % arr_name, src)
    if not dec_m:
        raise ValueError("decoder not found (obfuscation changed?)")
    offset = int(dec_m.group(3), 16)

    # The array is rotated at start-up until a checksum of parseInt(decoded) terms matches.
    rot_m = re.search(r"\}\(%s,(-?0x[0-9a-f]+)\)" % arr_name, src)
    expr_m = rot_m and re.search(r"var \w+=(parseInt\(.*?);if\(\w+===\w+\)break", src[:rot_m.end()])
    if not expr_m:
        raise ValueError("rotation checksum not found")
    target, expr = int(rot_m.group(1), 16), expr_m.group(1)
    call_re = r"parseInt\(\w+\((0x[0-9a-f]+),'((?:[^'\\]|\\.)*)'\)\)"
    terms = [(int(i, 16) - offset, _js_str("'%s'" % k)) for i, k in re.findall(call_re, expr)]
    tpl = re.sub(call_re, "V[%d]", expr)
    tpl = re.sub(r"V\[%d\]", lambda m, c=iter(range(len(terms))): "V[%d]" % next(c), tpl)
    # Only arithmetic is evaluated: refuse anything but numbers, operators and V[n].
    if not re.fullmatch(r"[\s0-9a-fx()+\-*/V\[\]]+", tpl):
        raise ValueError("unexpected checksum expression")
    code = compile(tpl, "<checksum>", "eval")

    def checksum(a):
        vals = []
        for n, k in terms:
            try:
                vals.append(_parse_int(_rc4(a[n], k)))
            except (IndexError, UnicodeDecodeError, ValueError):
                vals.append(math.nan)
        return eval(code, {"__builtins__": {}}, {"V": vals})

    for _ in range(len(arr)):
        if checksum(arr) == target:
            break
        arr.append(arr.pop(0))
    else:
        raise ValueError("string-array rotation not found")

    def replace(m):
        try:
            return json.dumps(_rc4(arr[int(m.group(1), 16) - offset], _js_str("'%s'" % m.group(2))))
        except (IndexError, UnicodeDecodeError, ValueError):
            return m.group(0)

    out = re.sub(r"\b\w+\((0x[0-9a-f]+),'((?:[^'\\]|\\.)*)'\)", replace, src)
    # Fold "abc"+'def' concatenations left behind by string splitting.
    fold = re.compile(r"(%s)\+(%s)" % (_STR, _STR))
    while True:
        folded = fold.sub(lambda m: json.dumps(_js_str(m.group(1)) + _js_str(m.group(2))), out)
        if folded == out:
            return out
        out = folded


def script_domains(url):
    """Fetch and decode one copy of the stage-2 script; return (version, rotation domains)."""
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30) as r:
        src = r.read().decode("utf-8")
    text = decode_strings(src)
    domains = []
    for lit in re.findall(_STR, text):
        try:
            m = ORIGIN_RE.match(_js_str(lit))
        except (ValueError, SyntaxError):
            continue
        if m and m.group(1) not in domains:
            domains.append(m.group(1))
    ver = re.search(r'"(e/\d+\.\d+\.\d+)"', text)
    return ver.group(1) if ver else "?", domains


# ---- alerts: email, Telegram, Home Assistant -----------------------------------------

def load_config(path):
    """Read KEY=VALUE lines (shell-style, # comments, optional quotes)."""
    cfg = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                cfg[k.strip()] = v.strip().strip("'\"")
    return cfg


def _post(url, data=None, json_body=None, headers=None):
    body = json.dumps(json_body).encode() if json_body is not None else urllib.parse.urlencode(data).encode()
    h = {"Content-Type": "application/json" if json_body is not None else "application/x-www-form-urlencoded"}
    h.update(headers or {})
    with urllib.request.urlopen(urllib.request.Request(url, data=body, headers=h, method="POST"), timeout=30) as r:
        return r.status


class Notifier:
    """Sends alerts to every configured channel and keeps a Home Assistant sensor up to date."""

    def __init__(self, config_path, dry_run):
        self.cfg = load_config(config_path)
        self.config_path = config_path
        self.state_path = config_path.with_name(".notify-state.json")
        self.dry_run = dry_run
        self.host = socket.gethostname()

    @property
    def channels(self):
        c = self.cfg
        return [name for name, on in [
            ("email", c.get("NOTIFY_TO") and c.get("SMTP_HOST")),
            ("telegram", c.get("TELEGRAM_BOT_TOKEN") and c.get("TELEGRAM_CHAT_ID")),
            ("home-assistant webhook", c.get("HA_WEBHOOK_URL")),
        ] if on]

    def send(self, subject, body, event="alert"):
        """Send to all channels; returns True if at least one succeeded."""
        if self.dry_run:
            print(f"\n--dry-run: would send to {', '.join(self.channels) or 'no channels'}:\n"
                  f"  {subject}\n" + "\n".join("  " + l for l in body.splitlines()))
            return False
        ok = False
        for name, fn in [("email", self._email), ("telegram", self._telegram),
                         ("home-assistant webhook", self._ha_webhook)]:
            if name not in self.channels:
                continue
            try:
                fn(subject, body, event)
                print(f"Alert sent via {name}: {subject}")
                ok = True
            except (OSError, smtplib.SMTPException, ValueError) as e:
                print(f"Alert via {name} failed: {e}", file=sys.stderr)
        return ok

    def _email(self, subject, body, event):
        c = self.cfg
        msg = EmailMessage()
        msg["Subject"] = f"[adshield@{self.host}] {subject}"
        msg["From"] = c.get("NOTIFY_FROM") or f"adshield@{self.host}"
        msg["To"] = c["NOTIFY_TO"]
        msg["Date"] = formatdate(localtime=True)
        msg["Message-ID"] = make_msgid(domain=self.host)
        msg.set_content(body)
        security = c.get("SMTP_SECURITY", "none").lower()
        port = int(c.get("SMTP_PORT") or (465 if security == "ssl" else 25))
        cls = smtplib.SMTP_SSL if security == "ssl" else smtplib.SMTP
        with cls(c["SMTP_HOST"], port, timeout=30) as smtp:
            if security == "starttls":
                smtp.starttls(context=ssl.create_default_context())
            smtp.send_message(msg)

    def _telegram(self, subject, body, event):
        text = f"adshield@{self.host}: {subject}\n\n{body}"[:4096]  # Telegram's message limit
        _post(f"https://api.telegram.org/bot{self.cfg['TELEGRAM_BOT_TOKEN']}/sendMessage",
              data={"chat_id": self.cfg["TELEGRAM_CHAT_ID"], "text": text, "disable_web_page_preview": "true"})

    def _ha_webhook(self, subject, body, event):
        _post(self.cfg["HA_WEBHOOK_URL"], json_body={
            "event": event, "title": subject, "message": body, "host": self.host})

    def decoder_status(self, failures, total, decoded):
        """Alert on decode failures (deduplicated), and once on recovery."""
        try:
            state = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            state = {}
        now = time.time()
        if failures:
            sig = hashlib.sha256(json.dumps(sorted(failures)).encode()).hexdigest()
            remind = float(self.cfg.get("REMIND_HOURS") or 24) * 3600
            if state.get("sig") == sig and now - state.get("sent", 0) < remind:
                return
            if not self.channels:
                print(f"(alerts not configured: see adshield.conf.example, expected at {self.config_path})",
                      file=sys.stderr)
                return
            lines = [f"Ad-Shield's script could not be decoded from {len(failures)} of {total} copies.",
                     "The obfuscation format has probably changed, so upcoming rotation domains",
                     "are no longer read in advance. The Pi-hole log scan still runs as a backup.",
                     "", "Failures:"]
            lines += [f"  {url}\n      {err}" for url, err in failures]
            lines += ["", "Fix: update decode_strings() in detect_adshield.py (see README, Limitations).",
                      "Test with: ./detect_adshield.py --no-log --dry-run"]
            if self.send(f"Ad-Shield decoder failed on {len(failures)}/{total} copies",
                         "\n".join(lines), event="decoder_failed"):
                self._save({"sig": sig, "sent": now, "failing": True})
        elif state.get("failing") and decoded and self.channels:
            if self.send("Ad-Shield decoder working again",
                         f"{decoded} of {total} copies of Ad-Shield's script decoded, with no decode failures.",
                         event="decoder_recovered"):
                self._save({})

    def ha_sensor(self, attrs):
        """Set a Home Assistant entity to this run's status via the REST API (every run)."""
        url, token = self.cfg.get("HA_URL"), self.cfg.get("HA_TOKEN")
        if not (url and token):
            return
        entity = self.cfg.get("HA_ENTITY", "sensor.adshield")
        state = "decoder_failing" if attrs.get("decode_failures") else "ok"
        attrs = dict(attrs, friendly_name="Ad-Shield blocklist", icon="mdi:shield-check"
                     if state == "ok" else "mdi:shield-alert", host=self.host)
        if self.dry_run:
            print(f"--dry-run: would set {entity} = {state} {json.dumps(attrs)}")
            return
        try:
            _post(f"{url.rstrip('/')}/api/states/{entity}", json_body={"state": state, "attributes": attrs},
                  headers={"Authorization": f"Bearer {token}"})
        except (OSError, ValueError) as e:
            print(f"Home Assistant sensor update failed: {e}", file=sys.stderr)

    def _save(self, state):
        try:
            self.state_path.write_text(json.dumps(state))
        except OSError as e:
            print(f"Could not write {self.state_path}: {e}", file=sys.stderr)


# ---- log source ----------------------------------------------------------------------

class PiHoleAPI:
    def __init__(self, url, password, insecure):
        self.url = url.rstrip("/")
        self.ctx = ssl._create_unverified_context() if insecure else None
        self.sid = None
        auth = self._call("POST", "/api/auth", body={"password": password or ""})
        session = auth.get("session", {})
        if not session.get("valid"):
            raise SystemExit(f"Pi-hole login failed: {session.get('message', auth)}")
        self.sid = session.get("sid")  # None when the Pi-hole has no password

    def _call(self, method, path, params=None, body=None):
        url = self.url + path + ("?" + urllib.parse.urlencode(params) if params else "")
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        if self.sid:
            headers["X-FTL-SID"] = self.sid
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=60, context=self.ctx) as r:
                raw = r.read()
        except urllib.error.HTTPError as e:
            raw = e.read()
            if e.code not in (401, 403) or path != "/api/auth":
                raise SystemExit(f"Pi-hole API {method} {path}: HTTP {e.code} {raw[:200]!r}")
        return json.loads(raw) if raw else {}

    def queries(self, since, until):
        params = {"from": int(since), "until": int(until), "length": 10000, "start": 0,
                  # The in-memory log only holds ~24h; go to the on-disk DB beyond that.
                  "disk": "true" if until - since > 86400 else "false"}
        while True:
            page = self._call("GET", "/api/queries", params)
            rows = page.get("queries", [])
            for q in rows:
                yield q["time"], q["domain"].lower(), q.get("status") in ALLOWED_API, (q.get("client") or {}).get("ip", "")
            params["start"] += len(rows)
            if "cursor" in page:
                params["cursor"] = page["cursor"]
            if not rows or params["start"] >= page.get("recordsFiltered", 0):
                break

    def close(self):
        if self.sid:  # free the session slot; Pi-hole only allows a handful
            try:
                self._call("DELETE", "/api/auth")
            except SystemExit:
                pass


def db_queries(path, since, until):
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        for ts, domain, status, client in con.execute(
                "SELECT timestamp, domain, status, client FROM queries WHERE timestamp BETWEEN ? AND ?",
                (since, until)):
            yield ts, (domain or "").lower(), status in ALLOWED_DB, client or ""
    finally:
        con.close()


def analyse(rows, exclude):
    bases = {}
    plain = {}  # domain -> allowed? (for marking base-domain lookups)
    for ts, domain, allowed, client in rows:
        m = SHARD_RE.match(domain)
        if m:
            digit, base = m.groups()
            if base in exclude:
                continue
            b = bases.setdefault(base, Base())
            b.shards.add(digit)
            b.queries += 1
            b.allowed += allowed
            b.first, b.last = min(b.first, ts), max(b.last, ts)
            b.clients.add(client)
        else:
            plain[domain] = plain.get(domain, False) or allowed
    for base, b in bases.items():
        b.base_queried = base in plain
    return bases


# ---- blocklist -----------------------------------------------------------------------

def load_blocklist(path):
    if not path.exists():
        return "", set()
    text = path.read_text()
    entries = {l.strip() for l in text.splitlines() if l.strip() and not l.lstrip().startswith("#")}
    return text, entries


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--no-script", action="store_true", help="skip decoding Ad-Shield's script")
    ap.add_argument("--script-url", action="append", metavar="URL",
                    help="stage-2 script URL to decode (repeatable; default: jsDelivr + mirrors)")
    ap.add_argument("--no-log", action="store_true", help="skip the Pi-hole query log")
    ap.add_argument("--url", default=os.environ.get("PIHOLE_URL", "http://pi.hole"),
                    help="Pi-hole base URL (default: $PIHOLE_URL or http://pi.hole)")
    ap.add_argument("--db", type=Path, help="read pihole-FTL.db directly instead of the API")
    ap.add_argument("--hours", type=float, default=24, help="how far back to look in the log (default 24)")
    ap.add_argument("--min-shards", type=int, default=3,
                    help="distinct N.<domain> shards needed to flag a domain (default 3)")
    ap.add_argument("--exclude", action="append", default=[], metavar="DOMAIN",
                    help="base domain to ignore (repeatable)")
    ap.add_argument("--blocklist", type=Path, default=Path(__file__).with_name("blocklist.txt"))
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification for https Pi-hole URLs")
    ap.add_argument("--dry-run", action="store_true",
                    help="report only: do not modify the blocklist or send alerts (prints them instead)")
    ap.add_argument("--config", type=Path, default=Path(__file__).with_name("adshield.conf"),
                    help="alert settings (default: adshield.conf next to this script)")
    ap.add_argument("--test-alert", action="store_true", help="send a test alert to every channel and exit")
    args = ap.parse_args()
    notifier = Notifier(args.config, args.dry_run)
    if args.test_alert:
        if not notifier.channels and not notifier.cfg.get("HA_URL"):
            ap.error(f"no alert channels configured in {args.config}")
        notifier.ha_sensor({"test": True, "last_run": datetime.now().isoformat(timespec="seconds")})
        sent = notifier.send("Test alert", "Alerts from detect_adshield.py are working.", event="test")
        return 0 if sent or not notifier.channels else 1
    if args.no_script and args.no_log:
        ap.error("nothing to do: both --no-script and --no-log given")

    exclude = DEFAULT_EXCLUDE | {d.lower() for d in args.exclude}
    text, existing = load_blocklist(args.blocklist)
    listed = lambda d: "already listed" if f"||{d}^" in existing else "new"
    found = {}  # domain -> source label, in discovery order
    failed = False
    stats = {"decoded_copies": None, "decode_failures": 0}

    if not args.no_script:
        urls = args.script_url or SCRIPT_URLS
        decoded = 0
        decode_failures = []  # downloaded but not decodable: the obfuscation format changed
        print("Ad-Shield script copies:")
        for url in urls:
            try:
                ver, domains = script_domains(url)
            except (ValueError, SyntaxError) as e:
                print(f"  {url}\n      DECODE FAILED: {e}")
                decode_failures.append((url, f"{type(e).__name__}: {e}"))
                continue
            except OSError as e:  # network errors and timeouts (includes URLError)
                print(f"  {url}\n      download failed: {e}")
                continue
            decoded += 1
            domains = [d for d in domains if d not in exclude]
            print(f"  {url} ({ver})\n      {' -> '.join(domains) or '(no domains)'}")
            for d in domains:
                found.setdefault(d, "Ad-Shield script")
        notifier.decoder_status(decode_failures, len(urls), decoded)
        stats.update(decoded_copies=f"{decoded}/{len(urls)}", decode_failures=len(decode_failures),
                     rotation_domains=[d for d, src in found.items() if src == "Ad-Shield script"])
        if not decoded:
            print("No copy of the Ad-Shield script could be decoded.", file=sys.stderr)
            failed = True
        else:
            script_found = [d for d, src in found.items() if src == "Ad-Shield script"]
            print(f"Rotation domains from {decoded}/{len(urls)} copies:")
            for d in script_found:
                print(f"  {d:28} [{listed(d)}]")

    if not args.no_log:
        until = time.time()
        since = until - args.hours * 3600
        api = None
        if args.db:
            rows, source = db_queries(args.db, since, until), str(args.db)
        else:
            api = PiHoleAPI(args.url, os.environ.get("PIHOLE_PASSWORD"), args.insecure)
            rows, source = api.queries(since, until), args.url
        try:
            bases = analyse(rows, exclude)
        finally:
            if api:
                api.close()
        flagged = {k: v for k, v in bases.items() if len(v.shards) >= args.min_shards}
        print(f"Scanned {source}, last {args.hours:g}h: {len(flagged)} Ad-Shield-style domain(s)")
        fmt = lambda t: datetime.fromtimestamp(t).strftime("%Y-%m-%d %H:%M")
        for base, b in sorted(flagged.items(), key=lambda kv: -kv[1].last):
            state = "GETTING THROUGH" if b.allowed else "blocked"
            print(f"  {base:28} shards {''.join(sorted(b.shards)):10} {b.queries:5} queries "
                  f"({b.allowed} allowed) {state:15} {fmt(b.first)} -> {fmt(b.last)}  [{listed(base)}]")
            found.setdefault(base, "Pi-hole log")

    new = [(d, src) for d, src in found.items() if f"||{d}^" not in existing]
    notifier.ha_sensor(dict(stats, last_run=datetime.now().isoformat(timespec="seconds"),
                            new_domains=[d for d, _ in new], listed=len(existing) + len(new)))
    if not new:
        print(f"\n{args.blocklist} is up to date.")
        return 1 if failed else 0

    print(f"\nNew entries ({len(new)}):\n  " + "\n  ".join(f"||{d}^   ({src})" for d, src in new))
    if args.dry_run:
        print("\n--dry-run: blocklist not modified.")
    else:
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
        block = "".join(f"\n# Auto-detected by detect_adshield.py on {stamp} from {src}\n||{d}^\n"
                        for d, src in new)
        args.blocklist.write_text(text.rstrip("\n") + "\n" + block if text else block.lstrip("\n"))
        print(f"\nAppended {len(new)} entr{'y' if len(new) == 1 else 'ies'} to {args.blocklist}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
