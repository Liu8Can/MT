"""Read-only, credential-free diagnostics for MT forum pages on GitHub Actions."""
import collections
import html
from html.parser import HTMLParser
import re
import socket
import time
from urllib.parse import urlsplit

import requests

HOST = "bbs.binmt.cc"
BASE = "https://" + HOST
PAGES = [
    ("homepage", "/"),
    ("standard_login", "/member.php?mod=logging&action=login"),
    ("ajax_login", "/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login"),
    ("sign_page", "/k_misign-sign.html"),
]
KEYWORDS = {
    "login": ("登录", "login", "logging"),
    "captcha": ("验证码", "captcha", "geetest", "hcaptcha", "recaptcha"),
    "challenge": ("challenge", "just a moment", "checking your browser", "安全验证", "访问验证"),
    "blocked": ("access denied", "forbidden", "访问受限", "禁止访问", "请求被拒绝"),
    "discuz": ("discuz", "formhash", "loginhash"),
}


class Structure(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags = collections.Counter()
        self.forms = []
        self.inputs = collections.Counter()
        self.scripts = 0
        self.title_parts = []
        self.in_title = False

    def handle_starttag(self, tag, attrs):
        self.tags[tag] += 1
        attrs = dict(attrs)
        if tag == "title":
            self.in_title = True
        elif tag == "form":
            self.forms.append({"method": attrs.get("method", "get").lower(),
                               "has_action": bool(attrs.get("action"))})
        elif tag == "input":
            # Only static field NAMES; never log field values, tokens or credentials.
            name = attrs.get("name", "")
            if name in {"username", "password", "formhash", "loginhash", "fastloginfield", "questionid", "answer"}:
                self.inputs[name] += 1
            elif name:
                self.inputs["other"] += 1
        elif tag == "script":
            self.scripts += 1

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title_parts.append(data)


def safe_title(value):
    value = " ".join(html.unescape(value).split())
    # Title may contain reflected text: only emit a known classification.
    for name, words in KEYWORDS.items():
        if any(w in value.lower() for w in words):
            return "category:" + name
    return "present" if value else "missing"


def inspect(session, name, path):
    try:
        start = time.monotonic()
        response = session.get(BASE + path, timeout=(12, 30), allow_redirects=True)
        elapsed = round(time.monotonic() - start, 2)
        raw = response.content
        response.encoding = response.apparent_encoding
        body = response.text
        parser = Structure()
        parser.feed(body[:200000])
        parsed = urlsplit(response.url)
        destination = "same-host" if parsed.hostname == HOST else "other-host"
        matches = {key: any(w in body.lower() for w in words) for key, words in KEYWORDS.items()}
        legacy_login = bool(re.search("loginhash.*?=", body, re.I))
        legacy_form = bool(re.search("formhash.*?value=", body, re.I | re.S))
        generic_login = "loginhash" in body.lower()
        generic_form = "formhash" in body.lower()
        print(f"[{name}] status={response.status_code} seconds={elapsed} bytes={len(raw)} "
              f"content_type={response.headers.get('Content-Type','').split(';')[0]} "
              f"redirects={len(response.history)} destination={destination}")
        print(f"[{name}] title={safe_title(''.join(parser.title_parts))} "
              f"forms={parser.forms} input_names={dict(parser.inputs)} "
              f"scripts={parser.scripts} tags={dict(parser.tags.most_common(10))}")
        print(f"[{name}] keywords={matches} "
              f"legacy_regex_login={legacy_login} legacy_regex_form={legacy_form} "
              f"generic_login={generic_login} generic_form={generic_form}")
        print(f"[{name}] headers: server_present={bool(response.headers.get('Server'))} "
              f"set_cookie_present={bool(response.headers.get('Set-Cookie'))} "
              f"location_present={bool(response.headers.get('Location'))}")
        if not response.ok:
            print(f"[{name}] HTTP non-success; no login attempt made")
    except requests.RequestException as exc:
        print(f"[{name}] request_error={type(exc).__name__}")
    except Exception as exc:
        print(f"[{name}] parse_error={type(exc).__name__}")


def main():
    print("READ-ONLY DIAGNOSTIC: GET only, no credentials, no login submission, no sign-in")
    try:
        addresses = socket.getaddrinfo(HOST, 443, type=socket.SOCK_STREAM)
        print("dns_resolved=True address_count=" + str(len(set(a[4][0] for a in addresses))))
    except OSError as exc:
        print("dns_resolved=False error=" + type(exc).__name__)
    with requests.Session() as session:
        session.trust_env = False
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        for name, path in PAGES:
            inspect(session, name, path)


if __name__ == "__main__":
    main()
