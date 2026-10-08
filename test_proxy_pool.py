"""Fetch fresh public proxies and test only the unauthenticated MT login page."""
import concurrent.futures
import ipaddress
import os
import re
import time
import requests

URL = "https://bbs.binmt.cc/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login"
SOURCES = {
    "databay": "https://raw.githubusercontent.com/databay-labs/free-proxy-list/master/https.txt",
    "moleway": "https://raw.githubusercontent.com/Moleway/Free-Proxy-List/main/https.txt",
    "proxio": "https://raw.githubusercontent.com/proxio-io/proxy-list/main/https.txt",
}
LIMIT = int(os.getenv("PROXY_TEST_LIMIT", "60"))
WORKERS = int(os.getenv("PROXY_TEST_WORKERS", "12"))


def valid(line):
    line = line.strip()
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}", line):
        return False
    ip, port = line.rsplit(":", 1)
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and 0 < int(port) <= 65535
    except ValueError:
        return False


def check(proxy):
    start = time.monotonic()
    try:
        with requests.Session() as s:
            s.trust_env = False
            s.proxies.update({"http": "http://" + proxy, "https": "http://" + proxy})
            r = s.get(URL, timeout=(5, 9), verify=True, allow_redirects=True,
                      headers={"User-Agent": "Mozilla/5.0", "Accept-Language": "zh-CN,zh;q=0.9"})
            body = r.content.decode(r.apparent_encoding or "utf-8", errors="replace")
            tokens = "formhash" in body.lower() and ("loginhash" in body.lower() or "password" in body.lower())
            return proxy, r.status_code, tokens, len(r.content), round(time.monotonic()-start, 2), "ok"
    except requests.exceptions.SSLError:
        return proxy, None, False, 0, round(time.monotonic()-start, 2), "tls_error"
    except requests.exceptions.Timeout:
        return proxy, None, False, 0, round(time.monotonic()-start, 2), "timeout"
    except requests.exceptions.RequestException:
        return proxy, None, False, 0, round(time.monotonic()-start, 2), "network_error"


def main():
    pool = {}
    for name, url in SOURCES.items():
        try:
            r = requests.get(url, timeout=(8, 18))
            r.raise_for_status()
            items = [p.strip() for p in r.text.splitlines() if valid(p)]
            print(f"source={name} http={r.status_code} valid_entries={len(items)}", flush=True)
            for p in items:
                pool.setdefault(p, set()).add(name)
        except requests.RequestException as e:
            print(f"source={name} failed={type(e).__name__}", flush=True)
    candidates = list(pool)[:LIMIT]
    print(f"unique={len(pool)} testing={len(candidates)} workers={WORKERS}", flush=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = {executor.submit(check, p): p for p in candidates}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    from collections import Counter
    print("results=" + str(dict(Counter(row[-1] for row in results))), flush=True)
    passing = sorted((r for r in results if r[1] == 200 and r[2]), key=lambda r:r[4])
    for proxy, status, tokens, size, seconds, kind in passing[:10]:
        print(f"login_page_pass proxy={proxy} http={status} bytes={size} seconds={seconds} sources={','.join(sorted(pool[proxy]))}", flush=True)
    print(f"login_page_pass_count={len(passing)}", flush=True)
    # Do not persist untrusted public proxies as credentials-bearing login endpoints.
    if not passing:
        print("No public proxy passed the unauthenticated MT login-page check.", flush=True)


if __name__ == "__main__":
    main()
